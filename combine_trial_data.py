#!/usr/bin/env python3
"""
combine_trial_data.py

Combines Locust per-request CSV data with TLS-handshake timing extracted
from a trial's packet capture (capture.pcap), joining the two data sources
on the request ID that Locust embeds as a custom HTTP header
("Request-ID: <uuid>") in each handshake's GET request.

For a given trial directory (as produced by run_trial.sh), this script:
  1. Ensures a combined "master_keylog.log" exists (concatenating all
     per-user SSLKEYLOGFILE outputs under keylogs/), so tshark can decrypt
     the TLS 1.3 traffic in capture.pcap. If run_trial.sh already produced
     one, this step is a no-op.
  2. Extracts, per TCP stream, the timestamp of the first and last packet
     seen (used here as a simple proxy for handshake duration -- a rougher
     stand-in for the SYN-to-Finished definition in the research plan).
  3. Extracts, per TCP stream, the request ID from the decrypted HTTP GET
     request's custom "Request-ID" header.
  4. Loads and concatenates all worker_*_requests.csv files written by
     locustfile.py.
  5. Left-joins the requests data with the per-stream pcap timing data on
     request_id (so failed/timed-out requests with no matching stream are
     kept, flagged via a `matched` column, rather than silently dropped),
     computes two phase-level latency columns -- syn_to_get_s (first packet
     of the stream to the packet carrying the GET request) and
     get_to_last_pkt_s (GET request to the stream's last packet) -- and
     writes the result to combined_metrics.csv in the trial directory.
     syn_to_get_s + get_to_last_pkt_s == pcap_duration_s for matched rows,
     which is a useful sanity check on the join.

Usage:
    python3 combine_trial_data.py /absolute/path/to/trial_dir
    python3 combine_trial_data.py /absolute/path/to/trial_dir --output /some/other/path.csv

Requires: tshark on PATH, pandas installed.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
from io import StringIO
from pathlib import Path

import pandas as pd

REQUEST_ID_RE = re.compile(r"Request-ID:\s*([0-9a-fA-F-]+)")
WINDOWS_DRIVE_RE = re.compile(r"^[a-zA-Z]:[\\/]")
MSYS_DRIVE_RE = re.compile(r"^/([a-zA-Z])/(.*)$")


def die(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def parse_path_arg(raw_path: str) -> Path:
    """
    Normalizes CLI path inputs so Windows absolute paths (e.g. C:\\Work\\...)
    and Git-Bash-style drive paths (/c/Work/...) both work.
    """
    value = raw_path.strip()

    msys_match = MSYS_DRIVE_RE.match(value)
    if msys_match:
        drive = msys_match.group(1).upper()
        tail = msys_match.group(2)
        value = f"{drive}:/{tail}"

    if WINDOWS_DRIVE_RE.match(value):
        # Keep absolute Windows-drive semantics and normalize separators.
        value = value.replace("\\", os.sep).replace("/", os.sep)

    return Path(value).expanduser()


def check_tshark_available() -> None:
    if shutil.which("tshark") is None:
        die("tshark not found on PATH. Install it or run this on a host that has it.")


def ensure_master_keylog(trial_dir: Path) -> Path:
    """
    Returns the path to trial_dir/master_keylog.log, creating it by
    concatenating trial_dir/keylogs/* if it doesn't already exist.
    (Mirrors generate_master_keylog() in debug.sh -- if that step already
    ran as part of run_trial.sh, this is a no-op.)
    """
    master_keylog = trial_dir / "master_keylog.log"
    if master_keylog.exists():
        print(f"[1/5] master_keylog.log already exists at {master_keylog}")
        return master_keylog

    keylog_dir = trial_dir / "keylogs"
    keylog_files = sorted(keylog_dir.glob("*"))
    if not keylog_files:
        die(f"No keylog files found in {keylog_dir}; cannot decrypt capture.pcap.")

    print(f"[1/5] Building master_keylog.log from {len(keylog_files)} file(s) in {keylog_dir}")
    with open(master_keylog, "w") as out_f:
        for f in keylog_files:
            out_f.write(f.read_text())

    return master_keylog


def run_tshark(args: list) -> str:
    """Runs tshark with the given argument list and returns stdout as text."""
    result = subprocess.run(
        ["tshark"] + args,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        die(f"tshark failed (exit {result.returncode}):\n{result.stderr}")
    return result.stdout


def extract_stream_timing(pcap_path: Path, keylog_path: Path) -> pd.DataFrame:
    """
    Returns a DataFrame with one row per TCP stream:
        tcp.stream, first_pkt_time, last_pkt_time, pcap_duration_s
    """
    print("[2/5] Extracting per-stream packet timing from capture.pcap...")
    stdout = run_tshark([
        "-r", str(pcap_path),
        "-o", f"tls.keylog_file:{keylog_path}",
        "-T", "fields",
        "-e", "tcp.stream",
        "-e", "frame.time_epoch",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d",
    ])

    df = pd.read_csv(StringIO(stdout))
    if df.empty:
        die("tshark returned no packets for capture.pcap -- check the pcap file and keylog.")

    df["frame.time_epoch"] = df["frame.time_epoch"].astype(float)

    grouped = (
        df.groupby("tcp.stream")["frame.time_epoch"]
        .agg(first_pkt_time="min", last_pkt_time="max")
        .reset_index()
    )
    grouped["pcap_duration_s"] = grouped["last_pkt_time"] - grouped["first_pkt_time"]

    return grouped


def extract_stream_request_ids(pcap_path: Path, keylog_path: Path) -> pd.DataFrame:
    """
    Returns a DataFrame with one row per TCP stream that had a decrypted
    HTTP request:
        tcp.stream, request_id, get_request_time

    get_request_time is the frame.time_epoch of the packet tshark reports
    the HTTP request on -- for a request this small (one header line, no
    body) that's effectively when the GET request was sent.
    """
    print("[3/5] Extracting request IDs and request timing from decrypted HTTP requests...")
    stdout = run_tshark([
        "-r", str(pcap_path),
        "-o", f"tls.keylog_file:{keylog_path}",
        "-Y", "http.request",
        "-T", "fields",
        "-e", "tcp.stream",
        "-e", "frame.time_epoch",
        "-e", "http.request.line",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d",
        "-E", "occurrence=a",
        "-E", "aggregator=;",
    ])

    df = pd.read_csv(StringIO(stdout))
    if df.empty:
        print(
            "  WARNING: no HTTP requests found via http.request.line. "
            "This can happen if this tshark version names the field "
            "differently. Verify with a manual "
            "'-z follow,http,ascii,<stream>' check on one stream before "
            "trusting the rest of this script's output."
        )
        return pd.DataFrame(columns=["tcp.stream", "request_id", "get_request_time"])

    df["frame.time_epoch"] = df["frame.time_epoch"].astype(float)

    def extract_id(line_field):
        if not isinstance(line_field, str):
            return None
        match = REQUEST_ID_RE.search(line_field)
        return match.group(1) if match else None

    df["request_id"] = df["http.request.line"].apply(extract_id)
    missing = df["request_id"].isna().sum()
    if missing:
        print(f"  WARNING: {missing} HTTP request(s) had no parseable Request-ID header.")

    result = df[["tcp.stream", "request_id", "frame.time_epoch"]].dropna(subset=["request_id"])
    return result.rename(columns={"frame.time_epoch": "get_request_time"})


def load_requests(trial_dir: Path) -> pd.DataFrame:
    """
    Loads and concatenates all worker_*_requests.csv files written by
    locustfile.py under trial_dir/locust/requests/.
    """
    requests_dir = trial_dir / "locust" / "requests"
    csv_files = sorted(requests_dir.glob("worker_*_requests.csv"))
    if not csv_files:
        die(f"No worker_*_requests.csv files found in {requests_dir}")

    print(f"[4/5] Loading {len(csv_files)} requests CSV(s) from {requests_dir}")
    dfs = [pd.read_csv(f) for f in csv_files]
    return pd.concat(dfs, ignore_index=True)


def combine(
    requests_df: pd.DataFrame,
    timing_df: pd.DataFrame,
    ids_df: pd.DataFrame,
) -> pd.DataFrame:
    """
    Joins stream timing + stream request IDs, then left-joins the result
    onto the Locust requests data via request_id. Adds a `matched`
    boolean column so failed/unmatched requests are visible rather than
    silently dropped or silently blank.
    """
    print("[5/5] Joining requests data with pcap stream data...")

    stream_data = ids_df.merge(timing_df, on="tcp.stream", how="left")

    # More than one stream mapping to the same request_id would indicate a
    # real problem (ID collision, connection reuse) worth surfacing rather
    # than silently overwriting rows during the merge below.
    dup_ids = stream_data["request_id"][stream_data["request_id"].duplicated()]
    if not dup_ids.empty:
        print(
            f"  WARNING: {dup_ids.nunique()} request_id(s) matched more than one "
            f"TCP stream -- check for connection reuse or ID collisions."
        )

    # Phase-level breakdown: syn_to_get_s covers connection setup + the TLS
    # handshake, up to the moment the client's GET request was sent;
    # get_to_last_pkt_s covers everything from there through the server's
    # response and connection teardown. These two should sum to
    # pcap_duration_s for every matched row.
    stream_data["syn_to_get_s"] = stream_data["get_request_time"] - stream_data["first_pkt_time"]
    stream_data["get_to_last_pkt_s"] = stream_data["last_pkt_time"] - stream_data["get_request_time"]

    # Expose the same measurements in milliseconds for quick inspection and
    # plot hover metadata without converting them repeatedly downstream.
    stream_data["syn_to_get_ms"] = stream_data["syn_to_get_s"] * 1000
    stream_data["get_to_last_pkt_ms"] = stream_data["get_to_last_pkt_s"] * 1000

    result = requests_df.merge(
        stream_data.drop(columns=["tcp.stream"]),
        on="request_id",
        how="left",
    )
    result["matched"] = result["first_pkt_time"].notna()

    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("trial_dir", type=str, help="Absolute path to a trial directory")
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output CSV path (default: <trial_dir>/combined_metrics.csv)",
    )
    args = parser.parse_args()

    trial_dir = parse_path_arg(args.trial_dir).resolve()
    if not trial_dir.is_dir():
        die(f"{trial_dir} is not a directory.")

    pcap_path = trial_dir / "capture.pcap"
    if not pcap_path.exists():
        die(f"{pcap_path} not found.")

    check_tshark_available()

    keylog_path = ensure_master_keylog(trial_dir)
    timing_df = extract_stream_timing(pcap_path, keylog_path)
    ids_df = extract_stream_request_ids(pcap_path, keylog_path)
    requests_df = load_requests(trial_dir)

    result = combine(requests_df, timing_df, ids_df)

    output_path = parse_path_arg(args.output).resolve() if args.output else (trial_dir / "combined_metrics.csv")
    result.to_csv(output_path, index=False)

    total = len(result)
    matched = int(result["matched"].sum())
    rate = matched / total if total else 0.0
    print(f"\nWrote {output_path}")
    print(f"{matched}/{total} requests matched to a pcap stream ({rate:.1%})")


if __name__ == "__main__":
    main()