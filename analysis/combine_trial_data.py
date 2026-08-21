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
  2. Extracts per-packet timing and phase markers (source IP, TCP payload
     length, TLS handshake-message type) for every packet in capture.pcap.
  3. Extracts, per TCP stream, the request ID and send-time of the
     decrypted HTTP GET request's custom "Request-ID" header.
  4. Derives, per TCP stream, both a coarse 2-phase split (syn_to_get_s,
     get_to_last_pkt_s) and a finer 5-phase split of the handshake and
     response:
       - tcp_handshake_s:     first packet -> ClientHello sent
       - tls_negotiation_s:   ClientHello -> GET request sent
       - ttfb_s:               GET request -> first response byte
       - response_transfer_s: first response byte -> last data packet
       - teardown_s:          last data packet -> last packet in stream
     The fine-grained phases sum to their coarse counterparts
     (tcp_handshake_s + tls_negotiation_s == syn_to_get_s, and
     ttfb_s + response_transfer_s + teardown_s == get_to_last_pkt_s),
     which is checked and reported as a sanity check on the markers.
  5. Loads and concatenates all worker_*_requests.csv files written by
     locustfile.py.
  6. Left-joins the requests data with the per-stream phase data on
     request_id (so failed/timed-out requests with no matching stream are
     kept, flagged via a `matched` column, rather than silently dropped),
     and writes the result to combined_metrics.csv in the trial directory.

Usage:
    python3 combine_trial_data.py /absolute/path/to/trial_dir
    python3 combine_trial_data.py /absolute/path/to/trial_dir --output /some/other/path.csv
    python3 combine_trial_data.py /absolute/path/to/trial_dir --server-ip 172.20.0.10

Requires: tshark on PATH, pandas installed.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
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


def create_temporary_keylog(trial_dir: Path) -> Path:
    """
    Create a temporary combined keylog for tshark and return its path.
    The caller owns cleanup of the returned file.
    """
    keylog_dir = trial_dir / "keylogs"
    keylog_files = sorted(keylog_dir.glob("*.log"))
    if not keylog_files:
        die(f"No keylog files found in {keylog_dir}; cannot decrypt capture.pcap.")

    print(f"[1/6] Building temporary keylog from {len(keylog_files)} file(s) in {keylog_dir}")
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="\n",
        prefix=".combine_trial_data_",
        suffix=".log",
        dir=trial_dir,
        delete=False,
    ) as out_f:
        for index, keylog_file in enumerate(keylog_files):
            if index:
                out_f.write("\n")
            out_f.write(keylog_file.read_text(encoding="utf-8", errors="ignore"))

    return Path(out_f.name)


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


def extract_stream_packets(pcap_path: Path, keylog_path: Path) -> pd.DataFrame:
    """
    Returns a DataFrame with one row per packet in capture.pcap:
        tcp.stream, frame.time_epoch, ip.src, tcp.len, tls.handshake.type

    This raw, per-packet data feeds compute_phase_markers() below, which
    derives both the coarse first/last-packet timestamps and the finer
    phase-boundary markers (ClientHello time, first response-byte time,
    last data-bearing packet time) used for the 5-way phase split.
    """
    print("[2/6] Extracting per-packet timing and phase markers from capture.pcap...")
    stdout = run_tshark([
        "-r", str(pcap_path),
        "-o", f"tls.keylog_file:{keylog_path}",
        "-T", "fields",
        "-e", "tcp.stream",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "tcp.len",
        "-e", "tls.handshake.type",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d",
        "-E", "occurrence=a",
        "-E", "aggregator=;",
    ])

    df = pd.read_csv(StringIO(stdout))
    if df.empty:
        die("tshark returned no packets for capture.pcap -- check the pcap file and keylog.")

    df["frame.time_epoch"] = df["frame.time_epoch"].astype(float)
    df["tcp.len"] = pd.to_numeric(df["tcp.len"], errors="coerce").fillna(0)

    return df


def compute_phase_markers(packets_df: pd.DataFrame, ids_df: pd.DataFrame, server_ip: str) -> pd.DataFrame:
    """
    Computes, per TCP stream, the packet-time markers needed for both the
    coarse (SYN-to-GET / GET-to-last-packet) and fine-grained (5-way) phase
    breakdown:
        tcp.stream, first_pkt_time, last_pkt_time, pcap_duration_s,
        clienthello_time, first_response_pkt_time, last_data_pkt_time

    Marker definitions:
      - first_pkt_time / last_pkt_time: earliest/latest packet in the
        stream (unchanged from before).
      - clienthello_time: earliest packet whose tls.handshake.type includes
        1 (ClientHello) -- marks the end of the plain TCP handshake and the
        start of TLS negotiation.
      - first_response_pkt_time: earliest packet sourced from server_ip,
        carrying a non-empty TCP payload, sent *after* that stream's GET
        request -- marks first byte of the actual HTTP response, as
        opposed to earlier TLS handshake bytes also sent by the server.
      - last_data_pkt_time: latest packet in the stream carrying a
        non-empty TCP payload -- marks the end of data transfer, before
        any trailing FIN/ACK-only teardown packets.

    A stream missing any of these markers (e.g. no ClientHello identified)
    simply gets NaN in that column and downstream phase columns derived
    from it -- reported by combine() rather than silently dropped.
    """
    print("[4/6] Deriving coarse and fine-grained phase markers per stream...")

    get_times = ids_df.set_index("tcp.stream")["get_request_time"]
    packets_df = packets_df.copy()
    packets_df["get_request_time"] = packets_df["tcp.stream"].map(get_times)

    def has_clienthello(field):
        if not isinstance(field, str):
            return False
        return "1" in field.split(";")

    is_clienthello = packets_df["tls.handshake.type"].apply(has_clienthello)

    first_pkt_time = packets_df.groupby("tcp.stream")["frame.time_epoch"].min()
    last_pkt_time = packets_df.groupby("tcp.stream")["frame.time_epoch"].max()
    clienthello_time = packets_df[is_clienthello].groupby("tcp.stream")["frame.time_epoch"].min()

    data_pkts = packets_df[packets_df["tcp.len"] > 0]
    last_data_pkt_time = data_pkts.groupby("tcp.stream")["frame.time_epoch"].max()

    response_pkts = data_pkts[
        (data_pkts["ip.src"] == server_ip)
        & (data_pkts["frame.time_epoch"] > data_pkts["get_request_time"])
    ]
    first_response_pkt_time = response_pkts.groupby("tcp.stream")["frame.time_epoch"].min()

    # Combining Series with potentially different indices (e.g. some
    # streams never had a ClientHello identified) into one DataFrame
    # aligns on the union of indices automatically, filling NaN for any
    # stream missing a given marker.
    markers = pd.DataFrame({
        "first_pkt_time": first_pkt_time,
        "last_pkt_time": last_pkt_time,
        "clienthello_time": clienthello_time,
        "first_response_pkt_time": first_response_pkt_time,
        "last_data_pkt_time": last_data_pkt_time,
    }).reset_index()

    markers["pcap_duration_s"] = markers["last_pkt_time"] - markers["first_pkt_time"]

    return markers


def extract_stream_request_ids(pcap_path: Path, keylog_path: Path) -> pd.DataFrame:
    """
    Returns a DataFrame with one row per TCP stream that had a decrypted
    HTTP request:
        tcp.stream, request_id, get_request_time

    get_request_time is the frame.time_epoch of the packet tshark reports
    the HTTP request on -- for a request this small (one header line, no
    body) that's effectively when the GET request was sent.
    """
    print("[3/6] Extracting request IDs and request timing from decrypted HTTP requests...")
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

    print(f"[5/6] Loading {len(csv_files)} requests CSV(s) from {requests_dir}")
    dfs = [pd.read_csv(f) for f in csv_files]
    return pd.concat(dfs, ignore_index=True)


def combine(
    requests_df: pd.DataFrame,
    markers_df: pd.DataFrame,
    ids_df: pd.DataFrame,
) -> pd.DataFrame:
    """
    Joins per-stream phase markers with per-stream request IDs, then
    left-joins the result onto the Locust requests data via request_id.
    Adds a `matched` boolean column so failed/unmatched requests are
    visible rather than silently dropped or silently blank.

    Produces two levels of phase-level latency breakdown:
      - Coarse (2-way): syn_to_get_s, get_to_last_pkt_s
      - Fine   (5-way): tcp_handshake_s, tls_negotiation_s, ttfb_s,
                         response_transfer_s, teardown_s
    The fine columns should sum to their corresponding coarse column for
    every stream where all markers were identified; this is checked below
    and any mismatches are reported rather than silently accepted.
    """
    print("[6/6] Joining requests data with pcap stream data...")

    stream_data = ids_df.merge(markers_df, on="tcp.stream", how="left")

    # More than one stream mapping to the same request_id would indicate a
    # real problem (ID collision, connection reuse) worth surfacing rather
    # than silently overwriting rows during the merge below.
    dup_ids = stream_data["request_id"][stream_data["request_id"].duplicated()]
    if not dup_ids.empty:
        print(
            f"  WARNING: {dup_ids.nunique()} request_id(s) matched more than one "
            f"TCP stream -- check for connection reuse or ID collisions."
        )

    # Coarse phase split: setup (SYN through the GET request being sent)
    # vs. response (GET request through the stream's last packet).
    # All phase durations are written in milliseconds to keep the CSV readable
    # and prevent tiny values from being rendered in scientific notation.
    stream_data["syn_to_get_s"] = (stream_data["get_request_time"] - stream_data["first_pkt_time"]) * 1000
    stream_data["get_to_last_pkt_s"] = (stream_data["last_pkt_time"] - stream_data["get_request_time"]) * 1000

    # Fine-grained phase split.
    stream_data["tcp_handshake_s"] = (stream_data["clienthello_time"] - stream_data["first_pkt_time"]) * 1000
    stream_data["tls_negotiation_s"] = (stream_data["get_request_time"] - stream_data["clienthello_time"]) * 1000
    stream_data["ttfb_s"] = (stream_data["first_response_pkt_time"] - stream_data["get_request_time"]) * 1000
    stream_data["response_transfer_s"] = (stream_data["last_data_pkt_time"] - stream_data["first_response_pkt_time"]) * 1000
    stream_data["teardown_s"] = (stream_data["last_pkt_time"] - stream_data["last_data_pkt_time"]) * 1000

    missing_markers = stream_data[
        stream_data[["clienthello_time", "first_response_pkt_time", "last_data_pkt_time"]].isna().any(axis=1)
    ]
    if not missing_markers.empty:
        print(
            f"  WARNING: {len(missing_markers)} stream(s) missing one or more fine-grained "
            f"phase markers (ClientHello, first response packet, or last data packet not "
            f"identified) -- their fine-grained phase columns will contain NaN."
        )

    # Sanity check: the fine-grained phases should sum to their coarse
    # counterparts. NaN comparisons evaluate to False, so streams already
    # missing markers are skipped here rather than double-reported.
    # Phase values are expressed in milliseconds here, so the tolerance is
    # scaled to the same unit.
    TOLERANCE_MS = 1e-6
    setup_gap = (stream_data["tcp_handshake_s"] + stream_data["tls_negotiation_s"] - stream_data["syn_to_get_s"]).abs()
    response_gap = (
        stream_data["ttfb_s"] + stream_data["response_transfer_s"] + stream_data["teardown_s"]
        - stream_data["get_to_last_pkt_s"]
    ).abs()
    bad_setup = stream_data[setup_gap > TOLERANCE_MS]
    bad_response = stream_data[response_gap > TOLERANCE_MS]
    if not bad_setup.empty:
        print(f"  WARNING: {len(bad_setup)} stream(s) where tcp_handshake_s + tls_negotiation_s != syn_to_get_s.")
    if not bad_response.empty:
        print(
            f"  WARNING: {len(bad_response)} stream(s) where "
            f"ttfb_s + response_transfer_s + teardown_s != get_to_last_pkt_s."
        )

    result = requests_df.merge(
        stream_data.rename(columns={"tcp.stream": "pcap_stream_id"}),
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
    parser.add_argument(
        "--server-ip",
        type=str,
        default="172.20.0.10",
        help=(
            "IP address of the oqs-nginx server on ws-router-net, used to identify "
            "response packets for the ttfb_s / response_transfer_s split "
            "(default: 172.20.0.10, per docker-compose.yml)"
        ),
    )
    args = parser.parse_args()

    trial_dir = parse_path_arg(args.trial_dir).resolve()
    if not trial_dir.is_dir():
        die(f"{trial_dir} is not a directory.")

    pcap_path = trial_dir / "capture.pcap"
    if not pcap_path.exists():
        die(f"{pcap_path} not found.")

    check_tshark_available()

    keylog_path = create_temporary_keylog(trial_dir)
    try:
        packets_df = extract_stream_packets(pcap_path, keylog_path)
        ids_df = extract_stream_request_ids(pcap_path, keylog_path)
    finally:
        keylog_path.unlink(missing_ok=True)
    markers_df = compute_phase_markers(packets_df, ids_df, args.server_ip)
    requests_df = load_requests(trial_dir)

    result = combine(requests_df, markers_df, ids_df)

    output_path = parse_path_arg(args.output).resolve() if args.output else (trial_dir / "combined_metrics.csv")
    result.to_csv(output_path, index=False, float_format="%.12f")

    total = len(result)
    matched = int(result["matched"].sum())
    rate = matched / total if total else 0.0
    print(f"\nWrote {output_path}")
    print(f"{matched}/{total} requests matched to a pcap stream ({rate:.1%})")


if __name__ == "__main__":
    main()