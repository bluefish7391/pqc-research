#!/usr/bin/env python3
"""
extract_stream_metrics.py

Extracts per-TCP-stream timing and loss metrics directly from a trial's
packet capture (capture.pcap). Unlike the earlier combine_trial_data.py,
this script does NOT join against Locust's worker_*_requests.csv files --
failure rate and throughput are computed separately, from the client
(Locust) side, since those are aggregate metrics that don't require a
per-request join to the pcap. This script's only job is to pull every
piece of raw per-stream data the pcap can give us, for every stream,
whether or not that stream's HTTP layer could be decrypted.

For a given trial directory (as produced by run_trial.sh), this script:
  1. Ensures a combined "master_keylog.log" exists (concatenating all
     per-user SSLKEYLOGFILE outputs under keylogs/), so tshark can decrypt
     the TLS 1.3 traffic in capture.pcap where possible.
  2. Extracts per-packet timing, phase markers, and retransmission flags
     for every packet in capture.pcap.
  3. Extracts, per TCP stream, the request ID and send-time of the
     decrypted HTTP GET request's custom "Request-ID" header, where
     decryption succeeded. (The request ID itself is not used for any
     join here -- one trial is one treatment cell, so no per-request
     attribution is needed -- but its presence/timestamp is what lets us
     mark a stream's phase_available flag and compute get_request_time.)
  4. Derives, per TCP stream, all available phase markers:
       - pure_tcp_handshake_ms:  first packet -> client's ACK completing
                                 the 3-way TCP handshake. This is the
                                 protocol-invariant network baseline --
                                 no TLS bytes have been exchanged yet, so
                                 it should not differ between KEM configs.
       - client_key_prep_ms:     TCP handshake complete -> ClientHello
                                 sent. Isolates client-side key-generation
                                 cost (one keypair for classical, two for
                                 hybrid) with network delay held constant.
       - tls_negotiation_ms:     ClientHello -> GET request sent. Mixes
                                 server-side crypto cost and network cost
                                 (larger hybrid messages, more segments,
                                 more loss exposure) -- deliberately not
                                 separated further here; that separation
                                 is the job of the regression analysis,
                                 not this extraction step.
       - ttfb_ms:                GET request -> first response byte.
       - response_transfer_ms:   first response byte -> last *new* data
                                 packet (see last_new_data_pkt_time below).
       - teardown_ms:            last data packet -> last packet in stream.
     A stream missing any marker (e.g. no ClientHello identified, or GET
     never decrypted) gets NaN in that column and any phase column
     derived from it, rather than being dropped.
  5. Counts retransmissions per stream (tcp.analysis.retransmission) as
     a loss/recovery indicator that is always computable, independent of
     decryption success -- this is what lets streams with a genuine
     TCP reassembly gap (lost GET, never decrypted) still contribute a
     retransmission count and a full stream span to the output.
  6. Records two variants of "last data packet time":
       - last_data_pkt_time:     latest payload-bearing packet, whether
                                 or not it was a retransmission.
       - last_new_data_pkt_time: latest payload-bearing packet that was
                                 NOT flagged as a retransmission.
     stream_span_ms and teardown_ms use last_data_pkt_time (retransmission
     included) as the primary value, per the decision that stream span
     should reflect the client's literal wall-clock experience. The
     last_new_data_pkt_time / last_packet_is_retransmission columns are
     kept alongside so the retransmission-inclusive vs. -exclusive
     distinction is available for later analysis without re-extracting
     from the pcap.

This script does NOT compute an analysis-window flag (e.g. excluding the
first/last N seconds of a trial) -- that is a downstream concern, applied
consistently across latency, throughput, and failure-rate calculations,
not something to bake into raw per-stream extraction.

Usage:
    python3 extract_stream_metrics.py /absolute/path/to/trial_dir
    python3 extract_stream_metrics.py /absolute/path/to/trial_dir --output /some/other/path.csv
    python3 extract_stream_metrics.py /absolute/path/to/trial_dir --server-ip 172.20.0.10

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

    print(f"[1/5] Building temporary keylog from {len(keylog_files)} file(s) in {keylog_dir}")
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="\n",
        prefix=".extract_stream_metrics_",
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
        tcp.stream, frame.time_epoch, ip.src, tcp.len, frame.len,
        tls.handshake.type, tcp.analysis.retransmission, tcp.flags.syn,
        tcp.flags.ack, ip.flags.mf, ip.frag_offset

    This raw, per-packet data feeds compute_phase_markers() and
    compute_retransmission_stats() below. tcp.flags.syn/tcp.flags.ack are
    the dedicated boolean flag fields (0/1), not the raw tcp.flags bitmask,
    so they can be compared directly without bit-masking.

    frame.len (whole-frame wire-byte length, header included) backs the
    handshake-size and hello-packet-span metrics computed below -- these
    are deliberately kept separate from tcp.len (payload-only length)
    already used elsewhere, since "bytes on the wire" was the explicit
    definition chosen for those metrics.

    ip.flags.mf / ip.frag_offset back compute_fragmentation_total() below.
    """
    print("[2/5] Extracting per-packet timing, phase, and retransmission markers from capture.pcap...")
    stdout = run_tshark([
        "-r", str(pcap_path),
        "-o", f"tls.keylog_file:{keylog_path}",
        "-T", "fields",
        "-e", "tcp.stream",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "tcp.len",
        "-e", "frame.len",
        "-e", "tls.handshake.type",
        "-e", "tcp.analysis.retransmission",
        "-e", "tcp.flags.syn",
        "-e", "tcp.flags.ack",
        "-e", "ip.flags.mf",
        "-e", "ip.frag_offset",
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
    df["frame.len"] = pd.to_numeric(df["frame.len"], errors="coerce").fillna(0)
    # tcp.analysis.retransmission is a presence-only field (empty when absent,
    # "1" when present). Cast to a clean boolean rather than carrying the
    # raw string/NaN representation through the rest of the pipeline.
    df["is_retransmission"] = df["tcp.analysis.retransmission"].notna()
    # tcp.flags.syn / tcp.flags.ack come back as 0/1 (occasionally as empty
    # for non-TCP rows, though this capture filter is TCP-only). Coerce
    # missing values to 0 rather than leaving them as NaN.
    df["tcp.flags.syn"] = pd.to_numeric(df["tcp.flags.syn"], errors="coerce").fillna(0).astype(int)
    df["tcp.flags.ack"] = pd.to_numeric(df["tcp.flags.ack"], errors="coerce").fillna(0).astype(int)
    # ip.flags.mf / ip.frag_offset are only populated on IP-fragmented
    # packets; coerce missing values to 0 ("not a fragment") rather than
    # leaving them as NaN, same treatment as the TCP flag fields above.
    df["ip.flags.mf"] = pd.to_numeric(df["ip.flags.mf"], errors="coerce").fillna(0).astype(int)
    df["ip.frag_offset"] = pd.to_numeric(df["ip.frag_offset"], errors="coerce").fillna(0).astype(int)

    return df


def extract_stream_request_ids(pcap_path: Path, keylog_path: Path) -> pd.DataFrame:
    """
    Returns a DataFrame with one row per TCP stream that had a decrypted
    HTTP request:
        tcp.stream, request_id, get_request_time

    get_request_time is the frame.time_epoch of the packet tshark reports
    the HTTP request on. The request_id itself is not used for any join
    in this script (see module docstring) -- it is kept only as a
    diagnostic and as the basis for get_request_time / phase_available.

    A stream can, in principle, emit more than one http.request row for
    the same GET (e.g. if tshark's dissector fires on both an original
    and a retransmitted copy of the segment carrying it); sorting by time
    and keeping the first occurrence per stream ensures get_request_time
    reflects when the client first sent the request, not a later replay.
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
    result = result.rename(columns={"frame.time_epoch": "get_request_time"})

    dup_streams = result["tcp.stream"][result["tcp.stream"].duplicated()]
    if not dup_streams.empty:
        print(
            f"  NOTE: {dup_streams.nunique()} stream(s) had more than one decrypted "
            f"HTTP request (likely a dissected retransmission); keeping the earliest."
        )
        result = result.sort_values("get_request_time").drop_duplicates(subset="tcp.stream", keep="first")

    return result


def compute_retransmission_stats(packets_df: pd.DataFrame) -> pd.DataFrame:
    """
    Returns a DataFrame with one row per TCP stream:
        tcp.stream, retransmission_count

    Computed purely from packet-level flags, so this is available for
    every stream regardless of whether its HTTP layer could be decrypted
    -- including streams with a genuine reassembly gap from a lost GET.
    """
    print("[4/5] Counting retransmissions per stream...")
    counts = (
        packets_df.groupby("tcp.stream")["is_retransmission"]
        .sum()
        .rename("retransmission_count")
        .reset_index()
    )
    return counts


def compute_phase_markers(packets_df: pd.DataFrame, ids_df: pd.DataFrame, server_ip: str) -> pd.DataFrame:
    """
    Computes, per TCP stream, every timing marker needed for the phase
    breakdown described in the module docstring:
        tcp.stream, first_pkt_time, last_pkt_time, pcap_duration_s,
        syn_ack_time, tcp_handshake_complete_time,
        clienthello_time, get_request_time,
        first_response_pkt_time,
        last_data_pkt_time, last_new_data_pkt_time,
        last_packet_is_retransmission

    Marker definitions:
      - first_pkt_time / last_pkt_time: earliest/latest packet in the
        stream.
      - syn_ack_time: earliest SYN+ACK packet sourced from server_ip --
        marks the server's half of the TCP handshake.
      - tcp_handshake_complete_time: earliest zero-payload ACK (not a
        SYN) sourced from the client, sent after syn_ack_time -- marks
        the client's final ACK completing the 3-way TCP handshake. The
        "sent after syn_ack_time" filter avoids mistaking a later,
        unrelated zero-payload ACK (e.g. during data transfer) for this
        one.
      - clienthello_time: earliest packet whose tls.handshake.type
        includes 1 (ClientHello).
      - first_response_pkt_time: earliest packet sourced from server_ip,
        carrying a non-empty TCP payload, sent after that stream's GET
        request.
      - last_data_pkt_time: latest packet in the stream carrying a
        non-empty TCP payload, retransmissions included.
      - last_new_data_pkt_time: latest payload-bearing packet that was
        NOT flagged as a retransmission. Equal to last_data_pkt_time
        unless the very last data packet in the stream was itself a
        retransmission.

    A stream missing any of these markers (e.g. no ClientHello
    identified, TCP handshake never completed, GET never decrypted)
    simply gets NaN in that column and in any phase column derived from
    it -- reported by the caller rather than silently dropped.
    """
    print("[5/5] Deriving phase markers per stream...")

    get_times = ids_df.set_index("tcp.stream")["get_request_time"]
    packets_df = packets_df.copy()
    packets_df["get_request_time"] = packets_df["tcp.stream"].map(get_times)

    def has_clienthello(field):
        if not isinstance(field, str):
            return False
        return "1" in field.split(";")

    def has_serverhello(field):
        if not isinstance(field, str):
            return False
        return "2" in field.split(";")

    is_clienthello = packets_df["tls.handshake.type"].apply(has_clienthello)
    is_serverhello = packets_df["tls.handshake.type"].apply(has_serverhello)

    first_pkt_time = packets_df.groupby("tcp.stream")["frame.time_epoch"].min()
    last_pkt_time = packets_df.groupby("tcp.stream")["frame.time_epoch"].max()
    clienthello_time = packets_df[is_clienthello].groupby("tcp.stream")["frame.time_epoch"].min()
    serverhello_time = packets_df[is_serverhello].groupby("tcp.stream")["frame.time_epoch"].min()

    # -- TCP 3-way handshake markers --
    is_syn_ack = (
        (packets_df["tcp.flags.syn"] == 1)
        & (packets_df["tcp.flags.ack"] == 1)
        & (packets_df["ip.src"] == server_ip)
    )
    syn_ack_time = packets_df[is_syn_ack].groupby("tcp.stream")["frame.time_epoch"].min()

    packets_df["syn_ack_time"] = packets_df["tcp.stream"].map(syn_ack_time)
    is_client_final_ack = (
        (packets_df["tcp.flags.syn"] == 0)
        & (packets_df["tcp.flags.ack"] == 1)
        & (packets_df["tcp.len"] == 0)
        & (packets_df["ip.src"] != server_ip)
        & (packets_df["frame.time_epoch"] > packets_df["syn_ack_time"])
    )
    tcp_handshake_complete_time = (
        packets_df[is_client_final_ack].groupby("tcp.stream")["frame.time_epoch"].min()
    )

    # -- data / response markers --
    data_pkts = packets_df[packets_df["tcp.len"] > 0]
    last_data_pkt_time = data_pkts.groupby("tcp.stream")["frame.time_epoch"].max()

    non_retrans_data_pkts = data_pkts[~data_pkts["is_retransmission"]]
    last_new_data_pkt_time = non_retrans_data_pkts.groupby("tcp.stream")["frame.time_epoch"].max()

    response_pkts = data_pkts[
        (data_pkts["ip.src"] == server_ip)
        & (data_pkts["frame.time_epoch"] > data_pkts["get_request_time"])
    ]
    first_response_pkt_time = response_pkts.groupby("tcp.stream")["frame.time_epoch"].min()

    markers = pd.DataFrame({
        "first_pkt_time": first_pkt_time,
        "last_pkt_time": last_pkt_time,
        "syn_ack_time": syn_ack_time,
        "tcp_handshake_complete_time": tcp_handshake_complete_time,
        "clienthello_time": clienthello_time,
        "serverhello_time": serverhello_time,
        "first_response_pkt_time": first_response_pkt_time,
        "last_data_pkt_time": last_data_pkt_time,
        "last_new_data_pkt_time": last_new_data_pkt_time,
    }).reset_index()

    markers["pcap_duration_s"] = markers["last_pkt_time"] - markers["first_pkt_time"]
    markers["last_packet_is_retransmission"] = (
        markers["last_data_pkt_time"] != markers["last_new_data_pkt_time"]
    )

    return markers


def compute_handshake_size(packets_df: pd.DataFrame, markers_df: pd.DataFrame, ids_df: pd.DataFrame) -> pd.DataFrame:
    """
    Returns a DataFrame with one row per TCP stream:
        tcp.stream, handshake_bytes, handshake_packet_count

    Defines "the handshake" as a time window -- every packet in the
    stream from first_pkt_time through get_request_time -- rather than
    by which packets tshark happens to tag with a tls.handshake.type.
    This is a deliberate choice: tshark only tags the packet where a TLS
    record finishes reassembling, so a message split across multiple TCP
    segments (the case this project cares about most, since a hybrid
    ClientHello is the one message mechanically guaranteed to be larger)
    would be undercounted by a tagging-based filter. The time-window
    definition trades a small amount of precision (a stray
    retransmission landing inside the window gets counted) for a
    definition that can't silently miss segmented messages.

    Streams with no decrypted GET request (get_request_time is NaN) get
    NaN in both output columns, consistent with how other GET-dependent
    phase columns are handled elsewhere in this script.
    """
    get_times = ids_df.set_index("tcp.stream")["get_request_time"]
    first_times = markers_df.set_index("tcp.stream")["first_pkt_time"]

    df = packets_df.copy()
    df["first_pkt_time"] = df["tcp.stream"].map(first_times)
    df["get_request_time"] = df["tcp.stream"].map(get_times)

    # NaN comparisons evaluate to False, so streams with no get_request_time
    # are automatically excluded here (and end up NaN after the left-merge
    # in build_stream_table), rather than needing an explicit check.
    in_window = (
        (df["frame.time_epoch"] >= df["first_pkt_time"])
        & (df["frame.time_epoch"] <= df["get_request_time"])
    )

    return (
        df[in_window]
        .groupby("tcp.stream")
        .agg(handshake_bytes=("frame.len", "sum"), handshake_packet_count=("frame.len", "count"))
        .reset_index()
    )


def extract_hello_lengths(pcap_path: Path, keylog_path: Path) -> pd.DataFrame:
    """
    Returns a DataFrame with one row per TCP stream that had an
    identifiable ClientHello and/or ServerHello:
        tcp.stream, clienthello_length, serverhello_length

    Uses tls.handshake.length rather than the frame.len-based windowing
    used elsewhere in this script. tls.handshake.length is the exact,
    protocol-defined message length (header-and-segmentation-agnostic),
    reported by tshark on whichever packet completes reassembly of that
    message -- so it is correct even when the message was split across
    multiple TCP segments. This is a deliberate departure from the
    "bytes on the wire" definition used for handshake_bytes above: it
    answers "how big was this message, per the protocol" rather than
    "how many bytes did it cost to deliver on the wire."
    """
    print("Extracting ClientHello/ServerHello lengths...")
    stdout = run_tshark([
        "-r", str(pcap_path),
        "-o", f"tls.keylog_file:{keylog_path}",
        "-Y", "tls.handshake.type == 1 or tls.handshake.type == 2",
        "-T", "fields",
        "-e", "tcp.stream",
        "-e", "tls.handshake.type",
        "-e", "tls.handshake.length",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d",
        "-E", "occurrence=a",
        "-E", "aggregator=;",
    ])

    empty_result = pd.DataFrame(columns=["tcp.stream", "clienthello_length", "serverhello_length"])

    df = pd.read_csv(StringIO(stdout))
    if df.empty:
        print("  WARNING: no ClientHello/ServerHello messages found via tls.handshake.length.")
        return empty_result

    # tls.handshake.type / tls.handshake.length can each carry more than one
    # ';'-joined value on a single packet if multiple handshake messages
    # coalesce into one TLS record. Explode both fields together (pandas
    # >= 1.3) so each (type, length) pair lands on its own row before
    # filtering -- otherwise a coalesced record could hide a hello length
    # behind an unrelated message sharing the same packet.
    df["tls.handshake.type"] = df["tls.handshake.type"].astype(str).str.split(";")
    df["tls.handshake.length"] = df["tls.handshake.length"].astype(str).str.split(";")
    df = df.explode(["tls.handshake.type", "tls.handshake.length"])

    df["tls.handshake.type"] = pd.to_numeric(df["tls.handshake.type"], errors="coerce")
    df["tls.handshake.length"] = pd.to_numeric(df["tls.handshake.length"], errors="coerce")

    # A stream could in principle show more than one ClientHello/ServerHello
    # row (e.g. a dissected retransmission of the same message); keep the
    # first, same policy as extract_stream_request_ids() uses for duplicate
    # HTTP requests.
    clienthello = (
        df[df["tls.handshake.type"] == 1]
        .drop_duplicates(subset="tcp.stream", keep="first")[["tcp.stream", "tls.handshake.length"]]
        .rename(columns={"tls.handshake.length": "clienthello_length"})
    )
    serverhello = (
        df[df["tls.handshake.type"] == 2]
        .drop_duplicates(subset="tcp.stream", keep="first")[["tcp.stream", "tls.handshake.length"]]
        .rename(columns={"tls.handshake.length": "serverhello_length"})
    )

    if clienthello.empty and serverhello.empty:
        return empty_result

    return clienthello.merge(serverhello, on="tcp.stream", how="outer")


def compute_hello_packet_spans(packets_df: pd.DataFrame, markers_df: pd.DataFrame, server_ip: str) -> pd.DataFrame:
    """
    Returns a DataFrame with one row per TCP stream:
        tcp.stream, clienthello_packet_span, clienthello_span_bytes,
        serverhello_packet_span, serverhello_span_bytes

    Reports how many packets (and how many wire bytes) it took to
    deliver each hello message, using the same per-stream time windows
    already established in compute_phase_markers:
      - ClientHello span: client-sourced packets strictly after
        tcp_handshake_complete_time, up through clienthello_time.
      - ServerHello span: server-sourced packets strictly after
        clienthello_time, up through serverhello_time.
    A span of 1 means the message fit in a single segment; a span > 1
    means it was split across multiple TCP segments -- the fragmentation
    -relevant case motivating this metric (a larger hybrid ClientHello
    is more likely to need more than one segment). Streams missing a
    marker (e.g. no ServerHello identified) get NaN, consistent with
    other marker-dependent columns in this script.
    """
    m = markers_df.set_index("tcp.stream")
    df = packets_df.copy()
    df["tcp_handshake_complete_time"] = df["tcp.stream"].map(m["tcp_handshake_complete_time"])
    df["clienthello_time"] = df["tcp.stream"].map(m["clienthello_time"])
    df["serverhello_time"] = df["tcp.stream"].map(m["serverhello_time"])

    in_clienthello_window = (
        (df["ip.src"] != server_ip)
        & (df["frame.time_epoch"] > df["tcp_handshake_complete_time"])
        & (df["frame.time_epoch"] <= df["clienthello_time"])
    )
    in_serverhello_window = (
        (df["ip.src"] == server_ip)
        & (df["frame.time_epoch"] > df["clienthello_time"])
        & (df["frame.time_epoch"] <= df["serverhello_time"])
    )

    clienthello_span = (
        df[in_clienthello_window]
        .groupby("tcp.stream")
        .agg(clienthello_packet_span=("frame.len", "count"), clienthello_span_bytes=("frame.len", "sum"))
        .reset_index()
    )
    serverhello_span = (
        df[in_serverhello_window]
        .groupby("tcp.stream")
        .agg(serverhello_packet_span=("frame.len", "count"), serverhello_span_bytes=("frame.len", "sum"))
        .reset_index()
    )

    return clienthello_span.merge(serverhello_span, on="tcp.stream", how="outer")


def compute_fragmentation_total(packets_df: pd.DataFrame) -> int:
    """
    Returns a single trial-wide count of IP-fragmented packets: any
    packet with the "more fragments" flag set (ip.flags.mf == 1) or a
    nonzero fragment offset (ip.frag_offset > 0).

    Deliberately NOT grouped by tcp.stream: only the first piece of a
    fragmented packet carries a TCP header (source/destination port,
    sequence number), since that information lives in the payload that
    got split away for every later fragment. tshark therefore cannot
    assign tcp.stream to most fragments, so a per-stream breakdown would
    silently undercount. Reported once per trial instead. Expected to be
    0 for most/all trials given typical Docker-bridge MTU sizes -- kept
    here to confirm that assumption rather than leave it unverified.
    """
    is_fragment = (packets_df["ip.flags.mf"] == 1) | (packets_df["ip.frag_offset"] > 0)
    return int(is_fragment.sum())


def build_stream_table(
    markers_df: pd.DataFrame,
    ids_df: pd.DataFrame,
    retrans_df: pd.DataFrame,
    handshake_size_df: pd.DataFrame,
    hello_lengths_df: pd.DataFrame,
    hello_spans_df: pd.DataFrame,
) -> pd.DataFrame:
    """
    Assembles the final per-stream table: phase markers, request IDs (for
    get_request_time / phase_available), retransmission counts,
    handshake-window size, hello message lengths, and hello packet spans,
    all keyed on tcp.stream. This is a set of left-joins on a single key
    that every source shares (tcp.stream) -- not the request_id-based
    join the old combine_trial_data.py performed against Locust's data.
    """
    table = markers_df.merge(ids_df, on="tcp.stream", how="left")
    table = table.merge(retrans_df, on="tcp.stream", how="left")
    table = table.merge(handshake_size_df, on="tcp.stream", how="left")
    table = table.merge(hello_lengths_df, on="tcp.stream", how="left")
    table = table.merge(hello_spans_df, on="tcp.stream", how="left")
    table["retransmission_count"] = table["retransmission_count"].fillna(0).astype(int)
    table["phase_available"] = table["get_request_time"].notna()

    # Durations in milliseconds throughout, to keep the CSV readable and
    # avoid tiny values rendering in scientific notation.
    table["stream_span_ms"] = table["pcap_duration_s"] * 1000
    table["pure_tcp_handshake_ms"] = (table["tcp_handshake_complete_time"] - table["first_pkt_time"]) * 1000
    table["client_key_prep_ms"] = (table["clienthello_time"] - table["tcp_handshake_complete_time"]) * 1000
    table["tls_negotiation_ms"] = (table["get_request_time"] - table["clienthello_time"]) * 1000
    table["ttfb_ms"] = (table["first_response_pkt_time"] - table["get_request_time"]) * 1000
    table["response_transfer_ms"] = (table["last_new_data_pkt_time"] - table["first_response_pkt_time"]) * 1000
    table["teardown_ms"] = (table["last_pkt_time"] - table["last_data_pkt_time"]) * 1000

    # Sanity check (carried over from the original script's syn_to_get_ms
    # invariant, updated to reflect the finer 3-way split): the fine
    # phases from first packet through the GET request being sent should
    # sum to the coarse first_pkt_time -> get_request_time span. NaN
    # comparisons evaluate to False, so streams already missing a marker
    # are skipped here rather than double-reported.
    TOLERANCE_MS = 1e-6
    setup_ms = (table["get_request_time"] - table["first_pkt_time"]) * 1000
    setup_gap = (
        table["pure_tcp_handshake_ms"] + table["client_key_prep_ms"] + table["tls_negotiation_ms"] - setup_ms
    ).abs()
    bad_setup = table[setup_gap > TOLERANCE_MS]
    if not bad_setup.empty:
        print(
            f"  WARNING: {len(bad_setup)} stream(s) where "
            f"pure_tcp_handshake_ms + client_key_prep_ms + tls_negotiation_ms "
            f"!= (get_request_time - first_pkt_time)."
        )

    response_ms = (table["last_pkt_time"] - table["get_request_time"]) * 1000
    response_gap = (
        table["ttfb_ms"] + table["response_transfer_ms"] + table["teardown_ms"] - response_ms
    ).abs()
    bad_response = table[response_gap > TOLERANCE_MS]
    if not bad_response.empty:
        print(
            f"  WARNING: {len(bad_response)} stream(s) where "
            f"ttfb_ms + response_transfer_ms + teardown_ms != (last_pkt_time - get_request_time)."
        )

    output_columns = [
        "tcp.stream", "request_id", "phase_available",
        "first_pkt_time", "last_pkt_time", "stream_span_ms",
        "retransmission_count",
        "syn_ack_time", "tcp_handshake_complete_time", "pure_tcp_handshake_ms",
        "clienthello_time", "client_key_prep_ms",
        "clienthello_length", "clienthello_packet_span", "clienthello_span_bytes",
        "serverhello_time", "serverhello_length", "serverhello_packet_span", "serverhello_span_bytes",
        "handshake_bytes", "handshake_packet_count",
        "get_request_time", "tls_negotiation_ms",
        "first_response_pkt_time", "ttfb_ms",
        "last_new_data_pkt_time", "response_transfer_ms",
        "last_data_pkt_time", "teardown_ms",
        "last_packet_is_retransmission",
    ]
    return table[output_columns].rename(columns={"tcp.stream": "pcap_stream_id"})


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("trial_dir", type=str, help="Absolute path to a trial directory")
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output CSV path (default: <trial_dir>/pcap_stream_metrics.csv)",
    )
    parser.add_argument(
        "--server-ip",
        type=str,
        default="172.20.0.10",
        help=(
            "IP address of the oqs-nginx server on ws-router-net, used to identify "
            "server-originated packets for the TCP-handshake and response markers "
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

    retrans_df = compute_retransmission_stats(packets_df)
    markers_df = compute_phase_markers(packets_df, ids_df, args.server_ip)
    handshake_size_df = compute_handshake_size(packets_df, markers_df, ids_df)
    hello_lengths_df = extract_hello_lengths(pcap_path, keylog_path)
    hello_spans_df = compute_hello_packet_spans(packets_df, markers_df, args.server_ip)
    fragmentation_total = compute_fragmentation_total(packets_df)

    result = build_stream_table(
        markers_df, ids_df, retrans_df, handshake_size_df, hello_lengths_df, hello_spans_df
    )

    output_path = parse_path_arg(args.output).resolve() if args.output else (trial_dir / "pcap_stream_metrics.csv")
    result.to_csv(output_path, index=False, float_format="%.12f")

    # Trial-wide (not per-stream) metric: written to its own small file
    # rather than as a repeated constant column on every row of the
    # per-stream CSV, since fragmentation can't be attributed to a stream
    # (see compute_fragmentation_total docstring).
    fragmentation_summary_path = trial_dir / "fragmentation_summary.csv"
    pd.DataFrame([{"fragmented_packet_count": fragmentation_total}]).to_csv(
        fragmentation_summary_path, index=False
    )

    total = len(result)
    available = int(result["phase_available"].sum())
    rate = available / total if total else 0.0
    print(f"\nWrote {output_path}")
    print(f"{available}/{total} streams had a decrypted GET request ({rate:.1%}); "
          f"the remainder still have stream_span_ms and retransmission_count.")
    print(f"Wrote {fragmentation_summary_path} (fragmented_packet_count={fragmentation_total})")


if __name__ == "__main__":
    main()