#!/usr/bin/env python3
"""Plot per-request latency across Locust worker request CSVs.

Given an absolute path to a trial directory containing
``locust/requests/worker_*_requests.csv`` files, this script computes request duration as:

    duration_ms = (end_time_ns - start_time_ns) / 1e6

and plots a scatter chart with:
  - x-axis: seconds since the first observed request start
    - y-axis: request duration in milliseconds (or stream span with a flag)

The chart is rendered as one combined figure with one trace per worker file.
Each scatter point includes a phase breakdown derived from the packet capture:
task start to first SYN, SYN to GET, and GET to end of stream.
The completed-request histograms default to end-time buckets, but can be
anchored to request start time with a command-line flag.
"""

import argparse
import csv
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
from bisect import bisect_left
from pathlib import Path

from collection_cleaner.pcap import TSHARK_FIELD_ARGS, parse_tshark_csv
from collection_cleaner.pcap import classify_direction


# Histogram bucket sizes (in seconds) used for completed-request density plots.
HISTOGRAM_BUCKET_SIZES_S = [0.01, 0.05, 0.1, 1]
REQUEST_ID_HEADER_RE = re.compile(
    r"(?:^|\r?\n)(?:X-)?Request-ID:\s*([^\r\n]+)",
    re.IGNORECASE,
)
TSHARK_RETRANS_FIELDS = [
    "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission",
    "tcp.analysis.spurious_retransmission",
]
PHASE_TSHARK_FIELD_ARGS = [
    "-T",
    "fields",
    "-e",
    "frame.time_epoch",
    "-e",
    "tcp.stream",
    "-e",
    "ip.src",
    "-e",
    "ip.dst",
    "-e",
    "tcp.analysis.retransmission",
    "-e",
    "tcp.analysis.fast_retransmission",
    "-e",
    "tcp.analysis.spurious_retransmission",
    "-e",
    "tcp.flags.syn",
    "-e",
    "tcp.flags.ack",
    "-e",
    "tcp.len",
    "-e",
    "http.request.method",
    "-E",
    "separator=,",
    "-E",
    "header=n",
]


def resolve_trial_dir(trial_dir_arg: str) -> Path:
    path = Path(trial_dir_arg)
    if not path.is_absolute():
        sys.exit(f"ERROR: trial directory must be an absolute path: {trial_dir_arg}")

    trial_dir = path.resolve()
    if not trial_dir.is_dir():
        sys.exit(f"ERROR: trial directory not found: {trial_dir}")

    requests_dir = trial_dir / "locust" / "requests"
    if not requests_dir.is_dir():
        sys.exit(f"ERROR: requests directory not found under trial directory: {requests_dir}")
    return trial_dir


def resolve_requests_dir(trial_dir: Path) -> Path:
    return trial_dir / "locust" / "requests"


def discover_worker_files(requests_dir: Path, expected_workers: int):
    worker_files = sorted(requests_dir.glob("worker_*_requests.csv"))
    if not worker_files:
        sys.exit(
            "ERROR: no worker request CSV files found with pattern "
            f"worker_*_requests.csv under {requests_dir}"
        )

    if len(worker_files) < expected_workers:
        print(
            f"WARNING: expected at least {expected_workers} worker files, found {len(worker_files)}",
            file=sys.stderr,
        )

    return worker_files


def worker_label_from_path(worker_file: Path) -> str:
    name = worker_file.name
    prefix = "worker_"
    suffix = "_requests.csv"
    if name.startswith(prefix) and name.endswith(suffix):
        return name[len(prefix) : -len(suffix)]
    return name


def parse_worker_rows(worker_file: Path):
    parsed_rows = []
    skipped_rows = 0

    with open(worker_file, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                start_ns = int(row["start_time_ns"])
                end_ns = int(row["end_time_ns"])
            except (KeyError, ValueError, TypeError):
                skipped_rows += 1
                continue

            parsed_rows.append(
                {
                    "request_id": row.get("request_id", ""),
                    "start_time_ns": start_ns,
                    "end_time_ns": end_ns,
                    "success": row.get("success", ""),
                }
            )

    return parsed_rows, skipped_rows


def _ns_to_ms(delta_ns: int | None):
    if delta_ns is None:
        return None
    return delta_ns / 1_000_000


def build_plot_points(worker_rows, success_only: bool):
    all_rows = []
    skip_summary = []

    for label, rows, skipped in worker_rows:
        if skipped:
            skip_summary.append((label, skipped))

        for row in rows:
            if success_only and row["success"] != "False":
                continue

            duration_ns = row["end_time_ns"] - row["start_time_ns"]
            if duration_ns < 0:
                continue

            all_rows.append(
                {
                    "worker": label,
                    "request_id": row["request_id"],
                    "start_time_ns": row["start_time_ns"],
                    "end_time_ns": row["end_time_ns"],
                    "duration_ms": duration_ns / 1_000_000,
                }
            )

    if not all_rows:
        sys.exit("ERROR: no valid request rows to plot after parsing/filtering")

    min_start_ns = min(row["start_time_ns"] for row in all_rows)
    for row in all_rows:
        row["relative_start_s"] = (row["start_time_ns"] - min_start_ns) / 1_000_000_000
        row["relative_end_s"] = (row["end_time_ns"] - min_start_ns) / 1_000_000_000

    return all_rows, skip_summary


def _parse_phase_packets(stdout: str) -> list[dict]:
    packets = []
    reader = csv.reader(stdout.splitlines())
    for row in reader:
        if len(row) < 4:
            continue

        try:
            epoch = float(row[0])
            stream = int(row[1])
        except (TypeError, ValueError):
            continue

        src_ip = row[2].strip() if len(row) > 2 else ""
        dst_ip = row[3].strip() if len(row) > 3 else ""
        retrans = any(_parse_boolish(value) for value in row[4:7])
        syn = _parse_boolish(row[7] if len(row) > 7 else None)
        ack = _parse_boolish(row[8] if len(row) > 8 else None)
        tcp_len = 0
        if len(row) > 9:
            try:
                tcp_len = int(row[9] or 0)
            except (TypeError, ValueError):
                tcp_len = 0
        request_method = row[10].strip() if len(row) > 10 else ""

        direction = classify_direction(src_ip, dst_ip)

        packets.append(
            {
                "time_ns": int(epoch * 1_000_000_000),
                "stream": stream,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "direction": direction,
                "retrans": retrans,
                "syn": syn,
                "ack": ack,
                "tcp_len": tcp_len,
                "request_method": request_method,
            }
        )

    packets.sort(key=lambda p: (p["time_ns"], p["stream"]))
    return packets


def _build_stream_phase_summary(packets: list[dict]) -> dict[int, dict[str, int | None]]:
    packets_by_stream: dict[int, list[dict]] = {}
    for packet in packets:
        packets_by_stream.setdefault(int(packet["stream"]), []).append(packet)

    summary: dict[int, dict[str, int | None]] = {}
    for stream, stream_packets in packets_by_stream.items():
        entry: dict[str, int | None] = {
            "first_packet_ns": None,
            "first_syn_ns": None,
            "get_ns": None,
            "end_ns": None,
        }

        # Prefer deriving the client endpoint from HTTP request packets.
        client_ip = None
        for packet in stream_packets:
            if packet.get("request_method"):
                client_ip = packet.get("src_ip")
                break
        if client_ip is None:
            for packet in stream_packets:
                if packet.get("syn") and not packet.get("ack"):
                    client_ip = packet.get("src_ip")
                    break

        for packet in stream_packets:
            time_ns = int(packet["time_ns"])
            if entry["first_packet_ns"] is None:
                entry["first_packet_ns"] = time_ns
            entry["end_ns"] = time_ns

            from_client = client_ip is None or packet.get("src_ip") == client_ip

            if entry["first_syn_ns"] is None and packet.get("syn") and not packet.get("ack") and from_client:
                entry["first_syn_ns"] = time_ns

            if entry["get_ns"] is None and from_client and packet.get("request_method"):
                entry["get_ns"] = time_ns

            if (
                entry["get_ns"] is None
                and from_client
                and packet.get("tcp_len", 0) > 0
                and not packet.get("syn")
                and time_ns >= (entry["first_syn_ns"] or time_ns)
            ):
                entry["get_ns"] = time_ns

        summary[stream] = entry

    return summary


def _populate_phase_timings(
    points: list[dict],
    phase_summary_by_stream: dict[int, dict[str, int | None]],
    request_time_by_id: dict[str, int],
) -> None:
    for row in points:
        stream = row.get("tcp_stream")
        phase_summary = phase_summary_by_stream.get(stream) if stream is not None else None
        row["task_to_syn_ms"] = None
        row["syn_to_get_ms"] = None
        row["get_to_end_ms"] = None
        row["stream_span_ms"] = None

        if phase_summary is None:
            continue

        first_syn_ns = phase_summary.get("first_syn_ns")
        first_packet_ns = phase_summary.get("first_packet_ns")
        get_ns = request_time_by_id.get(row["request_id"]) or phase_summary.get("get_ns")
        end_ns = phase_summary.get("end_ns")

        if first_syn_ns is not None:
            row["task_to_syn_ms"] = _ns_to_ms(first_syn_ns - row["start_time_ns"])
        if first_syn_ns is not None and get_ns is not None:
            row["syn_to_get_ms"] = _ns_to_ms(get_ns - first_syn_ns)
        if get_ns is not None and end_ns is not None:
            row["get_to_end_ms"] = _ns_to_ms(end_ns - get_ns)
        if first_packet_ns is not None and end_ns is not None:
            row["stream_span_ms"] = _ns_to_ms(end_ns - first_packet_ns)


def percentile(values, pct):
    """Nearest-rank style percentile using rounded index on sorted values."""
    if not values:
        return None

    ordered = sorted(values)
    k = max(0, min(len(ordered) - 1, round(pct / 100 * (len(ordered) - 1))))
    return ordered[k]


def compute_trial_percentiles(points):
    durations_ms = [row["duration_ms"] for row in points]
    return {
        "p50": percentile(durations_ms, 50),
        "p90": percentile(durations_ms, 90),
        "p99": percentile(durations_ms, 99),
    }


def print_trial_percentiles(points):
    percentiles = compute_trial_percentiles(points)
    for label in ("p50", "p90", "p99"):
        value = percentiles[label]
        value_str = f"{value:.3f}" if value is not None and math.isfinite(value) else "n/a"
        print(f"{label.upper()}: {value_str} ms")


def _format_bucket_label(bucket_size_s: float) -> str:
    bucket_ms = bucket_size_s * 1000
    if float(bucket_ms).is_integer():
        return f"{int(bucket_ms)}ms"
    return f"{bucket_ms:g}ms"


def _parse_boolish(value) -> bool:
    if value is None:
        return False
    if isinstance(value, list):
        return any(_parse_boolish(item) for item in value)
    text = str(value).strip().lower()
    return text not in {"", "0", "false", "no"}


def _recursive_find_request_id(value) -> str | None:
    if isinstance(value, dict):
        for nested in value.values():
            request_id = _recursive_find_request_id(nested)
            if request_id:
                return request_id
        return None

    if isinstance(value, list):
        for nested in value:
            request_id = _recursive_find_request_id(nested)
            if request_id:
                return request_id
        return None

    if isinstance(value, str):
        match = REQUEST_ID_HEADER_RE.search(value)
        if match:
            return match.group(1).strip()
    return None


def _extract_json_layers(packet: dict) -> dict:
    return packet.get("_source", {}).get("layers", {})


def _first_scalar_value(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        for item in value:
            scalar = _first_scalar_value(item)
            if scalar is not None:
                return scalar
        return None
    if isinstance(value, dict):
        for nested in value.values():
            scalar = _first_scalar_value(nested)
            if scalar is not None:
                return scalar
        return None
    return str(value)


def _first_field_value(layers: dict, field: str) -> str | None:
    # tshark JSON nests fields under protocol trees (e.g. layers["tcp"]["tcp.stream"]),
    # so walk recursively instead of assuming a flat dictionary.
    stack = [layers]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            if field in current:
                scalar = _first_scalar_value(current[field])
                if scalar is not None:
                    return scalar
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
    return None


def _packet_is_retransmission(layers: dict) -> bool:
    return any(_parse_boolish(layers.get(field)) for field in TSHARK_RETRANS_FIELDS)


def _load_request_stream_map(records: list[dict], include_retransmissions: bool):
    request_to_stream: dict[str, int] = {}
    conflicting_request_ids = 0

    for packet in records:
        layers = _extract_json_layers(packet)
        request_id = _recursive_find_request_id(layers.get("http", {}))
        if not request_id:
            continue

        if not include_retransmissions and _packet_is_retransmission(layers):
            continue

        stream_value = _first_field_value(layers, "tcp.stream")
        if stream_value is None:
            continue

        try:
            stream = int(stream_value)
        except ValueError:
            continue

        existing = request_to_stream.get(request_id)
        if existing is None:
            request_to_stream[request_id] = stream
        elif existing != stream:
            conflicting_request_ids += 1

    return request_to_stream, conflicting_request_ids


def _load_request_time_map(records: list[dict], include_retransmissions: bool):
    request_to_time: dict[str, int] = {}

    for packet in records:
        layers = _extract_json_layers(packet)
        request_id = _recursive_find_request_id(layers.get("http", {}))
        if not request_id:
            continue

        if not include_retransmissions and _packet_is_retransmission(layers):
            continue

        frame_time = _first_field_value(layers, "frame.time_epoch")
        if frame_time is None:
            continue

        try:
            time_ns = int(float(frame_time) * 1_000_000_000)
        except ValueError:
            continue

        existing = request_to_time.get(request_id)
        if existing is None or time_ns < existing:
            request_to_time[request_id] = time_ns

    return request_to_time


def _count_stream_retransmissions(stdout: str) -> dict[int, int]:
    counts: dict[int, int] = {}
    reader = csv.reader(stdout.splitlines())
    for row in reader:
        if not row:
            continue
        try:
            stream = int(row[0])
        except (TypeError, ValueError):
            continue

        if any(_parse_boolish(value) for value in row[1:]):
            counts[stream] = counts.get(stream, 0) + 1

    return counts


def _count_stream_retransmissions_from_packets(packets: list[dict]) -> dict[int, int]:
    counts: dict[int, int] = {}
    for packet in packets:
        if not packet.get("retrans"):
            continue
        stream = packet.get("stream")
        if stream is None:
            continue
        counts[int(stream)] = counts.get(int(stream), 0) + 1
    return counts


def _select_stream_for_window(candidates: list[dict]) -> tuple[int | None, float]:
    if not candidates:
        return None, 3.0

    by_stream: dict[int, dict[str, int]] = {}
    for packet in candidates:
        stream = int(packet["stream"])
        if stream not in by_stream:
            by_stream[stream] = {"c2s": 0, "s2c": 0, "other": 0}

        direction = packet.get("direction")
        if direction == "c2s":
            by_stream[stream]["c2s"] += 1
        elif direction == "s2c":
            by_stream[stream]["s2c"] += 1
        else:
            by_stream[stream]["other"] += 1

    if not by_stream:
        return None, 3.0

    streams = sorted(by_stream.keys())
    if len(streams) == 1:
        return streams[0], 0.0

    ranked = sorted(
        streams,
        key=lambda stream: (
            -by_stream[stream]["c2s"],
            -by_stream[stream]["s2c"],
            stream,
        ),
    )
    selected_stream = ranked[0]
    top_c2s = by_stream[selected_stream]["c2s"]
    tie_count = sum(1 for stream in ranked if by_stream[stream]["c2s"] == top_c2s)
    if tie_count > 1:
        return selected_stream, 2.0
    return selected_stream, 1.0


def _assign_streams_by_packet_windows(
    points: list[dict],
    packets_abs: list[dict],
    include_retransmissions: bool,
    preserve_existing: bool = False,
) -> tuple[int, int, dict[int, int]]:
    packets_rel = [packet for packet in packets_abs if include_retransmissions or not packet.get("retrans")]
    packet_times = [int(packet["time_ns"]) for packet in packets_rel]
    retransmissions_by_stream = _count_stream_retransmissions_from_packets(packets_abs)

    matched = 0
    missing = 0

    points_by_worker: dict[str, list[tuple[int, dict]]] = {}
    for index, row in enumerate(points):
        points_by_worker.setdefault(row["worker"], []).append((index, row))

    for worker_rows in points_by_worker.values():
        worker_rows.sort(key=lambda item: item[1]["start_time_ns"])

        for idx, (point_index, row) in enumerate(worker_rows):
            if preserve_existing and row.get("tcp_stream") is not None:
                continue

            window_start = row["start_time_ns"]
            if idx + 1 < len(worker_rows):
                window_end = worker_rows[idx + 1][1]["start_time_ns"]
            else:
                window_end = row["end_time_ns"]

            if window_end <= window_start:
                window_end = row["end_time_ns"]
            if window_end <= window_start:
                window_end = window_start + 1

            start_idx = bisect_left(packet_times, window_start)
            end_idx = bisect_left(packet_times, window_end)
            candidates = packets_rel[start_idx:end_idx]

            selected_stream, quality = _select_stream_for_window(candidates)
            row["tcp_stream"] = selected_stream
            row["stream_retransmissions"] = (
                retransmissions_by_stream.get(selected_stream, 0) if selected_stream is not None else None
            )
            row["stream_match_quality_code"] = quality

            if selected_stream is None:
                missing += 1
            else:
                matched += 1

    return matched, missing, retransmissions_by_stream


def _project_main_dir() -> Path:
    return Path(__file__).resolve().parent / "main"


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _host_tshark_available() -> bool:
    return shutil.which("tshark") is not None


def _build_tshark_command(
    trial_dir: Path,
    pcap_path: Path,
    keylog_path: Path,
    extra_args: list[str],
) -> tuple[list[str], Path | None, dict[str, str] | None]:
    if _host_tshark_available():
        return (
            ["tshark", "-r", str(pcap_path), "-o", f"tls.keylog_file:{keylog_path}", *extra_args],
            None,
            None,
        )

    main_dir = _project_main_dir()
    if _docker_available() and (main_dir / "docker-compose.yml").is_file():
        trial_parent = trial_dir.parent.resolve()
        mounted_trial_dir = Path("/mnt/cell") / trial_dir.name
        env = os.environ.copy()
        env["CELL_DIR"] = str(trial_parent)
        return (
            [
                "docker",
                "compose",
                "exec",
                "-T",
                "router",
                "tshark",
                "-r",
                str(mounted_trial_dir / "capture.pcap"),
                "-o",
                f"tls.keylog_file:{mounted_trial_dir / keylog_path.name}",
                *extra_args,
            ],
            main_dir,
            env,
        )

    raise RuntimeError(
        "tshark is not available on PATH and docker compose is unavailable for router fallback"
    )


def _ensure_router_available(trial_dir: Path) -> None:
    if _host_tshark_available() or not _docker_available():
        return

    main_dir = _project_main_dir()
    env = os.environ.copy()
    env["CELL_DIR"] = str(trial_dir.parent.resolve())
    proc = subprocess.run(
        ["docker", "compose", "up", "-d", "--no-deps", "router"],
        cwd=main_dir,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "failed to start router")


def _run_tshark(trial_dir: Path, pcap_path: Path, keylog_path: Path, extra_args: list[str]) -> str:
    _ensure_router_available(trial_dir)
    cmd, cwd, env = _build_tshark_command(trial_dir, pcap_path, keylog_path, extra_args)
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        stderr = proc.stderr.strip() or proc.stdout.strip()
        raise RuntimeError(stderr or "tshark failed")
    return proc.stdout


def _write_master_keylog(trial_dir: Path) -> Path:
    keylog_dir = trial_dir / "keylogs"
    keylog_files = sorted(keylog_dir.glob("*.log"))
    if not keylog_files:
        raise RuntimeError(f"no keylog files found under {keylog_dir}")

    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="\n",
        prefix=".plot_requests_scatter_",
        suffix=".log",
        dir=trial_dir,
        delete=False,
    ) as temp_file:
        for index, keylog_file in enumerate(keylog_files):
            if index:
                temp_file.write("\n")
            temp_file.write(keylog_file.read_text(encoding="utf-8", errors="ignore"))
        return Path(temp_file.name)


def enrich_points_with_stream_metadata(points, trial_dir: Path, include_retransmissions: bool):
    pcap_path = trial_dir / "capture.pcap"
    if not pcap_path.is_file():
        print(f"WARNING: capture.pcap not found under {trial_dir}; stream metadata omitted", file=sys.stderr)
        return

    try:
        keylog_path = _write_master_keylog(trial_dir)
    except RuntimeError as exc:
        print(f"WARNING: {exc}; stream metadata omitted", file=sys.stderr)
        return

    try:
        request_json = _run_tshark(
            trial_dir,
            pcap_path,
            keylog_path,
            ["-Y", "http.request", "-T", "json"],
        )
        retrans_csv = _run_tshark(
            trial_dir,
            pcap_path,
            keylog_path,
            [
                "-T",
                "fields",
                "-e",
                "tcp.stream",
                "-e",
                "tcp.analysis.retransmission",
                "-e",
                "tcp.analysis.fast_retransmission",
                "-e",
                "tcp.analysis.spurious_retransmission",
                "-E",
                "separator=,",
                "-E",
                "header=n",
            ],
        )
    except RuntimeError as exc:
        print(f"WARNING: unable to extract stream metadata via tshark: {exc}", file=sys.stderr)
        try:
            keylog_path.unlink(missing_ok=True)
        except OSError:
            pass
        return

    try:
        request_records = json.loads(request_json)
    except json.JSONDecodeError as exc:
        print(f"WARNING: failed to parse tshark JSON output: {exc}", file=sys.stderr)
        try:
            keylog_path.unlink(missing_ok=True)
        except OSError:
            pass
        return

    request_to_stream, conflicting_request_ids = _load_request_stream_map(
        request_records,
        include_retransmissions=include_retransmissions,
    )
    request_time_by_id = _load_request_time_map(
        request_records,
        include_retransmissions=include_retransmissions,
    )
    retransmissions_by_stream = _count_stream_retransmissions(retrans_csv)
    phase_summary_by_stream: dict[int, dict[str, int | None]] = {}
    try:
        phase_csv = _run_tshark(
            trial_dir,
            pcap_path,
            keylog_path,
            PHASE_TSHARK_FIELD_ARGS,
        )
    except RuntimeError as exc:
        print(f"WARNING: unable to extract phase timing via tshark: {exc}", file=sys.stderr)
    else:
        phase_packets = _parse_phase_packets(phase_csv)
        phase_summary_by_stream = _build_stream_phase_summary(phase_packets)

    missing_request_ids = 0
    matched_points = 0
    for row in points:
        stream = request_to_stream.get(row["request_id"])
        row["tcp_stream"] = stream
        row["stream_retransmissions"] = (
            retransmissions_by_stream.get(stream, 0) if stream is not None else None
        )
        if stream is None:
            missing_request_ids += 1
        else:
            matched_points += 1

    packet_window_fallback_used = False
    if missing_request_ids > 0:
        try:
            packet_fields_csv = _run_tshark(
                trial_dir,
                pcap_path,
                keylog_path,
                TSHARK_FIELD_ARGS,
            )
            packet_records = parse_tshark_csv(packet_fields_csv)
        except RuntimeError as exc:
            print(f"WARNING: packet-window stream fallback failed: {exc}", file=sys.stderr)
        else:
            packet_window_fallback_used = True
            _assign_streams_by_packet_windows(
                points,
                packet_records,
                include_retransmissions=include_retransmissions,
                preserve_existing=True,
            )
            matched_points = sum(1 for row in points if row.get("tcp_stream") is not None)
            missing_request_ids = len(points) - matched_points

    _populate_phase_timings(points, phase_summary_by_stream, request_time_by_id)

    print(
        "Stream metadata: "
        f"matched={matched_points} missing={missing_request_ids} "
        f"unique_streams={len(retransmissions_by_stream)} conflicting_request_ids={conflicting_request_ids} "
        f"fallback={'packet-window' if packet_window_fallback_used else 'request-id'}"
    )

    try:
        keylog_path.unlink(missing_ok=True)
    except OSError:
        pass


def render_scatter(
    points,
    output_html: str | None,
    histogram_bucket_sizes_s=None,
    histogram_time_source: str = "end",
    scatter_y_source: str = "duration",
):
    try:
        import plotly.graph_objects as go
        from plotly.subplots import make_subplots
    except ImportError:
        sys.exit(
            "ERROR: plotly is required to render the scatter plot. "
            "Install it with: pip install plotly"
        )

    if histogram_bucket_sizes_s is None:
        histogram_bucket_sizes_s = HISTOGRAM_BUCKET_SIZES_S

    if histogram_time_source not in {"start", "end"}:
        sys.exit("ERROR: histogram_time_source must be 'start' or 'end'")

    if scatter_y_source not in {"duration", "stream_span"}:
        sys.exit("ERROR: scatter_y_source must be 'duration' or 'stream_span'")

    scatter_y_field = "duration_ms" if scatter_y_source == "duration" else "stream_span_ms"
    scatter_y_label = "Request Duration (ms)" if scatter_y_source == "duration" else "Stream Span (ms)"
    scatter_y_hover_label = "duration" if scatter_y_source == "duration" else "stream_span"
    scatter_title_metric = "Request Duration" if scatter_y_source == "duration" else "Stream Span"

    valid_bucket_sizes = [size for size in histogram_bucket_sizes_s if size > 0]
    if not valid_bucket_sizes:
        sys.exit("ERROR: at least one positive histogram bucket size is required")

    workers = sorted({row["worker"] for row in points})
    histogram_rows = len(valid_bucket_sizes)
    total_rows = histogram_rows + 1
    histogram_row_height = 0.22 / histogram_rows
    row_heights = [histogram_row_height] * histogram_rows + [0.78]

    fig = make_subplots(
        rows=total_rows,
        cols=1,
        shared_xaxes=True,
        row_heights=row_heights,
        vertical_spacing=0.03,
    )

    for row_idx, bucket_size_s in enumerate(valid_bucket_sizes, start=1):
        bucket_label = _format_bucket_label(bucket_size_s)
        histogram_x_field = f"relative_{histogram_time_source}_s"
        histogram_axis_label = "Start" if histogram_time_source == "start" else "End"
        fig.add_trace(
            go.Histogram(
                x=[row[histogram_x_field] for row in points],
                xbins={"size": bucket_size_s},
                name=f"completed_requests_per_{bucket_label}",
                marker={"color": "#666666"},
                hovertemplate="completed=%{y}<br>t=%{x:.3f}s<extra></extra>",
            ),
            row=row_idx,
            col=1,
        )
        fig.update_yaxes(
            title_text=f"Completed Requests per {bucket_label} Bucket ({histogram_axis_label.lower()} time)",
            row=row_idx,
            col=1,
        )

    scatter_row = total_rows
    for worker in workers:
        worker_points = [row for row in points if row["worker"] == worker]
        fig.add_trace(
            go.Scatter(
                x=[row["relative_start_s"] for row in worker_points],
                y=[row.get(scatter_y_field) for row in worker_points],
                mode="markers",
                name=f"worker_{worker}",
                marker={"size": 5},
                hovertemplate=(
                    "worker=%{customdata[0]}<br>"
                    "request_id=%{customdata[1]}<br>"
                    "tcp_stream=%{customdata[2]}<br>"
                    "stream_retransmissions=%{customdata[3]}<br>"
                    "task_to_syn=%{customdata[4]}<br>"
                    "syn_to_get=%{customdata[5]}<br>"
                    "get_to_end=%{customdata[6]}<br>"
                    "stream_span=%{customdata[7]}<br>"
                    "t=%{x:.6f}s<br>"
                    f"{scatter_y_hover_label}=%{{y:.3f}}ms<extra></extra>"
                ),
                customdata=[
                    [
                        row["worker"],
                        row.get("request_id") or "",
                        "" if row.get("tcp_stream") is None else str(row["tcp_stream"]),
                        ""
                        if row.get("stream_retransmissions") is None
                        else str(row["stream_retransmissions"]),
                        "n/a"
                        if row.get("task_to_syn_ms") is None
                        else f"{row['task_to_syn_ms']:.3f} ms",
                        "n/a"
                        if row.get("syn_to_get_ms") is None
                        else f"{row['syn_to_get_ms']:.3f} ms",
                        "n/a"
                        if row.get("get_to_end_ms") is None
                        else f"{row['get_to_end_ms']:.3f} ms",
                        "n/a"
                        if row.get("stream_span_ms") is None
                        else f"{row['stream_span_ms']:.3f} ms",
                    ]
                    for row in worker_points
                ],
            ),
            row=scatter_row,
            col=1,
        )

    fig.update_yaxes(title_text=scatter_y_label, row=scatter_row, col=1)
    fig.update_xaxes(title_text="Time Since First Request Start (s)", row=scatter_row, col=1)

    fig.update_layout(
        title=f"{scatter_title_metric} and Phase Breakdown by Worker",
        bargap=0.05,
    )

    if output_html:
        fig.write_html(output_html)
        print(f"Wrote plot HTML: {output_html}")
    else:
        fig.show()


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Plot per-request duration scatter from a trial directory containing "
            "locust/requests/worker_*_requests.csv files."
        )
    )
    parser.add_argument("trial_dir", help="Absolute path to the trial directory containing locust/requests.")
    parser.add_argument(
        "--expected-workers",
        type=int,
        default=4,
        help="Warn if fewer worker CSV files than this count are found (default: 4).",
    )
    parser.add_argument(
        "--success-only",
        action="store_true",
        help=(
            "Include only rows where success == 'False' (this dataset uses inverted "
            "success semantics where 'False' means request succeeded)."
        ),
    )
    parser.add_argument(
        "--output-html",
        default=None,
        help="Optional output HTML path. If omitted, opens an interactive plot window.",
    )
    parser.add_argument(
        "--include-retransmissions",
        action="store_true",
        help=(
            "Allow retransmitted HTTP request records to participate when mapping "
            "request_id values to tcp streams. Retransmission counts are always reported."
        ),
    )
    parser.add_argument(
        "--histogram-start-time",
        action="store_true",
        help=(
            "Anchor completed-request histograms to request start time instead of the default "
            "request end time."
        ),
    )
    parser.add_argument(
        "--y-stream-span",
        action="store_true",
        help=(
            "Plot stream_span on the scatter y-axis instead of request duration. "
            "Requires phase timing metadata from capture parsing."
        ),
    )
    args = parser.parse_args()

    trial_dir = resolve_trial_dir(args.trial_dir)
    requests_dir = resolve_requests_dir(trial_dir)
    worker_files = discover_worker_files(requests_dir, args.expected_workers)

    worker_rows = []
    for worker_file in worker_files:
        label = worker_label_from_path(worker_file)
        rows, skipped = parse_worker_rows(worker_file)
        worker_rows.append((label, rows, skipped))

    points, skip_summary = build_plot_points(worker_rows, success_only=args.success_only)
    for worker_label, skipped_count in skip_summary:
        print(f"WARNING: skipped {skipped_count} malformed rows in worker_{worker_label}", file=sys.stderr)

    enrich_points_with_stream_metadata(
        points,
        trial_dir=trial_dir,
        include_retransmissions=args.include_retransmissions,
    )

    print_trial_percentiles(points)

    output_html = str(Path(args.output_html).resolve()) if args.output_html else None
    render_scatter(
        points,
        output_html,
        histogram_time_source="start" if args.histogram_start_time else "end",
        scatter_y_source="stream_span" if args.y_stream_span else "duration",
    )


if __name__ == "__main__":
    main()