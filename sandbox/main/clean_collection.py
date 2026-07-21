#!/usr/bin/env python3
"""Clean and consolidate one experiment collection into a deterministic CSV."""

from __future__ import annotations

import argparse
import csv
import json
import logging
import math
import os
import re
import shutil
import subprocess
from bisect import bisect_left, bisect_right
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


LOGGER = logging.getLogger("clean_collection")

CLIENT_IP = "172.21.0.10"
SERVER_IP = "172.20.0.10"

REQUIRED_TRIAL_METRICS = [
    "response_time_ms",
    "response_length",
    "success",
    "locust_cpu_pct",
    "locust_mem_used_bytes",
    "locust_mem_limit_bytes",
    "locust_net_rx_bytes",
    "locust_net_tx_bytes",
    "nginx_cpu_pct",
    "nginx_mem_used_bytes",
    "nginx_mem_limit_bytes",
    "nginx_net_rx_bytes",
    "nginx_net_tx_bytes",
    "packets_client_to_server_per_request",
    "packets_server_to_client_per_request",
    "packets_total_per_request",
    "pcap_match_quality_code",
    "resource_gap_ns",
]

BUCKET_ONLY_TRIAL_METRICS = ["requests_in_bucket"]

BUCKET_MEAN_METRICS = {"response_time_ms"}
BUCKET_SUM_METRICS = {
    "response_length",
    "success",
    "packets_client_to_server_per_request",
    "packets_server_to_client_per_request",
    "packets_total_per_request",
}
BUCKET_LAST_METRICS = {
    "locust_cpu_pct",
    "locust_mem_used_bytes",
    "locust_mem_limit_bytes",
    "locust_net_rx_bytes",
    "locust_net_tx_bytes",
    "nginx_cpu_pct",
    "nginx_mem_used_bytes",
    "nginx_mem_limit_bytes",
    "nginx_net_rx_bytes",
    "nginx_net_tx_bytes",
    "pcap_match_quality_code",
    "resource_gap_ns",
}


UNIT_FACTORS = {
    "": 1.0,
    "B": 1.0,
    "KB": 1000.0,
    "MB": 1000.0**2,
    "GB": 1000.0**3,
    "TB": 1000.0**4,
    "KIB": 1024.0,
    "MIB": 1024.0**2,
    "GIB": 1024.0**3,
    "TIB": 1024.0**4,
}

SUCCESS_TRUE = {"true", "1", "yes", "y", "t"}
SUCCESS_FALSE = {"false", "0", "no", "n", "f"}


@dataclass(frozen=True)
class TrialArtifacts:
    trial: str
    trial_dir: Path
    requests_csv: Path | None
    locust_csv: Path | None
    nginx_csv: Path | None
    tshark_log: Path | None
    pcap: Path | None


@dataclass
class TrialContext:
    trial: str
    rows: list[dict[str, float | int | None]]
    empty_after_warmup: bool


@dataclass
class RequestRow:
    request_id: str
    start_time_ns: int
    timestamp_ns: int
    response_time_ms: float | None
    response_length: float | None
    success: float | None


@dataclass
class Config:
    collection_path: Path
    project_dir: Path
    results_dir: Path
    pcap_dir: Path
    output_file: Path
    warmup_ns: int
    resource_join: str
    resource_max_gap_ns: int | None
    pcap_method: str
    exclude_retransmissions: bool
    strict: bool
    overwrite: bool
    fallback_window_ns: int
    emit_validation_report: bool
    timestamp_bucket_ms: int | None


class RouterTsharkSession:
    def __init__(self, project_dir: Path, pcap_dir: Path):
        self.project_dir = project_dir
        self.pcap_dir = pcap_dir.resolve()
        self.started = False
        self.force_container_tshark = False

    def _compose_env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["PCAP_DIR"] = str(self.pcap_dir)
        return env

    def _run(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            args,
            cwd=self.project_dir,
            env=self._compose_env(),
            capture_output=True,
            text=True,
            check=False,
        )

    def ensure_started(self) -> None:
        if self.started:
            return

        up_cmd = [
            "docker",
            "compose",
            "up",
            "-d",
            "--force-recreate",
            "--no-deps",
            "router",
        ]
        proc = self._run(up_cmd)
        if proc.returncode != 0:
            raise RuntimeError(
                "Failed to start router container for pcap parsing: "
                f"{proc.stderr.strip() or proc.stdout.strip()}"
            )
        self.started = True

    def extract_packets(self, pcap_path: Path) -> tuple[list[dict[str, Any]] | None, int | None]:
        self.ensure_started()

        container_pcap = f"/mnt/pcaps/{pcap_path.name}"
        cmd = [
            "docker",
            "compose",
            "exec",
            "-T",
            "router",
            "tshark",
            "-r",
            container_pcap,
            "-T",
            "fields",
            "-e",
            "frame.time_epoch",
            "-e",
            "tcp.stream",
            "-e",
            "ip.src",
            "-e",
            "tcp.srcport",
            "-e",
            "ip.dst",
            "-e",
            "tcp.dstport",
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
        ]

        proc = self._run(cmd)
        if proc.returncode != 0:
            LOGGER.warning(
                "router-container tshark parse failed for '%s': %s",
                pcap_path,
                proc.stderr.strip() or proc.stdout.strip(),
            )
            return (None, 5)

        return (parse_tshark_csv(proc.stdout), None)

    def teardown(self) -> None:
        if not self.started:
            return

        stop_proc = self._run(["docker", "compose", "stop", "router"])
        if stop_proc.returncode != 0:
            LOGGER.warning(
                "Failed stopping router container after pcap parsing: %s",
                stop_proc.stderr.strip() or stop_proc.stdout.strip(),
            )

        rm_proc = self._run(["docker", "compose", "rm", "-f", "router"])
        if rm_proc.returncode != 0:
            LOGGER.warning(
                "Failed removing router container after pcap parsing: %s",
                rm_proc.stderr.strip() or rm_proc.stdout.strip(),
            )


def parse_tshark_csv(stdout: str) -> list[dict[str, Any]]:
    packets: list[dict[str, Any]] = []
    reader = csv.reader(stdout.splitlines())
    for row in reader:
        if len(row) < 9:
            continue

        try:
            epoch = float(row[0])
            stream = int(row[1])
        except (TypeError, ValueError):
            continue

        src_ip = row[2].strip()
        dst_ip = row[4].strip()
        direction = classify_direction(src_ip, dst_ip)
        retrans = any(parse_boolish_field(r) for r in row[6:9])

        packets.append(
            {
                "time_ns": int(epoch * 1_000_000_000),
                "stream": stream,
                "direction": direction,
                "retrans": retrans,
            }
        )

    packets.sort(key=lambda p: (p["time_ns"], p["stream"]))
    return packets


def is_tshark_permission_denied(stderr: str) -> bool:
    text = stderr.lower()
    return "permission" in text and "read the file" in text


def parse_args() -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="Clean one collection and emit one deterministic consolidated CSV"
    )
    parser.add_argument("collection", help="Collection path or collection directory name")
    parser.add_argument(
        "--data-root",
        default=str(script_dir / "data"),
        help="Base path used when collection is provided by name",
    )
    parser.add_argument(
        "--output-dir",
        default=str(script_dir / "cleaned-data"),
        help="Destination directory for cleaned output",
    )
    parser.add_argument(
        "--warmup-dur",
        type=float,
        default=10.0,
        help="Warm-up duration in seconds",
    )
    parser.add_argument(
        "--resource-join",
        choices=["backward", "nearest", "forward", "interp"],
        default="backward",
        help="Resource alignment strategy",
    )
    parser.add_argument(
        "--resource-max-gap-ns",
        type=int,
        default=None,
        help="Optional staleness threshold for resource matches",
    )
    parser.add_argument(
        "--pcap-method",
        choices=["tcp-window", "http-events"],
        default="tcp-window",
        help="Pcap mapping strategy",
    )
    parser.add_argument(
        "--exclude-retransmissions",
        dest="exclude_retransmissions",
        action="store_true",
        default=True,
        help="Exclude retransmitted packets (default true)",
    )
    parser.add_argument(
        "--include-retransmissions",
        dest="exclude_retransmissions",
        action="store_false",
        help="Include retransmitted packets",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail on missing required trial artifacts",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow replacing existing cleaned CSV",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging verbosity",
    )
    parser.add_argument(
        "--emit-validation-report",
        action="store_true",
        help="Write sidecar validation summary JSON",
    )
    parser.add_argument(
        "--fallback-window-ns",
        type=int,
        default=1_000_000_000,
        help="Last request window minimum when next request start is unavailable",
    )
    parser.add_argument(
        "--timestamp-bucket-ms",
        type=int,
        default=None,
        help="Optional output-only timestamp bucketing (floor to N millisecond buckets)",
    )
    return parser.parse_args()


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(asctime)s %(levelname)s %(message)s",
    )


def resolve_collection_path(collection: str, data_root: str) -> Path:
    input_path = Path(collection).expanduser()
    if input_path.exists():
        return input_path.resolve()

    candidate = Path(data_root).expanduser() / collection
    if candidate.exists():
        return candidate.resolve()

    raise FileNotFoundError(
        f"Collection '{collection}' not found as path or under data root '{data_root}'."
    )


def find_single_file(trial_dir: Path, pattern: str) -> Path | None:
    matches = sorted(trial_dir.glob(pattern))
    if not matches:
        return None
    if len(matches) > 1:
        LOGGER.warning(
            "Multiple matches for pattern '%s' in '%s'; using '%s'.",
            pattern,
            trial_dir,
            matches[0].name,
        )
    return matches[0]


def discover_manifest(cfg: Config) -> list[TrialArtifacts]:
    if not cfg.results_dir.exists():
        raise FileNotFoundError(f"Missing required results directory: {cfg.results_dir}")

    trial_dirs = sorted(p for p in cfg.results_dir.iterdir() if p.is_dir())
    manifest: list[TrialArtifacts] = []

    for trial_dir in trial_dirs:
        trial = trial_dir.name
        requests_csv = find_single_file(trial_dir, "results_*_requests.csv")
        locust_csv = find_single_file(trial_dir, "locust_cpu_matrix_*.csv")
        nginx_csv = find_single_file(trial_dir, "nginx_cpu_matrix_*.csv")
        tshark_log = find_single_file(trial_dir, "tshark_*.log")
        pcap = cfg.pcap_dir / f"{trial}.pcap"
        if not pcap.exists():
            pcap = None

        if requests_csv is None:
            msg = f"Missing request CSV for trial '{trial}'"
            if cfg.strict:
                raise FileNotFoundError(msg)
            LOGGER.warning(msg)

        if cfg.strict and locust_csv is None:
            raise FileNotFoundError(f"Missing Locust resource CSV for trial '{trial}'")

        if cfg.strict and nginx_csv is None:
            raise FileNotFoundError(f"Missing Nginx resource CSV for trial '{trial}'")

        if cfg.strict and pcap is None:
            raise FileNotFoundError(f"Missing pcap for trial '{trial}'")

        manifest.append(
            TrialArtifacts(
                trial=trial,
                trial_dir=trial_dir,
                requests_csv=requests_csv,
                locust_csv=locust_csv,
                nginx_csv=nginx_csv,
                tshark_log=tshark_log,
                pcap=pcap,
            )
        )

    return manifest


def parse_float(value: str | None) -> float | None:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        return None


def parse_int(value: str | None) -> int | None:
    fval = parse_float(value)
    if fval is None:
        return None
    return int(fval)


def parse_success(value: str | None) -> float | None:
    if value is None:
        return None
    text = value.strip().lower()
    if text in SUCCESS_TRUE:
        return 1.0
    if text in SUCCESS_FALSE:
        return 0.0
    return None


def parse_percent(value: str | None) -> float | None:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("%"):
        text = text[:-1]
    return parse_float(text)


def parse_size_scalar(token: str) -> float | None:
    token = token.strip()
    if not token:
        return None
    match = re.match(r"^([+-]?(?:\d+(?:\.\d*)?|\.\d+))\s*([A-Za-z]*)$", token)
    if not match:
        return None

    num = float(match.group(1))
    unit = match.group(2)
    if unit.lower() == "kb":
        unit_key = "KB"
    elif unit.lower() == "mb":
        unit_key = "MB"
    elif unit.lower() == "gb":
        unit_key = "GB"
    elif unit.lower() == "tb":
        unit_key = "TB"
    else:
        unit_key = unit.upper()

    factor = UNIT_FACTORS.get(unit_key)
    if factor is None:
        return None
    return num * factor


def parse_pair_to_bytes(value: str | None) -> tuple[float | None, float | None]:
    if value is None:
        return (None, None)

    parts = value.split("/")
    if len(parts) != 2:
        return (None, None)

    left = parse_size_scalar(parts[0])
    right = parse_size_scalar(parts[1])
    return (left, right)


def load_requests(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="") as f:
        reader = csv.DictReader(f)
        return list(reader)


def filter_and_normalize_requests(
    rows: list[dict[str, str]], warmup_ns: int, trial: str, stats: dict[str, int]
) -> tuple[list[RequestRow], int | None, bool]:
    starts = [parse_int(r.get("start_time_ns")) for r in rows]
    starts = [s for s in starts if s is not None]
    if not starts:
        LOGGER.warning("Trial '%s' has no parseable start_time_ns values.", trial)
        return ([], None, True)

    first_request_ns = min(starts)
    cutoff_ns = first_request_ns + warmup_ns

    filtered_raw = []
    for row in rows:
        start = parse_int(row.get("start_time_ns"))
        if start is None:
            stats["request_rows_parse_dropped"] += 1
            continue
        if start >= cutoff_ns:
            filtered_raw.append(row)

    stats["rows_removed_warmup"] += max(0, len(rows) - len(filtered_raw))

    if not filtered_raw:
        LOGGER.warning("Trial '%s' empty after warm-up filter.", trial)
        stats["trials_empty_after_warmup"] += 1
        return ([], None, True)

    baseline_ns = min(parse_int(r.get("start_time_ns")) for r in filtered_raw if r.get("start_time_ns"))
    normalized: list[RequestRow] = []

    for row in filtered_raw:
        start = parse_int(row.get("start_time_ns"))
        if start is None:
            continue
        normalized.append(
            RequestRow(
                request_id=row.get("request_id", ""),
                start_time_ns=start,
                timestamp_ns=start - baseline_ns,
                response_time_ms=parse_float(row.get("response_time_ms")),
                response_length=parse_float(row.get("response_length")),
                success=parse_success(row.get("success")),
            )
        )

    normalized.sort(key=lambda r: (r.timestamp_ns, r.request_id))

    # Deterministic duplicate collapse by timestamp after sorting.
    deduped: list[RequestRow] = []
    seen_timestamps: set[int] = set()
    for row in normalized:
        if row.timestamp_ns in seen_timestamps:
            stats["duplicate_request_timestamps_collapsed"] += 1
            continue
        seen_timestamps.add(row.timestamp_ns)
        deduped.append(row)

    return (deduped, baseline_ns, False)


def load_resource_samples(path: Path | None, baseline_ns: int | None, prefix: str) -> list[dict[str, float]]:
    if path is None or baseline_ns is None:
        return []

    out_rows: list[dict[str, float]] = []

    with path.open("r", newline="") as f:
        reader = csv.DictReader(f)
        for rec in reader:
            ts = parse_int(rec.get("Timestamp"))
            if ts is None:
                continue

            cpu = parse_percent(rec.get("CPU_Pct"))
            mem_used, mem_limit = parse_pair_to_bytes(rec.get("Mem_Usage"))
            net_rx, net_tx = parse_pair_to_bytes(rec.get("Net_IO_Rx_Tx"))

            out_rows.append(
                {
                    "sample_time_ns": float(ts),
                    "rel_time_ns": float(ts - baseline_ns),
                    f"{prefix}_cpu_pct": cpu,
                    f"{prefix}_mem_used_bytes": mem_used,
                    f"{prefix}_mem_limit_bytes": mem_limit,
                    f"{prefix}_net_rx_bytes": net_rx,
                    f"{prefix}_net_tx_bytes": net_tx,
                }
            )

    # Keep last row for duplicate timestamps by overwriting in file order.
    dedup: dict[int, dict[str, float]] = {}
    for row in out_rows:
        dedup[int(row["rel_time_ns"])] = row

    return [dedup[k] for k in sorted(dedup.keys())]


def choose_resource_index(
    req_ts: int, sample_times: list[int], strategy: str
) -> tuple[int | None, int | None, int | None]:
    if not sample_times:
        return (None, None, None)

    left_pos = bisect_right(sample_times, req_ts) - 1
    right_pos = bisect_left(sample_times, req_ts)

    left_idx = left_pos if left_pos >= 0 else None
    right_idx = right_pos if right_pos < len(sample_times) else None

    if strategy == "backward":
        return (left_idx, left_idx, None)

    if strategy == "forward":
        return (right_idx, None, right_idx)

    if strategy == "nearest":
        if left_idx is None:
            return (right_idx, None, right_idx)
        if right_idx is None:
            return (left_idx, left_idx, None)
        left_gap = abs(req_ts - sample_times[left_idx])
        right_gap = abs(sample_times[right_idx] - req_ts)
        if left_gap <= right_gap:
            return (left_idx, left_idx, right_idx)
        return (right_idx, left_idx, right_idx)

    if strategy == "interp":
        if left_idx is not None and right_idx is not None:
            if sample_times[left_idx] == req_ts:
                return (left_idx, left_idx, right_idx)
            if sample_times[right_idx] == req_ts:
                return (right_idx, left_idx, right_idx)
            return (None, left_idx, right_idx)
        if left_idx is not None:
            return (left_idx, left_idx, None)
        return (right_idx, None, right_idx)

    raise ValueError(f"Unsupported resource join strategy: {strategy}")


def align_resource_series(
    requests: list[RequestRow],
    samples: list[dict[str, float]],
    strategy: str,
    max_gap_ns: int | None,
) -> list[dict[str, float | None]]:
    if not requests:
        return []

    if not samples:
        return [{"resource_gap_ns": None} for _ in requests]

    sample_times = [int(row["rel_time_ns"]) for row in samples]
    metric_fields = [k for k in samples[0].keys() if k not in {"sample_time_ns", "rel_time_ns"}]

    aligned: list[dict[str, float | None]] = []

    for req in requests:
        selected_idx, left_idx, right_idx = choose_resource_index(
            req.timestamp_ns, sample_times, strategy
        )

        result: dict[str, float | None] = {"resource_gap_ns": None}
        for field in metric_fields:
            result[field] = None

        if selected_idx is not None:
            sample_ts = sample_times[selected_idx]
            gap = abs(req.timestamp_ns - sample_ts)
            if max_gap_ns is None or gap <= max_gap_ns:
                for field in metric_fields:
                    result[field] = samples[selected_idx].get(field)
                result["resource_gap_ns"] = float(gap)
            aligned.append(result)
            continue

        if strategy == "interp" and left_idx is not None and right_idx is not None:
            left_ts = sample_times[left_idx]
            right_ts = sample_times[right_idx]
            denom = right_ts - left_ts
            if denom == 0:
                aligned.append(result)
                continue

            alpha = (req.timestamp_ns - left_ts) / denom
            gap = min(abs(req.timestamp_ns - left_ts), abs(right_ts - req.timestamp_ns))
            if max_gap_ns is not None and gap > max_gap_ns:
                aligned.append(result)
                continue

            for field in metric_fields:
                left_val = samples[left_idx].get(field)
                right_val = samples[right_idx].get(field)
                if left_val is None or right_val is None:
                    result[field] = None
                else:
                    result[field] = float(left_val) + alpha * (float(right_val) - float(left_val))
            result["resource_gap_ns"] = float(gap)

        aligned.append(result)

    return aligned


def classify_direction(src_ip: str, dst_ip: str) -> str | None:
    if src_ip == CLIENT_IP and dst_ip == SERVER_IP:
        return "c2s"
    if src_ip == SERVER_IP and dst_ip == CLIENT_IP:
        return "s2c"
    return None


def parse_boolish_field(value: str) -> bool:
    text = value.strip().lower()
    return text not in {"", "0", "false", "f", "no", "n"}


def build_request_windows(
    requests: list[RequestRow], fallback_window_ns: int
) -> list[tuple[int, int]]:
    windows: list[tuple[int, int]] = []
    for idx, row in enumerate(requests):
        start = row.timestamp_ns
        if idx < len(requests) - 1:
            end = requests[idx + 1].timestamp_ns
        else:
            resp_ns = int(row.response_time_ms * 1_000_000) if row.response_time_ms is not None else 0
            end = start + max(resp_ns, fallback_window_ns)
        if end <= start:
            end = start + fallback_window_ns
        windows.append((start, end))
    return windows


def run_tshark_extract(
    pcap_path: Path,
    router_session: RouterTsharkSession | None,
    stats: dict[str, int],
) -> tuple[list[dict[str, Any]] | None, int | None]:
    if router_session is not None and router_session.force_container_tshark:
        stats["pcap_router_tshark_fallbacks"] += 1
        return router_session.extract_packets(pcap_path)

    tshark_bin = shutil.which("tshark")
    if not tshark_bin:
        if router_session is not None:
            stats["pcap_router_tshark_fallbacks"] += 1
            return router_session.extract_packets(pcap_path)
        return (None, 5)

    cmd = [
        tshark_bin,
        "-r",
        str(pcap_path),
        "-T",
        "fields",
        "-e",
        "frame.time_epoch",
        "-e",
        "tcp.stream",
        "-e",
        "ip.src",
        "-e",
        "tcp.srcport",
        "-e",
        "ip.dst",
        "-e",
        "tcp.dstport",
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
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except OSError:
        if router_session is not None:
            stats["pcap_router_tshark_fallbacks"] += 1
            return router_session.extract_packets(pcap_path)
        return (None, 5)

    if proc.returncode != 0:
        if router_session is not None and is_tshark_permission_denied(proc.stderr):
            router_session.force_container_tshark = True
            LOGGER.warning(
                "Host tshark cannot read workspace pcap files; using router container for remaining pcap parsing in this run. First failing file: '%s'.",
                pcap_path,
            )
            stats["pcap_router_tshark_fallbacks"] += 1
            return router_session.extract_packets(pcap_path)
        LOGGER.warning("tshark parse failed for '%s': %s", pcap_path, proc.stderr.strip())
        return (None, 5)

    return (parse_tshark_csv(proc.stdout), None)


def packet_nan_rows(requests: list[RequestRow], code: int) -> list[dict[str, float | None]]:
    return [
        {
            "packets_client_to_server_per_request": None,
            "packets_server_to_client_per_request": None,
            "packets_total_per_request": None,
            "pcap_match_quality_code": float(code),
        }
        for _ in requests
    ]


def count_packets_per_request(
    requests: list[RequestRow],
    pcap_path: Path | None,
    baseline_ns: int | None,
    exclude_retransmissions: bool,
    fallback_window_ns: int,
    stats: dict[str, int],
    router_session: RouterTsharkSession | None,
) -> list[dict[str, float | None]]:
    if not requests:
        return []

    if pcap_path is None or not pcap_path.exists() or not pcap_path.is_file():
        stats["trials_missing_or_unreadable_pcap"] += 1
        return packet_nan_rows(requests, 4)

    if baseline_ns is None:
        return packet_nan_rows(requests, 4)

    packets_abs, error_code = run_tshark_extract(pcap_path, router_session, stats)
    if packets_abs is None:
        stats["trials_pcap_parse_error"] += 1
        return packet_nan_rows(requests, error_code if error_code is not None else 5)

    packets_rel: list[dict[str, Any]] = []
    for p in packets_abs:
        if exclude_retransmissions and p["retrans"]:
            continue
        rel_ns = int(p["time_ns"] - baseline_ns)
        packets_rel.append(
            {
                "rel_time_ns": rel_ns,
                "stream": int(p["stream"]),
                "direction": p["direction"],
            }
        )

    packets_rel.sort(key=lambda p: (p["rel_time_ns"], p["stream"]))
    packet_times = [int(p["rel_time_ns"]) for p in packets_rel]
    windows = build_request_windows(requests, fallback_window_ns)

    out_rows: list[dict[str, float | None]] = []

    for idx, req in enumerate(requests):
        win_start, win_end = windows[idx]
        start_idx = bisect_left(packet_times, win_start)
        end_idx = bisect_left(packet_times, win_end)
        candidates = packets_rel[start_idx:end_idx]

        if not candidates:
            out_rows.append(
                {
                    "packets_client_to_server_per_request": None,
                    "packets_server_to_client_per_request": None,
                    "packets_total_per_request": None,
                    "pcap_match_quality_code": 3.0,
                }
            )
            continue

        by_stream: dict[int, dict[str, int]] = {}
        for p in candidates:
            stream = p["stream"]
            if stream not in by_stream:
                by_stream[stream] = {"c2s": 0, "s2c": 0, "other": 0}
            direction = p["direction"]
            if direction == "c2s":
                by_stream[stream]["c2s"] += 1
            elif direction == "s2c":
                by_stream[stream]["s2c"] += 1
            else:
                by_stream[stream]["other"] += 1

        if not by_stream:
            out_rows.append(
                {
                    "packets_client_to_server_per_request": None,
                    "packets_server_to_client_per_request": None,
                    "packets_total_per_request": None,
                    "pcap_match_quality_code": 3.0,
                }
            )
            continue

        streams = sorted(by_stream.keys())
        quality = 0.0
        selected_stream = streams[0]

        if len(streams) == 1:
            quality = 0.0
        else:
            ranked = sorted(
                streams,
                key=lambda s: (
                    -by_stream[s]["c2s"],
                    -by_stream[s]["s2c"],
                    s,
                ),
            )
            selected_stream = ranked[0]
            top_c2s = by_stream[ranked[0]]["c2s"]
            tie_count = sum(1 for s in ranked if by_stream[s]["c2s"] == top_c2s)
            if tie_count > 1:
                quality = 2.0
                stats["pcap_ambiguous_stream_matches"] += 1
            else:
                quality = 1.0
                stats["pcap_heuristic_stream_matches"] += 1

        c2s = by_stream[selected_stream]["c2s"]
        s2c = by_stream[selected_stream]["s2c"]
        out_rows.append(
            {
                "packets_client_to_server_per_request": float(c2s),
                "packets_server_to_client_per_request": float(s2c),
                "packets_total_per_request": float(c2s + s2c),
                "pcap_match_quality_code": quality,
            }
        )

    return out_rows


def merge_metric_rows(*metric_sets: Iterable[dict[str, float | int | None]]) -> list[dict[str, float | int | None]]:
    row_lists = [list(m) for m in metric_sets]
    if not row_lists:
        return []

    count = len(row_lists[0])
    for rows in row_lists[1:]:
        if len(rows) != count:
            raise ValueError("Mismatched row counts while merging trial metrics")

    merged: list[dict[str, float | int | None]] = []
    for i in range(count):
        row: dict[str, float | int | None] = {}
        for rows in row_lists:
            row.update(rows[i])
        merged.append(row)

    return merged


def _mean_non_missing(values: list[float | int | None]) -> float | None:
    nums = [float(v) for v in values if v is not None]
    if not nums:
        return None
    return sum(nums) / len(nums)


def _sum_non_missing(values: list[float | int | None]) -> float | None:
    nums = [float(v) for v in values if v is not None]
    if not nums:
        return None
    return sum(nums)


def _last_non_missing(values: list[float | int | None]) -> float | None:
    for val in reversed(values):
        if val is not None:
            return float(val)
    return None


def bucket_trial_rows(
    rows: list[dict[str, float | int | None]],
    timestamp_bucket_ms: int,
) -> list[dict[str, float | int | None]]:
    if not rows:
        return []

    bucket_ns = timestamp_bucket_ms * 1_000_000
    rows_sorted = sorted(rows, key=lambda r: int(r["timestamp_ns"]))

    grouped: dict[int, list[dict[str, float | int | None]]] = {}
    for row in rows_sorted:
        ts = int(row["timestamp_ns"])
        bucket_ts = (ts // bucket_ns) * bucket_ns
        grouped.setdefault(bucket_ts, []).append(row)

    aggregated_rows: list[dict[str, float | int | None]] = []
    for bucket_ts in sorted(grouped.keys()):
        bucket_rows = grouped[bucket_ts]
        out_row: dict[str, float | int | None] = {"timestamp_ns": bucket_ts}

        for metric in REQUIRED_TRIAL_METRICS:
            vals = [r.get(metric) for r in bucket_rows]
            if metric in BUCKET_MEAN_METRICS:
                out_row[metric] = _mean_non_missing(vals)
            elif metric in BUCKET_SUM_METRICS:
                out_row[metric] = _sum_non_missing(vals)
            elif metric in BUCKET_LAST_METRICS:
                out_row[metric] = _last_non_missing(vals)
            else:
                # Default to deterministic last non-missing if a new metric appears.
                out_row[metric] = _last_non_missing(vals)

        out_row["requests_in_bucket"] = float(len(bucket_rows))
        aggregated_rows.append(out_row)

    return aggregated_rows


def maybe_bucket_trial_contexts(
    trial_contexts: list[TrialContext],
    timestamp_bucket_ms: int | None,
    stats: dict[str, int],
) -> list[TrialContext]:
    if timestamp_bucket_ms is None:
        return trial_contexts

    bucketed_contexts: list[TrialContext] = []
    for ctx in trial_contexts:
        original_len = len(ctx.rows)
        bucketed_rows = bucket_trial_rows(ctx.rows, timestamp_bucket_ms)
        stats["bucket_rows_collapsed"] += max(0, original_len - len(bucketed_rows))
        bucketed_contexts.append(
            TrialContext(
                trial=ctx.trial,
                rows=bucketed_rows,
                empty_after_warmup=ctx.empty_after_warmup,
            )
        )

    return bucketed_contexts


def process_trial(
    art: TrialArtifacts,
    cfg: Config,
    stats: dict[str, int],
    router_session: RouterTsharkSession | None,
) -> TrialContext:
    if art.requests_csv is None:
        if cfg.strict:
            raise FileNotFoundError(f"Trial '{art.trial}' missing requests CSV")
        LOGGER.warning("Skipping trial '%s': requests CSV missing.", art.trial)
        return TrialContext(trial=art.trial, rows=[], empty_after_warmup=True)

    request_rows = load_requests(art.requests_csv)
    requests, baseline_ns, empty_after_warmup = filter_and_normalize_requests(
        request_rows, cfg.warmup_ns, art.trial, stats
    )

    if empty_after_warmup:
        return TrialContext(trial=art.trial, rows=[], empty_after_warmup=True)

    base_metrics: list[dict[str, float | int | None]] = []
    for req in requests:
        base_metrics.append(
            {
                "timestamp_ns": int(req.timestamp_ns),
                "response_time_ms": req.response_time_ms,
                "response_length": req.response_length,
                "success": req.success,
            }
        )

    locust_samples = load_resource_samples(art.locust_csv, baseline_ns, "locust")
    nginx_samples = load_resource_samples(art.nginx_csv, baseline_ns, "nginx")

    if not locust_samples:
        LOGGER.warning("No Locust resource samples for trial '%s'.", art.trial)
    if not nginx_samples:
        LOGGER.warning("No Nginx resource samples for trial '%s'.", art.trial)

    locust_aligned = align_resource_series(
        requests, locust_samples, cfg.resource_join, cfg.resource_max_gap_ns
    )
    nginx_aligned = align_resource_series(
        requests, nginx_samples, cfg.resource_join, cfg.resource_max_gap_ns
    )

    for nrow, lrow in zip(nginx_aligned, locust_aligned):
        # Keep the worse (larger) observed resource gap across the two sources.
        gap_values = [v for v in (lrow.get("resource_gap_ns"), nrow.get("resource_gap_ns")) if v is not None]
        nrow["resource_gap_ns"] = max(gap_values) if gap_values else None

    if cfg.pcap_method == "http-events":
        LOGGER.warning("pcap-method 'http-events' not implemented; falling back to 'tcp-window'.")

    pcap_rows = count_packets_per_request(
        requests,
        art.pcap,
        baseline_ns,
        cfg.exclude_retransmissions,
        cfg.fallback_window_ns,
        stats,
        router_session,
    )

    merged_rows = merge_metric_rows(base_metrics, locust_aligned, nginx_aligned, pcap_rows)
    return TrialContext(trial=art.trial, rows=merged_rows, empty_after_warmup=False)


def prefix_trial_columns(trial: str, row: dict[str, float | int | None]) -> dict[str, float | int | None]:
    prefixed: dict[str, float | int | None] = {"timestamp_ns": row["timestamp_ns"]}
    for key, value in row.items():
        if key == "timestamp_ns":
            continue
        prefixed[f"{trial}__{key}"] = value
    return prefixed


def is_numeric_value(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, bool):
        return False
    return isinstance(value, (int, float))


def numeric_to_csv(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and math.isnan(value):
        return ""
    if isinstance(value, bool):
        return ""
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        # Deterministic compact float representation.
        return f"{value:.12g}"
    return ""


def build_output_rows(
    trial_contexts: list[TrialContext],
    timestamp_bucket_ms: int | None,
) -> tuple[list[str], list[dict[str, float | int | None]]]:
    # Outer-join all trial frames on timestamp_ns using dict accumulation.
    merged: dict[int, dict[str, float | int | None]] = {}

    for ctx in trial_contexts:
        for row in ctx.rows:
            prefixed = prefix_trial_columns(ctx.trial, row)
            ts = int(prefixed["timestamp_ns"])
            if ts not in merged:
                merged[ts] = {"timestamp_ns": ts}
            merged[ts].update(prefixed)

    sorted_trials = sorted(ctx.trial for ctx in trial_contexts)

    header = ["timestamp_ns"]
    trial_metrics = list(REQUIRED_TRIAL_METRICS)
    if timestamp_bucket_ms is not None:
        trial_metrics.extend(BUCKET_ONLY_TRIAL_METRICS)

    for trial in sorted_trials:
        for metric in trial_metrics:
            header.append(f"{trial}__{metric}")

    output_rows = [merged[ts] for ts in sorted(merged.keys())]

    return header, output_rows


def assert_numeric_only_non_key_fields(
    rows: list[dict[str, float | int | None]], header: list[str]
) -> None:
    for row in rows:
        for col in header:
            if col == "timestamp_ns":
                continue
            value = row.get(col)
            if not is_numeric_value(value):
                raise ValueError(f"Non-numeric value encountered in column '{col}': {value!r}")


def write_csv(path: Path, header: list[str], rows: list[dict[str, float | int | None]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        for row in rows:
            writer.writerow([numeric_to_csv(row.get(col)) for col in header])


def write_validation_report(
    output_file: Path,
    cfg: Config,
    trial_contexts: list[TrialContext],
    stats: dict[str, int],
) -> None:
    report_path = output_file.with_suffix(".validation.json")
    report = {
        "collection": cfg.collection_path.name,
        "output_file": str(output_file),
        "timestamp_bucket_enabled": cfg.timestamp_bucket_ms is not None,
        "timestamp_bucket_ms": cfg.timestamp_bucket_ms,
        "trials_discovered": len(trial_contexts),
        "trials_empty_after_warmup": sum(1 for t in trial_contexts if t.empty_after_warmup),
        "stats": stats,
    }
    with report_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)
    LOGGER.info("Validation report written: %s", report_path)


def build_config(args: argparse.Namespace) -> Config:
    collection_path = resolve_collection_path(args.collection, args.data_root)
    project_dir = Path(__file__).resolve().parent
    results_dir = collection_path / "results"
    pcap_dir = collection_path / "pcaps"
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_file = output_dir / f"cleaned_{collection_path.name}.csv"

    if output_file.exists() and not args.overwrite:
        raise FileExistsError(
            f"Output file already exists: {output_file}. Use --overwrite to replace it."
        )

    timestamp_bucket_ms: int | None = args.timestamp_bucket_ms
    if timestamp_bucket_ms is not None and timestamp_bucket_ms <= 0:
        raise ValueError("--timestamp-bucket-ms must be a positive integer when provided")

    return Config(
        collection_path=collection_path,
        project_dir=project_dir,
        results_dir=results_dir,
        pcap_dir=pcap_dir,
        output_file=output_file,
        warmup_ns=int(args.warmup_dur * 1_000_000_000),
        resource_join=args.resource_join,
        resource_max_gap_ns=args.resource_max_gap_ns,
        pcap_method=args.pcap_method,
        exclude_retransmissions=args.exclude_retransmissions,
        strict=args.strict,
        overwrite=args.overwrite,
        fallback_window_ns=args.fallback_window_ns,
        emit_validation_report=args.emit_validation_report,
        timestamp_bucket_ms=timestamp_bucket_ms,
    )


def main() -> int:
    args = parse_args()
    setup_logging(args.log_level)

    cfg = build_config(args)

    LOGGER.info("Collection: %s", cfg.collection_path.name)
    LOGGER.info("Collection path: %s", cfg.collection_path)
    LOGGER.info("Results dir: %s", cfg.results_dir)
    LOGGER.info("Pcap dir: %s", cfg.pcap_dir)
    LOGGER.info("Output file: %s", cfg.output_file)
    LOGGER.info(
        "Options: warmup_ns=%d resource_join=%s resource_max_gap_ns=%s pcap_method=%s exclude_retransmissions=%s strict=%s timestamp_bucket_ms=%s",
        cfg.warmup_ns,
        cfg.resource_join,
        cfg.resource_max_gap_ns,
        cfg.pcap_method,
        cfg.exclude_retransmissions,
        cfg.strict,
        cfg.timestamp_bucket_ms,
    )

    manifest = discover_manifest(cfg)
    if not manifest:
        raise RuntimeError(f"No trial directories found under {cfg.results_dir}")

    stats = {
        "request_rows_parse_dropped": 0,
        "rows_removed_warmup": 0,
        "trials_empty_after_warmup": 0,
        "duplicate_request_timestamps_collapsed": 0,
        "bucket_rows_collapsed": 0,
        "trials_missing_or_unreadable_pcap": 0,
        "trials_pcap_parse_error": 0,
        "pcap_router_tshark_fallbacks": 0,
        "pcap_heuristic_stream_matches": 0,
        "pcap_ambiguous_stream_matches": 0,
    }

    router_session = RouterTsharkSession(cfg.project_dir, cfg.pcap_dir)
    trial_contexts: list[TrialContext] = []
    try:
        for art in sorted(manifest, key=lambda x: x.trial):
            LOGGER.info("Processing trial: %s", art.trial)
            ctx = process_trial(art, cfg, stats, router_session)
            trial_contexts.append(ctx)
    finally:
        router_session.teardown()

    trial_contexts = maybe_bucket_trial_contexts(
        trial_contexts,
        cfg.timestamp_bucket_ms,
        stats,
    )

    header, rows = build_output_rows(trial_contexts, cfg.timestamp_bucket_ms)
    assert_numeric_only_non_key_fields(rows, header)
    write_csv(cfg.output_file, header, rows)

    LOGGER.info("Wrote consolidated CSV: %s", cfg.output_file)
    LOGGER.info("Output rows: %d", len(rows))

    if cfg.emit_validation_report:
        write_validation_report(cfg.output_file, cfg, trial_contexts, stats)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
