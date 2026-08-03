"""Pcap parsing and packet-to-request assignment logic."""

from __future__ import annotations

import csv
import logging
import os
import shutil
import subprocess
from bisect import bisect_left
from pathlib import Path
from typing import Any

from .constants import CLIENT_IP, SERVER_IP
from .models import RequestRow
from .parsing import parse_boolish_field

LOGGER = logging.getLogger("clean_collection")

TSHARK_FIELD_ARGS = [
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


class RouterTsharkSession:
    """Manage router container lifecycle for tshark fallback parsing."""

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
        """Start router container once per run when fallback parsing is needed."""
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
        """Extract packet fields via tshark inside the router container."""
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
        ]
        cmd.extend(TSHARK_FIELD_ARGS)

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
        """Stop and remove fallback container resources created for parsing."""
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


def classify_direction(src_ip: str, dst_ip: str) -> str | None:
    """Map packet direction relative to configured client/server endpoints."""
    if src_ip == CLIENT_IP and dst_ip == SERVER_IP:
        return "c2s"
    if src_ip == SERVER_IP and dst_ip == CLIENT_IP:
        return "s2c"
    return None


def parse_tshark_csv(stdout: str) -> list[dict[str, Any]]:
    """Parse tshark CSV lines into normalized packet dictionaries."""
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
    """Detect host filesystem permission failures from tshark stderr."""
    text = stderr.lower()
    return "permission" in text and "read the file" in text


def build_request_windows(
    requests: list[RequestRow], fallback_window_ns: int
) -> list[tuple[int, int]]:
    """Build request time windows used to assign packet candidates per request."""
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
    """Run tshark on host first, with router-container fallback when necessary."""
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
    ]
    cmd.extend(TSHARK_FIELD_ARGS)

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
    """Return sentinel rows used when packet extraction cannot be completed."""
    return [
        {
            "packets_client_to_server_per_request": None,
            "packets_server_to_client_per_request": None,
            "packets_total_per_request": None,
            "pcap_match_quality_code": float(code),
        }
        for _ in requests
    ]


def _empty_packet_metrics_row() -> dict[str, float | None]:
    """Return an empty per-request packet metrics row for no-match cases."""
    return {
        "packets_client_to_server_per_request": None,
        "packets_server_to_client_per_request": None,
        "packets_total_per_request": None,
        "pcap_match_quality_code": 3.0,
    }


def count_packets_per_request(
    requests: list[RequestRow],
    pcap_path: Path | None,
    baseline_ns: int | None,
    exclude_retransmissions: bool,
    fallback_window_ns: int,
    stats: dict[str, int],
    router_session: RouterTsharkSession | None,
) -> list[dict[str, float | None]]:
    """Count request-scoped packets and emit quality-coded packet metrics rows."""
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

    for idx, _req in enumerate(requests):
        # Narrow to packets whose relative timestamp falls within this request window.
        win_start, win_end = windows[idx]
        start_idx = bisect_left(packet_times, win_start)
        end_idx = bisect_left(packet_times, win_end)
        candidates = packets_rel[start_idx:end_idx]

        if not candidates:
            out_rows.append(_empty_packet_metrics_row())
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
            out_rows.append(_empty_packet_metrics_row())
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
