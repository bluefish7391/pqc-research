"""Trial discovery, per-trial processing, and metric merging."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable

from .models import Config, TrialArtifacts, TrialContext
from .pcap import RouterTsharkSession, count_packets_per_request
from .requests_processing import filter_and_normalize_requests, load_requests
from .resources import align_resource_series, load_resource_samples

LOGGER = logging.getLogger("clean_collection")


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
