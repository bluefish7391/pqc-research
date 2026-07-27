"""Trial discovery, per-trial processing, and metric merging."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable

from .models import Config, RequestRow, TrialArtifacts, TrialContext
from .pcap import RouterTsharkSession, count_packets_per_request
from .requests_processing import filter_and_normalize_requests, load_requests
from .resources import align_resource_series, load_resource_samples

LOGGER = logging.getLogger("clean_collection")

REQUESTS_PATTERN = "results_*_requests.csv"
LOCUST_PATTERN = "locust_cpu_matrix_*.csv"
NGINX_PATTERN = "nginx_cpu_matrix_*.csv"
TSHARK_LOG_PATTERN = "tshark_*.log"


def find_single_file(trial_dir: Path, pattern: str) -> Path | None:
    """Return a deterministic file match for a trial artifact pattern."""
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


def _validate_trial_artifacts(
    cfg: Config,
    trial: str,
    requests_csv: Path | None,
    locust_csv: Path | None,
    nginx_csv: Path | None,
    pcap: Path | None,
) -> None:
    """Apply strict-mode checks and warnings for missing per-trial inputs."""
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


def _build_base_metrics(requests: list[RequestRow]) -> list[dict[str, float | int | None]]:
    """Convert normalized request rows into core request metrics."""
    return [
        {
            "timestamp_ns": int(req.timestamp_ns),
            "response_time_ms": req.response_time_ms,
            "response_length": req.response_length,
            "success": req.success,
        }
        for req in requests
    ]


def _merge_resource_gap_fields(
    nginx_rows: list[dict[str, float | None]],
    locust_rows: list[dict[str, float | None]],
) -> None:
    """Unify resource gap into one field by retaining the largest observed gap."""
    for nrow, lrow in zip(nginx_rows, locust_rows):
        # Keep the worse (larger) observed resource gap across both sources.
        gaps = [value for value in (lrow.get("resource_gap_ns"), nrow.get("resource_gap_ns")) if value is not None]
        nrow["resource_gap_ns"] = max(gaps) if gaps else None


def discover_manifest(cfg: Config) -> list[TrialArtifacts]:
    """Build per-trial artifact references and enforce strict-mode requirements."""
    if not cfg.results_dir.exists():
        raise FileNotFoundError(f"Missing required results directory: {cfg.results_dir}")

    trial_dirs = sorted(p for p in cfg.results_dir.iterdir() if p.is_dir())
    manifest: list[TrialArtifacts] = []

    for trial_dir in trial_dirs:
        trial = trial_dir.name
        # Artifact discovery is pattern-based because timestamps vary by run.
        requests_csv = find_single_file(trial_dir, REQUESTS_PATTERN)
        locust_csv = find_single_file(trial_dir, LOCUST_PATTERN)
        nginx_csv = find_single_file(trial_dir, NGINX_PATTERN)
        tshark_log = find_single_file(trial_dir, TSHARK_LOG_PATTERN)
        pcap = cfg.pcap_dir / f"{trial}.pcap"
        if not pcap.exists():
            pcap = None

        _validate_trial_artifacts(
            cfg,
            trial,
            requests_csv,
            locust_csv,
            nginx_csv,
            pcap,
        )

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
    """Merge N row-aligned metric lists into a single row list."""
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
    """Load, normalize, and merge all metrics for one trial."""
    if art.requests_csv is None:
        if cfg.strict:
            raise FileNotFoundError(f"Trial '{art.trial}' missing requests CSV")
        LOGGER.warning("Skipping trial '%s': requests CSV missing.", art.trial)
        return TrialContext(trial=art.trial, rows=[], empty_after_warmup=True)

    request_rows = load_requests(art.requests_csv)
    requests, baseline_ns, empty_after_warmup, post_warmup_warning = filter_and_normalize_requests(
        request_rows, cfg.warmup_ns, art.trial, stats
    )

    if empty_after_warmup:
        return TrialContext(trial=art.trial, rows=[], empty_after_warmup=True)

    # Build the request-derived metrics first; all other metrics align to these rows.
    base_metrics = _build_base_metrics(requests)

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

    _merge_resource_gap_fields(nginx_aligned, locust_aligned)

    if cfg.pcap_method == "http-events":
        LOGGER.warning("pcap-method 'http-events' not implemented; falling back to 'tcp-window'.")

    # Packet counts are computed per request window from pcap traffic.
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
    return TrialContext(
        trial=art.trial,
        rows=merged_rows,
        empty_after_warmup=False,
        post_warmup_warning=post_warmup_warning,
    )
