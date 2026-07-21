"""Datamodels for collection cleaning pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


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
