"""CLI parsing and config construction."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from .models import Config


def parse_args() -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent.parent
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


def build_config(args: argparse.Namespace) -> Config:
    collection_path = resolve_collection_path(args.collection, args.data_root)
    project_dir = Path(__file__).resolve().parent.parent
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
