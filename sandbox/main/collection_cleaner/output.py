"""Timestamp bucketing, output assembly, and writers."""

from __future__ import annotations

import csv
import json
import math
from pathlib import Path
from statistics import median

from .constants import (
    BUCKET_LAST_METRICS,
    BUCKET_MEAN_METRICS,
    BUCKET_ONLY_TRIAL_METRICS,
    BUCKET_SUM_METRICS,
    REQUIRED_TRIAL_METRICS,
)
from .models import Config, TrialContext
from .parsing import is_numeric_value, numeric_to_csv, parse_float, parse_int


SCALE_TARGET_MAGNITUDE = 10_000_000_000
INTERMEDIATE_TRIAL_HEADER = ["timestamp_ns", *REQUIRED_TRIAL_METRICS]


def trial_intermediate_csv_path(intermediate_dir: Path, trial: str) -> Path:
    """Return deterministic path for one trial intermediate CSV."""
    return intermediate_dir / f"{trial}.trimmed.csv"


def write_trial_intermediate_csvs(
    trial_contexts: list[TrialContext],
    intermediate_dir: Path,
    overwrite: bool,
) -> list[Path]:
    """Persist one pre-bucketing trimmed CSV per trial."""
    intermediate_dir.mkdir(parents=True, exist_ok=True)
    written_paths: list[Path] = []

    for ctx in sorted(trial_contexts, key=lambda item: item.trial):
        path = trial_intermediate_csv_path(intermediate_dir, ctx.trial)
        if path.exists() and not overwrite:
            raise FileExistsError(
                f"Intermediate file already exists: {path}. Use --overwrite to replace it."
            )

        sorted_rows = sorted(ctx.rows, key=lambda row: int(row["timestamp_ns"]))
        write_csv(path, INTERMEDIATE_TRIAL_HEADER, sorted_rows)
        written_paths.append(path)

    return written_paths


def _parse_intermediate_row(row: dict[str, str], trial: str) -> dict[str, float | int | None]:
    """Parse one intermediate row with required schema validation."""
    timestamp_ns = parse_int(row.get("timestamp_ns"))
    if timestamp_ns is None:
        raise ValueError(f"Invalid timestamp_ns in intermediate CSV for trial '{trial}': {row!r}")

    parsed: dict[str, float | int | None] = {"timestamp_ns": int(timestamp_ns)}
    for metric in REQUIRED_TRIAL_METRICS:
        parsed[metric] = parse_float(row.get(metric))
    return parsed


def load_trial_intermediate_csvs(intermediate_dir: Path) -> list[TrialContext]:
    """Load all saved per-trial intermediate CSVs for master assembly."""
    trial_paths = sorted(intermediate_dir.glob("*.trimmed.csv"))
    if not trial_paths:
        raise FileNotFoundError(f"No intermediate trial CSVs found in {intermediate_dir}")

    loaded_contexts: list[TrialContext] = []
    for path in trial_paths:
        trial = path.name[: -len(".trimmed.csv")]
        with path.open("r", newline="") as f:
            reader = csv.DictReader(f)
            header = reader.fieldnames or []
            if header != INTERMEDIATE_TRIAL_HEADER:
                raise ValueError(
                    f"Unexpected intermediate CSV header for trial '{trial}' at {path}: {header}"
                )
            rows = [_parse_intermediate_row(row, trial) for row in reader]

        loaded_contexts.append(
            TrialContext(
                trial=trial,
                rows=rows,
                empty_after_warmup=len(rows) == 0,
            )
        )

    return loaded_contexts


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
    """Aggregate per-request rows into deterministic fixed-width time buckets."""
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
    """Apply optional per-trial timestamp bucketing and track row collapse stats."""
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


def prefix_trial_columns(trial: str, row: dict[str, float | int | None]) -> dict[str, float | int | None]:
    """Namespace one trial's metric columns so cross-trial merges do not collide."""
    prefixed: dict[str, float | int | None] = {"timestamp_ns": row["timestamp_ns"]}
    for key, value in row.items():
        if key == "timestamp_ns":
            continue
        prefixed[f"{trial}__{key}"] = value
    return prefixed


def build_output_rows(
    trial_contexts: list[TrialContext],
    timestamp_bucket_ms: int | None,
) -> tuple[list[str], list[dict[str, float | int | None]]]:
    """Outer-join all trial rows by timestamp and build deterministic column order."""
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


def _metric_suffix(column_name: str) -> str:
    if "__" not in column_name:
        return column_name
    return column_name.split("__", 1)[1]


def derive_metric_scale_exponents(
    rows: list[dict[str, float | int | None]],
    header: list[str],
    target_magnitude: int = SCALE_TARGET_MAGNITUDE,
) -> dict[str, int]:
    """Choose per-metric powers of 10 so values land near a target magnitude."""
    suffix_values: dict[str, list[float]] = {}

    for col in header:
        if col != "timestamp_ns":
            suffix_values.setdefault(_metric_suffix(col), [])

    for row in rows:
        for col in header:
            if col == "timestamp_ns":
                continue
            value = row.get(col)
            if not is_numeric_value(value) or value is None:
                continue
            numeric_value = float(value)
            if numeric_value == 0.0:
                continue
            suffix_values.setdefault(_metric_suffix(col), []).append(abs(numeric_value))

    scale_exponents: dict[str, int] = {}
    for suffix, values in suffix_values.items():
        if not values:
            scale_exponents[suffix] = 0
            continue
        representative = median(values)
        if representative <= 0:
            scale_exponents[suffix] = 0
            continue
        exponent = int(round(math.log10(target_magnitude / representative)))
        scale_exponents[suffix] = max(0, exponent)

    return scale_exponents


def scale_output_rows(
    rows: list[dict[str, float | int | None]],
    header: list[str],
    scale_exponents: dict[str, int],
) -> list[dict[str, float | int | None]]:
    """Apply derived scaling exponents while leaving missing values untouched."""
    if not scale_exponents:
        return rows

    scaled_rows: list[dict[str, float | int | None]] = []
    for row in rows:
        scaled_row: dict[str, float | int | None] = {}
        for col in header:
            value = row.get(col)
            if col == "timestamp_ns" or value is None:
                scaled_row[col] = value
                continue

            exponent = scale_exponents.get(_metric_suffix(col), 0)
            if exponent <= 0:
                scaled_row[col] = value
            else:
                scaled_row[col] = float(value) * (10 ** exponent)
        scaled_rows.append(scaled_row)

    return scaled_rows


def assert_numeric_only_non_key_fields(
    rows: list[dict[str, float | int | None]], header: list[str]
) -> None:
    """Guardrail to ensure emitted metric cells are numeric-or-empty only."""
    for row in rows:
        for col in header:
            if col == "timestamp_ns":
                continue
            value = row.get(col)
            if not is_numeric_value(value):
                raise ValueError(f"Non-numeric value encountered in column '{col}': {value!r}")


def write_csv(path: Path, header: list[str], rows: list[dict[str, float | int | None]]) -> None:
    """Write deterministic CSV output with stable header order."""
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
    scale_exponents: dict[str, int] | None = None,
) -> Path:
    """Write a sidecar JSON report summarizing run options and key counters."""
    report_path = output_file.with_suffix(".validation.json")
    report = {
        "collection": cfg.collection_path.name,
        "output_file": str(output_file),
        "timestamp_bucket_enabled": cfg.timestamp_bucket_ms is not None,
        "timestamp_bucket_ms": cfg.timestamp_bucket_ms,
        "scale_to_billions": cfg.scale_to_billions,
        "metric_scale_exponents": scale_exponents or {},
        "trials_discovered": len(trial_contexts),
        "trials_empty_after_warmup": sum(1 for t in trial_contexts if t.empty_after_warmup),
        "stats": stats,
    }
    with report_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)
    return report_path
