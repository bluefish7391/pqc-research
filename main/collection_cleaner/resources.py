"""Resource sample loading and timestamp alignment utilities."""

from __future__ import annotations

import csv
from bisect import bisect_left, bisect_right
from pathlib import Path

from .models import RequestRow
from .parsing import parse_int, parse_pair_to_bytes, parse_percent


SAMPLE_TIME_FIELDS = {"sample_time_ns", "rel_time_ns"}


def load_resource_samples(path: Path | None, baseline_ns: int | None, prefix: str) -> list[dict[str, float]]:
    """Load and normalize docker stats samples to trial-relative timestamps."""
    if path is None or baseline_ns is None:
        return []

    out_rows: list[dict[str, float]] = []

    with path.open("r", newline="") as f:
        reader = csv.DictReader(f)
        for rec in reader:
            ts = parse_int(rec.get("Timestamp"))
            if ts is None:
                continue
            if ts < baseline_ns:
                continue

            cpu = parse_percent(rec.get("CPU_Pct"))
            mem_used, _mem_limit = parse_pair_to_bytes(rec.get("Mem_Usage"))
            net_rx, net_tx = parse_pair_to_bytes(rec.get("Net_IO_Rx_Tx"))

            out_rows.append(
                {
                    "sample_time_ns": float(ts),
                    "rel_time_ns": float(ts - baseline_ns),
                    f"{prefix}_cpu_pct": cpu,
                    f"{prefix}_mem_used_bytes": mem_used,
                    f"{prefix}_net_rx_bytes": net_rx,
                    f"{prefix}_net_tx_bytes": net_tx,
                }
            )

    # Keep last row for duplicate timestamps by overwriting in file order.
    dedup: dict[int, dict[str, float]] = {}
    for row in out_rows:
        dedup[int(row["rel_time_ns"])] = row

    return [dedup[k] for k in sorted(dedup.keys())]


def _find_unassigned_backward(
    sample_ts: int,
    request_times: list[int],
    assigned: set[int],
) -> int | None:
    """Pick the first unassigned request at/after the sample timestamp."""
    idx = bisect_left(request_times, sample_ts)
    while idx < len(request_times) and idx in assigned:
        idx += 1
    if idx >= len(request_times):
        return None
    return idx


def _find_unassigned_forward(
    sample_ts: int,
    request_times: list[int],
    assigned: set[int],
) -> int | None:
    """Pick the first unassigned request at/before the sample timestamp."""
    idx = bisect_right(request_times, sample_ts) - 1
    while idx >= 0 and idx in assigned:
        idx -= 1
    if idx < 0:
        return None
    return idx


def _find_unassigned_nearest(
    sample_ts: int,
    request_times: list[int],
    assigned: set[int],
) -> int | None:
    """Pick the nearest unassigned request around the sample timestamp."""
    if not request_times:
        return None

    right = bisect_left(request_times, sample_ts)
    left = right - 1

    while left >= 0 or right < len(request_times):
        left_dist = None
        right_dist = None

        if left >= 0:
            left_dist = abs(sample_ts - request_times[left])
        if right < len(request_times):
            right_dist = abs(request_times[right] - sample_ts)

        choose_left = False
        if left_dist is not None and right_dist is not None:
            choose_left = left_dist <= right_dist
        elif left_dist is not None:
            choose_left = True

        if choose_left:
            if left not in assigned:
                return left
            left -= 1
        else:
            if right not in assigned:
                return right
            right += 1

    return None


def _select_request_index_for_sample(
    sample_ts: int,
    request_times: list[int],
    assigned: set[int],
    strategy: str,
) -> int | None:
    """Dispatch sample-to-request matching based on configured strategy."""
    if strategy == "backward":
        return _find_unassigned_backward(sample_ts, request_times, assigned)
    if strategy == "forward":
        return _find_unassigned_forward(sample_ts, request_times, assigned)
    if strategy in {"nearest", "interp"}:
        # In sample-once mode, "interp" falls back to nearest request row.
        return _find_unassigned_nearest(sample_ts, request_times, assigned)
    raise ValueError(f"Unsupported resource join strategy: {strategy}")


def _build_empty_aligned_rows(
    request_count: int, metric_fields: list[str]
) -> list[dict[str, float | None]]:
    """Pre-build output rows with None values for all resource metrics."""
    aligned: list[dict[str, float | None]] = []
    for _ in range(request_count):
        row: dict[str, float | None] = {"resource_gap_ns": None}
        for field in metric_fields:
            row[field] = None
        aligned.append(row)
    return aligned


def align_resource_series(
    requests: list[RequestRow],
    samples: list[dict[str, float]],
    strategy: str,
    max_gap_ns: int | None,
) -> list[dict[str, float | None]]:
    """Align resource samples onto request rows using one-sample-per-request semantics."""
    if not requests:
        return []

    if not samples:
        return [{"resource_gap_ns": None} for _ in requests]

    request_times = [int(req.timestamp_ns) for req in requests]
    sample_times = [int(row["rel_time_ns"]) for row in samples]
    metric_fields = [k for k in samples[0].keys() if k not in SAMPLE_TIME_FIELDS]

    aligned = _build_empty_aligned_rows(len(requests), metric_fields)

    assigned_request_indexes: set[int] = set()

    for sample_idx, sample_ts in enumerate(sample_times):
        # Sample-once assignment ensures each request row is populated by at most one sample.
        req_idx = _select_request_index_for_sample(
            sample_ts, request_times, assigned_request_indexes, strategy
        )
        if req_idx is None:
            continue

        # Optional staleness guard rejects assignments that are too far apart in time.
        gap = abs(request_times[req_idx] - sample_ts)
        if max_gap_ns is not None and gap > max_gap_ns:
            continue

        for field in metric_fields:
            aligned[req_idx][field] = samples[sample_idx].get(field)
        aligned[req_idx]["resource_gap_ns"] = float(gap)
        assigned_request_indexes.add(req_idx)

    return aligned
