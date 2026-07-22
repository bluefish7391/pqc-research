"""Resource sample loading and timestamp alignment utilities."""

from __future__ import annotations

import csv
from bisect import bisect_left, bisect_right
from pathlib import Path

from .models import RequestRow
from .parsing import parse_int, parse_pair_to_bytes, parse_percent


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


def _find_unassigned_backward(
    sample_ts: int,
    request_times: list[int],
    assigned: set[int],
) -> int | None:
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
    if strategy == "backward":
        return _find_unassigned_backward(sample_ts, request_times, assigned)
    if strategy == "forward":
        return _find_unassigned_forward(sample_ts, request_times, assigned)
    if strategy in {"nearest", "interp"}:
        # In sample-once mode, "interp" falls back to nearest request row.
        return _find_unassigned_nearest(sample_ts, request_times, assigned)
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

    request_times = [int(req.timestamp_ns) for req in requests]
    sample_times = [int(row["rel_time_ns"]) for row in samples]
    metric_fields = [k for k in samples[0].keys() if k not in {"sample_time_ns", "rel_time_ns"}]

    aligned: list[dict[str, float | None]] = []
    for _req in requests:
        row: dict[str, float | None] = {"resource_gap_ns": None}
        for field in metric_fields:
            row[field] = None
        aligned.append(row)

    assigned_request_indexes: set[int] = set()

    for sample_idx, sample_ts in enumerate(sample_times):
        req_idx = _select_request_index_for_sample(
            sample_ts, request_times, assigned_request_indexes, strategy
        )
        if req_idx is None:
            continue

        gap = abs(request_times[req_idx] - sample_ts)
        if max_gap_ns is not None and gap > max_gap_ns:
            continue

        for field in metric_fields:
            aligned[req_idx][field] = samples[sample_idx].get(field)
        aligned[req_idx]["resource_gap_ns"] = float(gap)
        assigned_request_indexes.add(req_idx)

    return aligned
