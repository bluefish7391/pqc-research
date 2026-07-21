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
