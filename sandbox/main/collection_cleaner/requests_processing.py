"""Request CSV loading and warm-up normalization."""

from __future__ import annotations

import csv
import logging
from pathlib import Path

from .models import RequestRow
from .parsing import parse_float, parse_int, parse_success

LOGGER = logging.getLogger("clean_collection")


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
