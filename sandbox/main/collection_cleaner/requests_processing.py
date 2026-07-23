"""Request CSV loading and warm-up normalization."""

from __future__ import annotations

import csv
import logging
from pathlib import Path

from .constants import POST_WARMUP_HANDSHAKE_LIMIT
from .models import PostWarmupHandshakeWarning, RequestRow
from .parsing import parse_float, parse_int, parse_success

LOGGER = logging.getLogger("clean_collection")


def load_requests(path: Path) -> list[dict[str, str]]:
    """Load raw request rows exactly as emitted by Locust results files."""
    with path.open("r", newline="") as f:
        reader = csv.DictReader(f)
        return list(reader)


def _parse_start_times(rows: list[dict[str, str]]) -> list[int]:
    """Extract parseable start timestamps used to anchor warm-up filtering."""
    return [start for start in (parse_int(r.get("start_time_ns")) for r in rows) if start is not None]


def _apply_warmup_filter(
    rows: list[dict[str, str]],
    warmup_cutoff_ns: int,
    stats: dict[str, int],
) -> list[tuple[dict[str, str], int]]:
    """Drop rows before warm-up cutoff while accounting for parse failures."""
    filtered_raw: list[tuple[dict[str, str], int]] = []
    for row in rows:
        start = parse_int(row.get("start_time_ns"))
        if start is None:
            stats["request_rows_parse_dropped"] += 1
            continue
        if start >= warmup_cutoff_ns:
            filtered_raw.append((row, start))
    return filtered_raw


def _apply_post_warmup_limit(
    filtered_raw: list[tuple[dict[str, str], int]],
    trial: str,
    stats: dict[str, int],
) -> tuple[list[tuple[dict[str, str], int]], PostWarmupHandshakeWarning | None]:
    """Keep only the earliest post-warmup handshake window for consistent horizons."""
    if len(filtered_raw) < POST_WARMUP_HANDSHAKE_LIMIT:
        return (
            filtered_raw,
            PostWarmupHandshakeWarning(
                trial=trial,
                observed_post_warmup_handshakes=len(filtered_raw),
                required_post_warmup_handshakes=POST_WARMUP_HANDSHAKE_LIMIT,
            ),
        )

    sorted_starts = sorted(start for _, start in filtered_raw)
    handshake_cutoff_ns = sorted_starts[POST_WARMUP_HANDSHAKE_LIMIT - 1]
    limited_raw = [(row, start) for row, start in filtered_raw if start <= handshake_cutoff_ns]
    stats["rows_removed_post_warmup_handshake_limit"] += max(0, len(filtered_raw) - len(limited_raw))
    return (limited_raw, None)


def _normalize_rows(
    filtered_raw: list[tuple[dict[str, str], int]],
    baseline_ns: int,
) -> list[RequestRow]:
    """Map CSV records into typed rows with trial-relative timestamps."""
    normalized: list[RequestRow] = []
    for row, start in filtered_raw:
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
    return normalized


def _dedupe_by_timestamp(
    normalized: list[RequestRow],
    stats: dict[str, int],
) -> list[RequestRow]:
    """Collapse duplicate normalized timestamps deterministically."""
    # Deterministic duplicate collapse by timestamp after sorting.
    deduped: list[RequestRow] = []
    seen_timestamps: set[int] = set()
    for row in normalized:
        if row.timestamp_ns in seen_timestamps:
            stats["duplicate_request_timestamps_collapsed"] += 1
            continue
        seen_timestamps.add(row.timestamp_ns)
        deduped.append(row)
    return deduped


def filter_and_normalize_requests(
    rows: list[dict[str, str]], warmup_ns: int, trial: str, stats: dict[str, int]
) -> tuple[list[RequestRow], int | None, bool, PostWarmupHandshakeWarning | None]:
    """Prepare request rows for downstream alignment and packet matching."""
    starts = _parse_start_times(rows)
    if not starts:
        LOGGER.warning("Trial '%s' has no parseable start_time_ns values.", trial)
        return ([], None, True, None)

    first_request_ns = min(starts)
    warmup_cutoff_ns = first_request_ns + warmup_ns

    # Warm-up is defined relative to the first parseable request timestamp.
    filtered_raw = _apply_warmup_filter(rows, warmup_cutoff_ns, stats)

    stats["rows_removed_warmup"] += max(0, len(rows) - len(filtered_raw))

    if not filtered_raw:
        LOGGER.warning("Trial '%s' empty after warm-up filter.", trial)
        stats["trials_empty_after_warmup"] += 1
        return ([], None, True, None)

    # Enforce the post-warmup request horizon used by all downstream metrics.
    filtered_raw, post_warmup_warning = _apply_post_warmup_limit(filtered_raw, trial, stats)

    baseline_ns = min(start for _, start in filtered_raw)
    normalized = _normalize_rows(filtered_raw, baseline_ns)
    deduped = _dedupe_by_timestamp(normalized, stats)

    return (deduped, baseline_ns, False, post_warmup_warning)
