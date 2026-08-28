#!/usr/bin/env python3
"""
compute_cell_cv.py

For a directory produced by reorg_by_cell.py (cell-first layout, one
pcap_stream_metrics.csv per repetition), compute the coefficient of variation
(CV = stddev/mean) of P50/P95/P99 handshake latency *across repetitions*,
for each cell, and the number of repetitions recommended by a power
analysis on the worst-case CV.

Expected input layout (as produced by reorg_by_cell.py):

    BY_CELL_DIR/
      <cell_name>/
        rep_<N>/
          pcap_stream_metrics.csv
        ...
      ...

Per-(cell, rep) processing:
  1. Load pcap_stream_metrics.csv (one row per TCP stream).
  2. Use stream_span_ms as the latency value.
  3. Determine t_start and t_end from all rows with valid packet timestamps.
  4. Keep rows where:
             - first_pkt_time/last_pkt_time/stream_span_ms are present
       - first_pkt_time >= t_start + WARMUP_SEC
       - last_pkt_time  <= t_end   - COOLDOWN_SEC
  5. Sort by first_pkt_time; if fewer than ANALYSIS_HANDSHAKE_TARGET rows
     remain, log a warning but still compute P50/P95/P99 using all eligible
     rows. If at least ANALYSIS_HANDSHAKE_TARGET rows remain, use the first
     ANALYSIS_HANDSHAKE_TARGET rows (in time order).

Then, per cell, aggregate per-rep P50/P95/P99 values across reps with at
least one eligible handshake and compute mean/CV for each percentile. The
recommended repetition count for a cell is driven by the worst (largest)
CV among its P50/P95/P99, via the same two-sample-t-test power analysis
used by the original pilot-CV script.

Cells are NOT required to have the same number of repetitions -- a
mismatch is logged as a warning, not a fatal error, since a cell-first
layout may legitimately have partial/resumed data per cell.

Usage:
    python3 compute_cell_cv.py <by_cell_dir> [--output OUTPUT_CSV]

Outputs (written as siblings of <by_cell_dir> by default):
    <by_cell_dir_name>_cv_results.csv   -- one row per cell: avg_p50_ms,
                                            avg_p95_ms, avg_p99_ms, per-trial
                                            percentile lists, their CVs, and
                                            recommended_repetitions
    <by_cell_dir_name>_cv_warnings.log  -- one line per (cell, rep) that
                                            fell short of
                                            ANALYSIS_HANDSHAKE_TARGET
                                            eligible handshakes, plus any
                                            rep-count-mismatch warnings
"""

import argparse
import csv
import importlib
import math
import ntpath
import re
import statistics
import sys
import warnings as warnings_module
from pathlib import Path

# ---- Tunable constants -----------------------------------------------------
WARMUP_SEC = 10          # seconds after trial start to discard (pcap-time)
COOLDOWN_SEC = 10        # seconds before trial end to discard (pcap-time)
ANALYSIS_HANDSHAKE_TARGET = 10_000  # handshakes used for percentile analysis
PERCENTILES = (("p50", 50.0), ("p90", 90.0), ("p95", 95.0))
REP_DIR_RE = re.compile(r"^rep_(?P<num>\d+)$")
REQUIRED_COLUMNS = {"first_pkt_time", "last_pkt_time", "stream_span_ms"}
RELATIVE_EFFECT_SIZE = 0.10  # detectable mean shift as a fraction of baseline mean
ALPHA = 0.0167
POWER = 0.90
GROUP_RATIO = 1.0
# -----------------------------------------------------------------------------


def resolve_by_cell_dir(raw_arg: str) -> Path:
    raw = raw_arg.strip()

    # Helpful message for Git Bash users: unescaped backslashes in a Windows path
    # (e.g. C:\Work\pqc-research\pilot_by_cell) can become C:Workpqc-researchpilot_by_cell.
    if re.match(r"^[A-Za-z]:[^\\/].+", raw):
        sys.exit(
            "ERROR: invalid Windows path format. In Git Bash, either use forward slashes "
            "(e.g. C:/Work/pqc-research/pilot_by_cell) or quote/escape backslashes "
            "(e.g. 'C:\\\\Work\\\\pqc-research\\\\pilot_by_cell')."
        )

    if ntpath.isabs(raw) or Path(raw).is_absolute():
        by_cell_dir = Path(raw).resolve()
    else:
        by_cell_dir = (Path.cwd() / raw).resolve()

    if not by_cell_dir.is_dir():
        sys.exit(f"ERROR: by-cell directory not found: {by_cell_dir}")
    return by_cell_dir


def visible_subdirs(path: Path):
    """Subdirectories of `path`, skipping dotfiles/dirs, sorted for stable ordering."""
    return sorted(p for p in path.iterdir() if p.is_dir() and not p.name.startswith("."))


def find_cell_reps(by_cell_dir: Path, log):
    """
    Walks BY_CELL_DIR and returns an ordered dict mapping cell_name ->
    list of (rep_number, rep_dir), for every rep_<N> directory found.

    Any subdirectory of a cell directory that does NOT match "rep_<N>" is
    skipped and reported via `log` rather than silently ignored.
    """
    cell_reps = {}
    for cell_dir in visible_subdirs(by_cell_dir):
        reps = []
        for rep_dir in visible_subdirs(cell_dir):
            match = REP_DIR_RE.fullmatch(rep_dir.name)
            if match is None:
                log(f"  WARNING: skipping unexpected directory {rep_dir} "
                    f"(does not match 'rep_<N>').")
                continue
            reps.append((int(match.group("num")), rep_dir))
        reps.sort(key=lambda pair: pair[0])
        if not reps:
            log(f"  WARNING: no rep_<N> directories found under cell {cell_dir}")
        cell_reps[cell_dir.name] = reps
    return cell_reps


def check_rep_count_consistency(cell_reps, log):
    """
    Cells are not required to have equal repetition counts (a cell-first
    layout may hold partial/resumed data per cell), but a mismatch is
    almost always worth a human's attention, so it's logged as a warning
    rather than silently accepted.
    """
    counts = {cell: len(reps) for cell, reps in cell_reps.items()}
    distinct = set(counts.values())
    if len(distinct) > 1:
        breakdown = ", ".join(f"{cell}={n}" for cell, n in counts.items())
        log(f"WARNING: cells have differing repetition counts: {breakdown}")


def parse_float(value):
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def load_rep_rows(rep_dir: Path):
    """
    Loads pcap_stream_metrics.csv for one (cell, rep) and returns a list of
    dicts with the fields needed for filtering/latency, or None if the
    file is missing entirely (treated as a failed/incomplete trial).
    """
    csv_path = rep_dir / "pcap_stream_metrics.csv"
    if not csv_path.is_file():
        return None

    rows = []
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        missing = REQUIRED_COLUMNS - set(reader.fieldnames or [])
        if missing:
            sys.exit(
                f"ERROR: {csv_path} is missing required column(s): {sorted(missing)}. "
                f"Was this file produced by combine_trial_data.py?"
            )
        for row in reader:
            rows.append(
                {
                    "first_pkt_time": parse_float(row.get("first_pkt_time")),
                    "last_pkt_time": parse_float(row.get("last_pkt_time")),
                    "stream_span_ms": parse_float(row.get("stream_span_ms")),
                }
            )
    return rows


def compute_trial_percentiles(rows, percentile_specs):
    """
    Applies the matched/success/warm-up/cooldown filtering described in the
    module docstring and returns requested percentiles in ms, or None if no
    eligible rows remain.

    Also returns a breakdown of counts for warning purposes: completed_count,
    unmatched_count, warm_count, eligible_count, and cooldown_count.
    """
    zero_counts = {
        "completed_count": 0,
        "unmatched_count": 0,
        "warm_count": 0,
        "eligible_count": 0,
        "cooldown_count": 0,
    }

    if not rows:
        return None, zero_counts

    def has_stream_data(r):
        return (
            r["first_pkt_time"] is not None
            and r["last_pkt_time"] is not None
            and r["stream_span_ms"] is not None
        )

    # Trial-boundary reference points: all rows (success + failure) that
    # actually joined to a pcap stream. Rows that never matched a stream
    # can't contribute a boundary, since they have no packet timestamps.
    boundary_rows = [r for r in rows if has_stream_data(r)]
    if not boundary_rows:
        counts = dict(zero_counts)
        counts["completed_count"] = len(rows)
        return None, counts

    t_start = min(r["first_pkt_time"] for r in boundary_rows)
    t_end = max(r["last_pkt_time"] for r in boundary_rows)
    warmup_cutoff = t_start + WARMUP_SEC
    cooldown_cutoff = t_end - COOLDOWN_SEC

    completed = rows
    completed_matched = [r for r in completed if has_stream_data(r)]
    unmatched_count = len(completed) - len(completed_matched)

    warm = [r for r in completed_matched if r["first_pkt_time"] < warmup_cutoff]
    cooldown = [r for r in completed_matched if r["last_pkt_time"] > cooldown_cutoff]
    eligible = [
        r
        for r in completed_matched
        if r["first_pkt_time"] >= warmup_cutoff and r["last_pkt_time"] <= cooldown_cutoff
    ]
    eligible.sort(key=lambda r: r["first_pkt_time"])

    counts = {
        "completed_count": len(completed),
        "unmatched_count": unmatched_count,
        "warm_count": len(warm),
        "eligible_count": len(eligible),
        "cooldown_count": len(cooldown),
    }

    if counts["eligible_count"] == 0:
        return None, counts

    window = (
        eligible[:ANALYSIS_HANDSHAKE_TARGET]
        if counts["eligible_count"] >= ANALYSIS_HANDSHAKE_TARGET
        else eligible
    )
    latencies_ms = [r["stream_span_ms"] for r in window]

    result = {label: percentile(latencies_ms, pct) for label, pct in percentile_specs}
    return result, counts


def percentile(values, pct):
    """Nearest-rank percentile on a list assumed already relevant (order doesn't
    matter here since we sort internally)."""
    if not values:
        return None
    ordered = sorted(values)
    k = max(0, min(len(ordered) - 1, round(pct / 100 * (len(ordered) - 1))))
    return ordered[k]


def cv(values):
    """Coefficient of variation (stddev/mean). Requires n >= 2 for stddev."""
    if len(values) < 2:
        return None
    mean = statistics.mean(values)
    if mean == 0:
        return None
    return statistics.stdev(values) / mean


def repetitions_from_max_cv(max_cv):
    """Return required repetitions per group from max CV via two-sample t-test power.

    We map relative effect size to Cohen's d using d = (delta/mu) / (sigma/mu),
    i.e. d = RELATIVE_EFFECT_SIZE / CV.
    """
    if max_cv is None or max_cv <= 0:
        return None

    standardized_effect = RELATIVE_EFFECT_SIZE / max_cv
    if standardized_effect <= 0:
        return None

    try:
        stats_power = importlib.import_module("statsmodels.stats.power")
        TTestIndPower = getattr(stats_power, "TTestIndPower")
    except (ImportError, AttributeError):
        sys.exit(
            "ERROR: statsmodels is required for repetition estimation. "
            "Install it with: pip install statsmodels"
        )

    analysis = TTestIndPower()
    with warnings_module.catch_warnings():
        # For some parameter regions statsmodels can emit convergence warnings
        # and return NaN/array-like objects; we handle those safely below.
        warnings_module.simplefilter("ignore")
        n_per_group = analysis.solve_power(
            effect_size=standardized_effect,
            alpha=ALPHA,
            power=POWER,
            ratio=GROUP_RATIO,
            alternative="two-sided",
        )

    def to_scalar(value):
        try:
            return float(value)
        except (TypeError, ValueError):
            pass

        if hasattr(value, "item"):
            try:
                return float(value.item())
            except (TypeError, ValueError):
                pass

        try:
            for candidate in value:
                try:
                    return float(candidate)
                except (TypeError, ValueError):
                    continue
        except TypeError:
            return None

        return None

    n_scalar = to_scalar(n_per_group)
    if n_scalar is None or not math.isfinite(n_scalar) or n_scalar <= 0:
        return None

    return int(math.ceil(n_scalar))


def main():
    parser = argparse.ArgumentParser(description="Compute per-cell latency CV across repetitions.")
    parser.add_argument(
        "by_cell_dir",
        help=(
            "Path to a directory produced by reorg_by_cell.py (absolute or relative). "
            "On Windows/Git Bash, prefer C:/... or quote backslash paths."
        ),
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output CSV path (default: sibling of by_cell_dir, named <by_cell_dir_name>_cv_results.csv)",
    )
    args = parser.parse_args()

    by_cell_dir = resolve_by_cell_dir(args.by_cell_dir)

    results_path = (
        Path(args.output).expanduser().resolve()
        if args.output
        else by_cell_dir.parent / f"{by_cell_dir.name}_cv_results.csv"
    )
    warnings_path = results_path.with_name(f"{results_path.stem}_warnings.log")

    percentile_labels = [label for label, _ in PERCENTILES]

    log_lines = []

    def log(msg: str = "") -> None:
        print(msg)
        log_lines.append(msg)

    cell_reps = find_cell_reps(by_cell_dir, log)
    if not cell_reps:
        log(f"FATAL: no cell directories found under {by_cell_dir}. Check the path and layout.")
        sys.exit(1)

    check_rep_count_consistency(cell_reps, log)

    cell_names = sorted(cell_reps.keys())
    total_reps = sum(len(reps) for reps in cell_reps.values())
    log(f"Found {len(cell_names)} cell(s), {total_reps} repetition(s) total.")
    log("")

    # per_cell_percentiles[cell][percentile] = list of values, one per valid rep
    per_cell_percentiles = {cell: {p: [] for p in percentile_labels} for cell in cell_names}
    shortfall_warnings = []  # (cell_name, rep_label, counts)
    zero_counts = {
        "completed_count": 0,
        "unmatched_count": 0,
        "warm_count": 0,
        "eligible_count": 0,
        "cooldown_count": 0,
    }

    for cell_name in cell_names:
        for rep_number, rep_dir in cell_reps[cell_name]:
            rep_label = f"rep_{rep_number}"
            rows = load_rep_rows(rep_dir)
            if rows is None:
                shortfall_warnings.append((cell_name, rep_label, zero_counts))
                continue

            result, counts = compute_trial_percentiles(rows, PERCENTILES)

            if counts["eligible_count"] < ANALYSIS_HANDSHAKE_TARGET:
                shortfall_warnings.append((cell_name, rep_label, counts))

            if result is None:
                continue

            for p in percentile_labels:
                per_cell_percentiles[cell_name][p].append(result[p])

    # Write warnings log
    with open(warnings_path, "w") as f:
        if not shortfall_warnings:
            f.write("No (cell, rep) fell short of the eligible-handshake target.\n")
        else:
            f.write(
                f"(cell, rep) combinations falling short of ANALYSIS_HANDSHAKE_TARGET="
                f"{ANALYSIS_HANDSHAKE_TARGET} eligible streams (after warmup={WARMUP_SEC}s, "
                f"cooldown={COOLDOWN_SEC}s, valid packet timestamps):\n"
            )
            for cell_name, rep_label, counts in shortfall_warnings:
                f.write(
                    f"  {cell_name} / {rep_label}: completed={counts['completed_count']}, "
                    f"unmatched={counts['unmatched_count']}, warm_period={counts['warm_count']}, "
                    f"eligible={counts['eligible_count']}, cooldown_period={counts['cooldown_count']}\n"
                )
        if any("differing repetition" in line for line in log_lines):
            f.write("\n")
            for line in log_lines:
                if "differing repetition" in line:
                    f.write(line.lstrip() + "\n")

    # Write results CSV
    with open(results_path, "w", newline="") as f:
        writer = csv.writer(f)
        header = ["cell"]
        for p in percentile_labels:
            header += [f"avg_{p}_ms", f"{p}_values_ms", f"{p}_cv"]
        header += ["recommended_repetitions"]
        writer.writerow(header)

        for cell_name in cell_names:
            row = [cell_name]
            cell_cvs = []
            for p in percentile_labels:
                values = per_cell_percentiles[cell_name][p]
                mean_val = statistics.mean(values) if values else None
                cv_val = cv(values)
                row.append(f"{mean_val:.3f}" if mean_val is not None else "NA")
                row.append(";".join(f"{v:.3f}" for v in values) if values else "NA")
                row.append(f"{cv_val:.4f}" if cv_val is not None else "NA")
                if cv_val is not None:
                    cell_cvs.append(cv_val)

            cell_max_cv = max(cell_cvs) if cell_cvs else None
            repetitions = repetitions_from_max_cv(cell_max_cv)
            row.append(repetitions if repetitions is not None else "NA")
            writer.writerow(row)

    print(f"Wrote results to {results_path}")
    print(f"Wrote warnings to {warnings_path} ({len(shortfall_warnings)} warning(s))")


if __name__ == "__main__":
    main()