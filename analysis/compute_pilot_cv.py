#!/usr/bin/env python3
"""
compute_pilot_cv.py

For a directory produced by reorg_pilot_by_cell.py (cell-first layout with
rep_<N> directories), compute the coefficient of
variation (CV = stddev/mean) of P50/P90/P99 handshake latency *across sweeps*,
for each cell.

Per-(cell, repetition) processing:
    1. Load pcap_stream_metrics.csv from each <cell>/rep_<N>/ directory.
    2. Use stream_span_ms as the latency value.
    3. Determine t_start and t_end from all rows with valid packet timestamps.
  4. Keep rows where first_pkt_time >= t_start + WARMUP_SEC and
      last_pkt_time <= t_end - COOLDOWN_SEC.
  5. Sort by first_pkt_time; if fewer than ANALYSIS_HANDSHAKE_TARGET rows remain, log a
      warning but still compute P50/P90/P99 using all eligible rows. If at least
      ANALYSIS_HANDSHAKE_TARGET rows remain, use the first ANALYSIS_HANDSHAKE_TARGET rows (in time
      order) for percentile computation.

Then, per cell, aggregate per-repetition P50/P90/P99 values across repetitions with at
least one eligible handshake and compute mean/stddev/CV for each percentile.

Usage:
    python3 compute_pilot_cv.py <by_cell_dir>

Outputs (written into the mirror directory):
    cv_results.csv       -- one row per cell: n_valid_repetitions, eligible
                             handshakes counted per trial (semicolon-separated),
                             means, per-trial percentile values (semicolon-
                             separated), CVs, and average throughput
    warnings.log         -- one line per (repetition, cell) that fell short of
                             ANALYSIS_HANDSHAKE_TARGET eligible handshakes
"""

import argparse
import csv
import importlib
import math
import ntpath
import re
import statistics
import sys
import warnings
from pathlib import Path

# ---- Tunable constants -----------------------------------------------------
WARMUP_SEC = 10          # seconds after trial start to discard
COOLDOWN_SEC = 10        # seconds before trial end to discard
ANALYSIS_HANDSHAKE_TARGET = 10_000  # handshakes used for percentile analysis
TOTAL_HANDSHAKE_TARGET = 15_000  # handshakes actually completed by each trial
OUTPUT_PERCENTILES = ("p50", "p90", "p95")
REPETITION_PERCENTILES = ("p50", "p90", "p95")
REP_DIR_RE = re.compile(r"^rep_(?P<num>\d+)$")
PERCENTILE_NAME_RE = re.compile(r"^p(?P<value>\d+(?:\.\d+)?)$", re.IGNORECASE)
RELATIVE_EFFECT_SIZE = 0.10  # detectable mean shift as a fraction of baseline mean
ALPHA = 0.0167
POWER = 0.90
GROUP_RATIO = 1.0
# -----------------------------------------------------------------------------


def visible_subdirs(path: Path):
    return sorted(p for p in path.iterdir() if p.is_dir() and not p.name.startswith("."))


def find_cell_reps(collection_dir: Path):
    cell_reps = {}
    for cell_dir in visible_subdirs(collection_dir):
        reps = []
        for rep_dir in visible_subdirs(cell_dir):
            match = REP_DIR_RE.fullmatch(rep_dir.name)
            if match:
                reps.append((int(match.group("num")), rep_dir))
        reps.sort(key=lambda pair: pair[0])
        cell_reps[cell_dir.name] = reps
    if not cell_reps:
        sys.exit(f"ERROR: no cell directories found under {collection_dir}")
    return cell_reps


def load_stream_metrics(rep_dir: Path):
    """Load pcap stream metrics for one mirrored repetition."""
    csv_path = rep_dir / "pcap_stream_metrics.csv"
    if not csv_path.is_file():
        return None

    rows = []
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        required = {"first_pkt_time", "last_pkt_time", "stream_span_ms"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            sys.exit(f"ERROR: {csv_path} is missing required column(s): {sorted(missing)}")
        for row in reader:
            try:
                first = float(row["first_pkt_time"])
                last = float(row["last_pkt_time"])
                span = float(row["stream_span_ms"])
            except (KeyError, TypeError, ValueError):
                continue
            rows.append({"first_pkt_time": first, "last_pkt_time": last, "stream_span_ms": span})
    return rows


def compute_cell_percentiles(rows, percentile_specs):
    """Apply warm-up/cooldown/success filtering and return requested percentiles in ms,
    or None if no eligible rows remain.

    Also returns a breakdown of counts for warning purposes: completed_count,
    warm_count, eligible_count, and cooldown_count.

    Throughput is computed on the same window used for percentile metrics as:
        len(window) / (window_end_time - window_start_time)
    in handshakes per second.
    """
    if not rows:
        return None, {
            "completed_count": 0,
            "warm_count": 0,
            "eligible_count": 0,
            "cooldown_count": 0,
        }

    t_start = min(r["first_pkt_time"] for r in rows)
    t_end = max(r["last_pkt_time"] for r in rows)

    warmup_cutoff = t_start + WARMUP_SEC
    cooldown_cutoff = t_end - COOLDOWN_SEC

    completed = rows
    warm = [r for r in completed if r["first_pkt_time"] < warmup_cutoff]
    cooldown = [r for r in completed if r["last_pkt_time"] > cooldown_cutoff]
    eligible = [
        r
        for r in completed
        if r["first_pkt_time"] >= warmup_cutoff and r["last_pkt_time"] <= cooldown_cutoff
    ]
    eligible.sort(key=lambda r: r["first_pkt_time"])

    counts = {
        "completed_count": len(completed),
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
    window_start = window[0]["first_pkt_time"]
    window_end = window[-1]["last_pkt_time"]
    duration_sec = window_end - window_start
    throughput_hps = len(window) / duration_sec if duration_sec > 0 else None

    result = {label: percentile(latencies_ms, pct) for label, pct in percentile_specs}
    result["throughput_hps"] = throughput_hps
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


def parse_percentile_name(name: str, setting_name: str):
    if not isinstance(name, str):
        sys.exit(f"ERROR: {setting_name} entries must be strings, got {type(name).__name__}")

    label = name.strip().lower()
    match = PERCENTILE_NAME_RE.match(label)
    if not match:
        sys.exit(
            f"ERROR: invalid percentile '{name}' in {setting_name}. "
            "Expected values like p50, p90, p99, p99.9"
        )

    value = float(match.group("value"))
    if value <= 0 or value > 100:
        sys.exit(
            f"ERROR: percentile '{name}' in {setting_name} must be in (0, 100], got {value}"
        )

    return label, value


def parse_percentile_settings(names, setting_name: str):
    parsed = []
    seen = set()
    for name in names:
        label, value = parse_percentile_name(name, setting_name)
        if label in seen:
            continue
        seen.add(label)
        parsed.append((label, value))
    return parsed


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
    with warnings.catch_warnings():
        # For some parameter regions statsmodels can emit convergence warnings
        # and return NaN/array-like objects; we handle those safely below.
        warnings.simplefilter("ignore")
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


def resolve_collection_dir(collection_dir_arg: str) -> Path:
    raw = collection_dir_arg.strip()

    # Helpful message for Git Bash users: unescaped backslashes in a Windows path
    # (e.g. C:\Work\pqc-research\pilot) can become C:Workpqc-researchpilot.
    if re.match(r"^[A-Za-z]:[^\\/].+", raw):
        sys.exit(
            "ERROR: invalid Windows path format. In Git Bash, either use forward slashes "
            "(e.g. C:/Work/pqc-research/pilot) or quote/escape backslashes "
            "(e.g. 'C:\\\\Work\\\\pqc-research\\\\pilot')."
        )

    # Accept absolute paths in either Windows (C:\..., C:/..., UNC) or POSIX styles.
    # Also accept relative paths and resolve them against the current working directory.
    if ntpath.isabs(raw) or Path(raw).is_absolute():
        collection_dir = Path(raw).resolve()
    else:
        collection_dir = (Path.cwd() / raw).resolve()

    if not collection_dir.is_dir():
        sys.exit(f"ERROR: collection directory not found: {collection_dir}")
    return collection_dir


def main():
    parser = argparse.ArgumentParser(description="Compute per-cell latency CV across mirror repetitions.")
    parser.add_argument(
        "collection_dir",
        help=(
            "Path to a cell-first mirror directory (absolute or relative). "
            "On Windows/Git Bash, prefer C:/... or quote backslash paths."
        ),
    )
    args = parser.parse_args()

    collection_dir = resolve_collection_dir(args.collection_dir)

    output_percentile_specs = parse_percentile_settings(OUTPUT_PERCENTILES, "OUTPUT_PERCENTILES")
    repetition_percentile_specs = parse_percentile_settings(
        REPETITION_PERCENTILES,
        "REPETITION_PERCENTILES",
    )

    # Keep configured order and allow repetition percentiles to be hidden from output.
    all_percentile_specs = list(output_percentile_specs)
    seen_output = {label for label, _ in output_percentile_specs}
    for label, pct in repetition_percentile_specs:
        if label not in seen_output:
            all_percentile_specs.append((label, pct))

    if not all_percentile_specs:
        sys.exit(
            "ERROR: no percentiles configured. Set at least one entry in "
            "OUTPUT_PERCENTILES or REPETITION_PERCENTILES"
        )

    output_percentile_labels = [label for label, _ in output_percentile_specs]
    repetition_percentile_labels = [label for label, _ in repetition_percentile_specs]
    all_percentile_labels = [label for label, _ in all_percentile_specs]

    cell_reps = find_cell_reps(collection_dir)
    cell_names = sorted(cell_reps)
    repetition_count = len({rep_number for reps in cell_reps.values() for rep_number, _ in reps})

    print(f"Found {repetition_count} repetition(s), {len(cell_names)} cell(s).")

    # per_cell_percentiles[cell][percentile] = list of values, one per valid sweep
    per_cell_percentiles = {cell: {p: [] for p in all_percentile_labels} for cell in cell_names}
    per_cell_throughputs_hps = {cell: [] for cell in cell_names}
    per_cell_handshakes_counted = {cell: [] for cell in cell_names}
    warnings = []  # (sweep_name, cell_name, counts)
    zero_counts = {
        "completed_count": 0,
        "warm_count": 0,
        "eligible_count": 0,
        "cooldown_count": 0,
    }

    for cell_name in cell_names:
        for rep_number, rep_dir in cell_reps[cell_name]:
            rep_label = f"rep_{rep_number}"
            rows = load_stream_metrics(rep_dir)
            if rows is None:
                per_cell_handshakes_counted[cell_name].append(0)
                warnings.append((rep_label, cell_name, zero_counts))
                continue

            result, counts = compute_cell_percentiles(rows, all_percentile_specs)
            # Track true eligible volume per trial for visibility into shortfalls.
            per_cell_handshakes_counted[cell_name].append(counts["eligible_count"])

            if counts["eligible_count"] < ANALYSIS_HANDSHAKE_TARGET:
                warnings.append((rep_label, cell_name, counts))

            if result is None:
                continue

            for p in all_percentile_labels:
                per_cell_percentiles[cell_name][p].append(result[p])
            if result["throughput_hps"] is not None:
                per_cell_throughputs_hps[cell_name].append(result["throughput_hps"])

    # Write warnings log
    warnings_path = collection_dir / "warnings.log"
    with open(warnings_path, "w") as f:
        if not warnings:
            f.write("No cells fell short of the eligible-handshake target.\n")
        else:
            f.write(
                f"Cells falling short of ANALYSIS_HANDSHAKE_TARGET={ANALYSIS_HANDSHAKE_TARGET} "
                f"eligible handshakes (after warmup={WARMUP_SEC}s, cooldown={COOLDOWN_SEC}s, success-only filter):\n"
            )
            for rep_name, cell_name, counts in warnings:
                f.write(
                    f"  {cell_name} / {rep_name}: completed={counts['completed_count']}, "
                    f"warm_period={counts['warm_count']}, eligible={counts['eligible_count']}, "
                    f"cooldown_period={counts['cooldown_count']}\n"
                )

    # Write results CSV
    results_path = collection_dir / "cv_results.csv"
    with open(results_path, "w", newline="") as f:
        writer = csv.writer(f)
        header = ["cell", "n_valid_repetitions", "eligible_handshakes_counted"]
        header += ["avg_throughput_hps", "estimated_trial_duration_sec"]
        for p in output_percentile_labels:
            header += [f"{p}_mean_ms", f"{p}_values_ms", f"{p}_cv"]
        header += [
            "max_cv",
            "recommended_repetitions_per_group",
            "estimated_experiment_hours",
        ]
        writer.writerow(header)

        global_max_cv_for_repetitions = None
        total_experiment_hours = 0.0

        for cell_name in cell_names:
            row = [cell_name]
            n_valid = len(per_cell_percentiles[cell_name][all_percentile_labels[0]])
            row.append(n_valid)
            row.append(";".join(str(v) for v in per_cell_handshakes_counted[cell_name]))
            throughput_values = per_cell_throughputs_hps[cell_name]
            mean_throughput = statistics.mean(throughput_values) if throughput_values else None
            row.append(f"{mean_throughput:.3f}" if mean_throughput is not None else "NA")
            trial_duration_sec = (
                TOTAL_HANDSHAKE_TARGET / mean_throughput
                if mean_throughput is not None and mean_throughput > 0
                else None
            )
            row.append(f"{trial_duration_sec:.3f}" if trial_duration_sec is not None else "NA")

            cell_cvs = []
            for p in output_percentile_labels:
                values = per_cell_percentiles[cell_name][p]
                mean_val = statistics.mean(values) if values else None
                cv_val = cv(values)
                row.append(f"{mean_val:.3f}" if mean_val is not None else "NA")
                row.append(";".join(f"{v:.3f}" for v in values) if values else "NA")
                row.append(f"{cv_val:.4f}" if cv_val is not None else "NA")

                if cv_val is not None:
                    cell_cvs.append(cv_val)

            cell_cvs_for_repetitions = []
            for p in repetition_percentile_labels:
                values = per_cell_percentiles[cell_name][p]
                cv_val = cv(values)
                if cv_val is None:
                    continue
                cell_cvs_for_repetitions.append(cv_val)
                if (
                    global_max_cv_for_repetitions is None
                    or cv_val > global_max_cv_for_repetitions
                ):
                    global_max_cv_for_repetitions = cv_val

            cell_max_cv = max(cell_cvs) if cell_cvs else None
            cell_max_cv_for_repetitions = (
                max(cell_cvs_for_repetitions) if cell_cvs_for_repetitions else None
            )
            repetitions = repetitions_from_max_cv(cell_max_cv_for_repetitions)
            row.append(f"{cell_max_cv:.4f}" if cell_max_cv is not None else "NA")
            row.append(repetitions if repetitions is not None else "NA")
            experiment_hours = (
                trial_duration_sec * repetitions / 3600
                if trial_duration_sec is not None and repetitions is not None
                else None
            )
            if experiment_hours is not None:
                total_experiment_hours += experiment_hours
            row.append(f"{experiment_hours:.3f}" if experiment_hours is not None else "NA")
            writer.writerow(row)

    print(f"Wrote results to {results_path}")
    print(f"Wrote warnings to {warnings_path} ({len(warnings)} warning(s))")
    if global_max_cv_for_repetitions is None:
        print("No valid CV values were available to estimate repetitions.")
    else:
        repetitions = repetitions_from_max_cv(global_max_cv_for_repetitions)
        print(
            "Recommended repetitions per group from worst-case CV "
            f"across {tuple(repetition_percentile_labels)} "
            f"({global_max_cv_for_repetitions:.4f}): {repetitions} "
            f"(effect={RELATIVE_EFFECT_SIZE}, alpha={ALPHA}, power={POWER}, ratio={GROUP_RATIO})"
        )
    print(
        f"Estimated main-experiment time for {TOTAL_HANDSHAKE_TARGET:,} handshakes/trial: "
        f"{total_experiment_hours:.3f} hour(s)"
    )


if __name__ == "__main__":
    main()