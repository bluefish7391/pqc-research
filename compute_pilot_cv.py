#!/usr/bin/env python3
"""
compute_pilot_cv.py

For a given collection directory (containing sweep_1, sweep_2, ... subdirs,
each with the same 24 experimental cell subdirs), compute the coefficient of
variation (CV = stddev/mean) of P50/P90/P99 handshake latency *across sweeps*,
for each cell.

Per-(sweep, cell) processing:
  1. Load all 4 worker_*_requests.csv files from <cell>/locust/requests/.
  2. Compute response_time_ms = (end_time_ns - start_time_ns) / 1e6 for all rows.
  3. Determine t_start (min start_time_ns) and t_end (max end_time_ns) across
     ALL rows (successes + failures) -- this is Option A: trial-activity-based
     reference points, not success-only.
  4. Keep rows where:
       - success == "False"   (NOTE: this column is inverted in the source
         data -- "False" means the request actually succeeded, see
         locustfile.py's log_request_to_csv, which writes
         `exception is not None` into the success field)
       - start_time_ns >= t_start + WARMUP_SEC * 1e9
       - end_time_ns   <= t_end   - COOLDOWN_SEC * 1e9
  5. Sort by start_time_ns; if fewer than HANDSHAKE_TARGET rows remain, log a
      warning but still compute P50/P90/P99 using all eligible rows. If at least
      HANDSHAKE_TARGET rows remain, use the first HANDSHAKE_TARGET rows (in time
      order) for percentile computation.

Then, per cell, aggregate per-sweep P50/P90/P99 values across sweeps with at
least one eligible handshake and compute mean/stddev/CV for each percentile.

Usage:
    python3 compute_pilot_cv.py <collection_name> [--data-dir DATA_DIR]

Outputs (written into the collection directory):
    cv_results.csv       -- one row per cell: n_valid_sweeps, eligible
                             handshakes counted per trial (semicolon-separated),
                             means, per-trial percentile values (semicolon-
                             separated), CVs, and average throughput
    warnings.log         -- one line per (sweep, cell) that fell short of
                             HANDSHAKE_TARGET eligible handshakes
"""

import argparse
import csv
import importlib
import math
import re
import statistics
import sys
import warnings
from pathlib import Path

# ---- Tunable constants -----------------------------------------------------
WARMUP_SEC = 10          # seconds after trial start to discard
COOLDOWN_SEC = 10        # seconds before trial end to discard
HANDSHAKE_TARGET = 10_000  # eligible handshakes required per (sweep, cell)
OUTPUT_PERCENTILES = ("p50", "p90", "p95")
REPETITION_PERCENTILES = ("p50", "p90", "p95")
CELL_NAME_RE = re.compile(r"^(?P<base>.+)_rep\d+$")
PERCENTILE_NAME_RE = re.compile(r"^p(?P<value>\d+(?:\.\d+)?)$", re.IGNORECASE)
RELATIVE_EFFECT_SIZE = 0.10  # detectable mean shift as a fraction of baseline mean
ALPHA = 0.0167
POWER = 0.90
GROUP_RATIO = 1.0
# -----------------------------------------------------------------------------


def find_sweep_dirs(collection_dir: Path):
    sweep_dirs = sorted(
        [p for p in collection_dir.iterdir() if p.is_dir() and p.name.startswith("sweep_")],
        key=lambda p: p.name,
    )
    if not sweep_dirs:
        sys.exit(f"ERROR: no sweep_* directories found under {collection_dir}")
    return sweep_dirs


def canonical_cell_name(cell_name: str) -> str:
    match = CELL_NAME_RE.match(cell_name)
    return match.group("base") if match else cell_name


def get_cells_for_sweep(sweep_dir: Path):
    """Return a mapping from canonical cell name to the actual directory."""
    cells = {}
    for cell_dir in sweep_dir.iterdir():
        if not cell_dir.is_dir():
            continue

        cell_name = canonical_cell_name(cell_dir.name)
        if cell_name in cells:
            sys.exit(
                f"ERROR: duplicate cell family '{cell_name}' in {sweep_dir.name}: "
                f"{cells[cell_name].name} and {cell_dir.name}"
            )
        cells[cell_name] = cell_dir

    return cells


def assert_consistent_cells(sweep_dirs):
    """All sweeps must contain the same set of cell names, or something is wrong
    with the collection (a partial/failed sweep) and we should fail loudly
    rather than silently comparing mismatched data."""
    reference = None
    for sweep_dir in sweep_dirs:
        cells = set(get_cells_for_sweep(sweep_dir).keys())
        if reference is None:
            reference = cells
        elif cells != reference:
            missing = reference - cells
            extra = cells - reference
            sys.exit(
                f"ERROR: cell mismatch in {sweep_dir.name}.\n"
                f"  Missing: {sorted(missing)}\n"
                f"  Extra:   {sorted(extra)}"
            )
    return sorted(reference)


def load_cell_requests(cell_dir: Path):
    """Load and concatenate all worker_*_requests.csv files for one cell/sweep.
    Returns a list of dicts with start_time_ns, end_time_ns, success (raw str)."""
    requests_dir = cell_dir / "locust" / "requests"
    if not requests_dir.is_dir():
        return None  # missing entirely -- treat as a failed/incomplete run

    rows = []
    worker_files = sorted(requests_dir.glob("worker_*_requests.csv"))
    if not worker_files:
        return None

    for worker_file in worker_files:
        with open(worker_file, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    start_ns = int(row["start_time_ns"])
                    end_ns = int(row["end_time_ns"])
                except (KeyError, ValueError):
                    continue  # skip malformed row rather than crash the whole script
                rows.append(
                    {
                        "start_time_ns": start_ns,
                        "end_time_ns": end_ns,
                        "success": row.get("success", ""),
                    }
                )
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

    # Option A: reference points from ALL rows (success + failure).
    t_start = min(r["start_time_ns"] for r in rows)
    t_end = max(r["end_time_ns"] for r in rows)

    warmup_cutoff = t_start + WARMUP_SEC * 1_000_000_000
    cooldown_cutoff = t_end - COOLDOWN_SEC * 1_000_000_000

    completed = [r for r in rows if r["success"] == "False"]
    warm = [r for r in completed if r["start_time_ns"] < warmup_cutoff]
    cooldown = [r for r in completed if r["end_time_ns"] > cooldown_cutoff]
    eligible = [
        r
        for r in completed
        if r["start_time_ns"] >= warmup_cutoff and r["end_time_ns"] <= cooldown_cutoff
    ]
    eligible.sort(key=lambda r: r["start_time_ns"])

    counts = {
        "completed_count": len(completed),
        "warm_count": len(warm),
        "eligible_count": len(eligible),
        "cooldown_count": len(cooldown),
    }

    if counts["eligible_count"] == 0:
        return None, counts

    window = eligible[:HANDSHAKE_TARGET] if counts["eligible_count"] >= HANDSHAKE_TARGET else eligible
    latencies_ms = [(r["end_time_ns"] - r["start_time_ns"]) / 1e6 for r in window]
    window_start_ns = window[0]["start_time_ns"]
    window_end_ns = window[-1]["end_time_ns"]
    duration_sec = (window_end_ns - window_start_ns) / 1e9
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
    path = Path(collection_dir_arg)
    if not path.is_absolute():
        sys.exit(f"ERROR: collection directory must be an absolute path: {collection_dir_arg}")

    collection_dir = path.resolve()
    if not collection_dir.is_dir():
        sys.exit(f"ERROR: collection directory not found: {collection_dir}")
    return collection_dir


def main():
    parser = argparse.ArgumentParser(description="Compute per-cell latency CV across sweeps.")
    parser.add_argument("collection_dir", help="Absolute path to the collection directory.")
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

    sweep_dirs = find_sweep_dirs(collection_dir)
    cell_names = assert_consistent_cells(sweep_dirs)

    print(f"Found {len(sweep_dirs)} sweep(s), {len(cell_names)} cell(s).")

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

    for sweep_dir in sweep_dirs:
        cells_for_sweep = get_cells_for_sweep(sweep_dir)
        for cell_name in cell_names:
            cell_dir = cells_for_sweep.get(cell_name)
            if cell_dir is None:
                per_cell_handshakes_counted[cell_name].append(0)
                warnings.append((sweep_dir.name, cell_name, zero_counts))
                continue

            rows = load_cell_requests(cell_dir)
            if rows is None:
                per_cell_handshakes_counted[cell_name].append(0)
                warnings.append((sweep_dir.name, cell_name, zero_counts))
                continue

            result, counts = compute_cell_percentiles(rows, all_percentile_specs)
            # Track true eligible volume per trial for visibility into shortfalls.
            per_cell_handshakes_counted[cell_name].append(counts["eligible_count"])

            if counts["eligible_count"] < HANDSHAKE_TARGET:
                warnings.append((sweep_dir.name, cell_name, counts))

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
                f"Cells falling short of HANDSHAKE_TARGET={HANDSHAKE_TARGET} "
                f"eligible handshakes (after warmup={WARMUP_SEC}s, cooldown={COOLDOWN_SEC}s, success-only filter):\n"
            )
            for sweep_name, cell_name, counts in warnings:
                f.write(
                    f"  {sweep_name} / {cell_name}: completed={counts['completed_count']}, "
                    f"warm_period={counts['warm_count']}, eligible={counts['eligible_count']}, "
                    f"cooldown_period={counts['cooldown_count']}\n"
                )

    # Write results CSV
    results_path = collection_dir / "cv_results.csv"
    with open(results_path, "w", newline="") as f:
        writer = csv.writer(f)
        header = ["cell", "n_valid_sweeps", "eligible_handshakes_counted"]
        header += ["avg_throughput_hps"]
        for p in output_percentile_labels:
            header += [f"{p}_mean_ms", f"{p}_values_ms", f"{p}_cv"]
        header += ["max_cv", "recommended_repetitions_per_group"]
        writer.writerow(header)

        global_max_cv_for_repetitions = None

        for cell_name in cell_names:
            row = [cell_name]
            n_valid = len(per_cell_percentiles[cell_name][all_percentile_labels[0]])
            row.append(n_valid)
            row.append(";".join(str(v) for v in per_cell_handshakes_counted[cell_name]))
            throughput_values = per_cell_throughputs_hps[cell_name]
            mean_throughput = statistics.mean(throughput_values) if throughput_values else None
            row.append(f"{mean_throughput:.3f}" if mean_throughput is not None else "NA")

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


if __name__ == "__main__":
    main()