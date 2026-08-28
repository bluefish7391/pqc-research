#!/usr/bin/env python3
"""
compute_throttle_deltas.py

Computes per-metric before/after deltas for the throttle statistics
collected during each trial.

run_trial.sh's throttle-capture step (write_throttle_stats, in
capture_throttle.sh) appends one row per trial to a single PER-CELL CSV
(CELL_DIR/throttle_stats.csv -- one level above the individual trial
directories), keyed by run_id, with a "_before" and "_after" column for
each raw throttle counter (e.g. lt_nrp_before / lt_nrp_after) plus a
non-numeric capture_status column.

This script pulls one trial's row out of that per-cell file (matched by
run_id == trial directory name), computes a "<prefix>_delta" column
(after - before) for every before/after pair found in the header, and
writes the result as its own one-row PER-TRIAL CSV -- matching the
granularity of this trial's other derived outputs
(pcap_stream_metrics.csv, fragmentation_summary.csv) even though the raw
source data lives in a shared per-cell file.

Before/after pairs are discovered generically from the header (any
column ending in "_before" with a matching "_after" column), rather than
hardcoding the specific metric names (lt_nrp, lt_nrt, lt_tu, ...) -- so
this keeps working if the set of throttle counters collected ever
changes, as long as each counter keeps the "<name>_before"/"<name>_after"
naming convention.

Usage:
    python3 compute_throttle_deltas.py /absolute/path/to/trial_dir
    python3 compute_throttle_deltas.py /absolute/path/to/trial_dir --output /some/other/path.csv
    python3 compute_throttle_deltas.py /absolute/path/to/trial_dir --throttle-csv /some/other/throttle_stats.csv

Requires: pandas installed.
"""

import argparse
import sys
from pathlib import Path

import pandas as pd


def die(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def find_before_after_pairs(columns):
    """
    Returns a list of (prefix, before_col, after_col) tuples for every
    column ending in "_before" that has a matching "_after" column.
    Discovered from the header rather than hardcoded, so this keeps
    working if the set of throttle counters collected ever changes.
    """
    pairs = []
    for col in columns:
        if col.endswith("_before"):
            prefix = col[: -len("_before")]
            after_col = f"{prefix}_after"
            if after_col in columns:
                pairs.append((prefix, col, after_col))
    return pairs


def compute_deltas_for_trial(throttle_csv: Path, run_id: str) -> pd.DataFrame:
    """
    Returns a one-row DataFrame: run_id, capture_status (if present),
    and a "<prefix>_delta" column for every before/after pair found in
    throttle_csv, for the row matching run_id.
    """
    df = pd.read_csv(throttle_csv)

    if "run_id" not in df.columns:
        die(f"{throttle_csv} has no 'run_id' column -- cannot match this trial's row.")

    matches = df[df["run_id"] == run_id]
    if matches.empty:
        die(f"No row for run_id={run_id!r} found in {throttle_csv}.")
    if len(matches) > 1:
        die(f"{len(matches)} rows for run_id={run_id!r} found in {throttle_csv}; expected exactly one.")

    row = matches.iloc[0]
    pairs = find_before_after_pairs(df.columns)
    if not pairs:
        die(f"No '<name>_before' / '<name>_after' column pairs found in {throttle_csv}.")

    result = {"run_id": run_id}
    if "capture_status" in df.columns:
        result["capture_status"] = row["capture_status"]

    for prefix, before_col, after_col in pairs:
        before_val = pd.to_numeric(row[before_col], errors="coerce")
        after_val = pd.to_numeric(row[after_col], errors="coerce")
        result[f"{prefix}_delta"] = after_val - before_val

    return pd.DataFrame([result])


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("trial_dir", type=str, help="Absolute path to a trial directory")
    parser.add_argument(
        "--throttle-csv", type=str, default=None,
        help="Path to the per-cell throttle_stats.csv (default: <trial_dir>/../throttle_stats.csv)",
    )
    parser.add_argument(
        "--output", type=str, default=None,
        help="Output CSV path (default: <trial_dir>/throttle_deltas.csv)",
    )
    args = parser.parse_args()

    trial_dir = Path(args.trial_dir).expanduser().resolve()
    if not trial_dir.is_dir():
        die(f"{trial_dir} is not a directory.")

    throttle_csv = (
        Path(args.throttle_csv).expanduser().resolve()
        if args.throttle_csv
        else trial_dir.parent / "throttle_stats.csv"
    )
    if not throttle_csv.is_file():
        die(f"{throttle_csv} not found.")

    run_id = trial_dir.name
    result = compute_deltas_for_trial(throttle_csv, run_id)

    output_path = (
        Path(args.output).expanduser().resolve() if args.output else (trial_dir / "throttle_deltas.csv")
    )
    result.to_csv(output_path, index=False)
    print(f"Wrote {output_path}")


if __name__ == "__main__":
    main()