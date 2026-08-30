#!/usr/bin/env python3
"""
filter_for_window.py

Takes a directory produced by reorg_by_cell.py (cell-first layout with pcap_stream_metrics.csv
and container stats per repetition) and creates a sibling directory with the same structure,
filtering time-based data using the same warmup/cooldown logic as compute_cell_cv.py.

For each (cell, rep):
  1. Load pcap_stream_metrics.csv
  2. Determine the trial time window (t_start, t_end) from all valid packet timestamps
  3. Filter rows to keep only those outside warmup (first WARMUP_SEC) and cooldown (last COOLDOWN_SEC)
  4. If >= ANALYSIS_HANDSHAKE_TARGET eligible rows exist, keep only the first ANALYSIS_HANDSHAKE_TARGET (in time order)
  5. Write filtered pcap_stream_metrics.csv to the new directory
  6. Filter container_stats files (nginx, locust, router CPU matrices) to include only samples within the same time window
  7. Copy other files (throttle_deltas.csv, fragmentation_summary.csv) as-is

Expected input layout (as produced by reorg_by_cell.py):

    BY_CELL_DIR/
      <cell_name>/
        rep_<N>/
          pcap_stream_metrics.csv
          container_stats/
            nginx_cpu_matrix_*.csv
            locust_cpu_matrix_*.csv
            router_cpu_matrix_*.csv
          throttle_deltas.csv
          fragmentation_summary.csv
        ...
      ...

Output layout (created in sibling directory):

    BY_CELL_DIR_filtered/
      <cell_name>/
        rep_<N>/
          [same structure with filtered data]
        ...
      ...

Usage:
    python3 filter_for_window.py <by_cell_dir> [--output OUTPUT_DIR]

Options:
    --output OUTPUT_DIR   Explicit output directory path (default: sibling of by_cell_dir, 
                         named <by_cell_dir_name>_filtered)
"""

import argparse
import csv
import math
import ntpath
import re
import sys
from pathlib import Path


# ---- Tunable constants (match compute_cell_cv.py) -----------------------------------------------
WARMUP_SEC = 10          # seconds after trial start to discard (pcap-time)
COOLDOWN_SEC = 10        # seconds before trial end to discard (pcap-time)
ANALYSIS_HANDSHAKE_TARGET = 10_000  # handshakes used for analysis; filter to this count
REP_DIR_RE = re.compile(r"^rep_(?P<num>\d+)$")
REQUIRED_COLUMNS = {"first_pkt_time", "last_pkt_time", "stream_span_ms"}
# ------------------------------------------------------------------------------------------------


def resolve_by_cell_dir(raw_arg: str) -> Path:
    """Resolve input directory path (absolute or relative)."""
    raw = raw_arg.strip()

    # Helpful message for Git Bash users
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


def find_cell_reps(by_cell_dir: Path):
    """
    Walks BY_CELL_DIR and returns a dict mapping cell_name -> list of (rep_number, rep_dir).
    """
    cell_reps = {}
    for cell_dir in visible_subdirs(by_cell_dir):
        reps = []
        for rep_dir in visible_subdirs(cell_dir):
            match = REP_DIR_RE.fullmatch(rep_dir.name)
            if match is None:
                print(f"  WARNING: skipping unexpected directory {rep_dir} "
                      f"(does not match 'rep_<N>').")
                continue
            reps.append((int(match.group("num")), rep_dir))
        reps.sort(key=lambda pair: pair[0])
        if not reps:
            print(f"  WARNING: no rep_<N> directories found under cell {cell_dir}")
        cell_reps[cell_dir.name] = reps
    return cell_reps


def parse_float(value):
    """Safely parse a float from a string, returning None on failure."""
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def load_rep_rows(rep_dir: Path):
    """
    Loads pcap_stream_metrics.csv for one (cell, rep) and returns a list of dicts
    with the fields needed for filtering, or None if the file is missing.
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
                    "original_row": row,  # keep all original columns for writing
                }
            )
    return rows


def compute_filter_window(rows):
    """
    Determines the time window (t_start, t_end) and filters rows based on warmup/cooldown.
    
    Returns:
        (eligible_rows, t_start, t_end, counts_dict) or (None, None, None, counts_dict)
        if no eligible rows remain after filtering.
    """
    zero_counts = {
        "completed_count": 0,
        "unmatched_count": 0,
        "warm_count": 0,
        "eligible_count": 0,
        "cooldown_count": 0,
    }

    if not rows:
        return None, None, None, zero_counts

    def has_stream_data(r):
        return (
            r["first_pkt_time"] is not None
            and r["last_pkt_time"] is not None
            and r["stream_span_ms"] is not None
        )

    # Determine trial boundaries from all rows with valid packet timestamps
    boundary_rows = [r for r in rows if has_stream_data(r)]
    if not boundary_rows:
        counts = dict(zero_counts)
        counts["completed_count"] = len(rows)
        return None, None, None, counts

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
        return None, t_start, t_end, counts

    # Cap at ANALYSIS_HANDSHAKE_TARGET rows (already sorted by first_pkt_time)
    window = (
        eligible[:ANALYSIS_HANDSHAKE_TARGET]
        if counts["eligible_count"] >= ANALYSIS_HANDSHAKE_TARGET
        else eligible
    )

    return window, t_start, t_end, counts


def write_filtered_pcap_metrics(filtered_rows, output_path: Path):
    """Write the filtered pcap_stream_metrics.csv, preserving all original columns."""
    if not filtered_rows:
        output_path.touch()  # create empty file
        return

    # Use fieldnames from the first row's original_row dict
    fieldnames = list(filtered_rows[0]["original_row"].keys())
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in filtered_rows:
            writer.writerow(row["original_row"])


def filter_container_stats(csv_path: Path, t_start: float, t_end: float, output_path: Path):
    """
    Filter a container_stats CSV file to keep only rows with Timestamp within [t_start, t_end].
    Timestamp is expected in nanoseconds; t_start/t_end are in seconds (with fractional part).
    """
    if not csv_path.is_file():
        return  # file doesn't exist, skip it

    # Convert time window from seconds to nanoseconds for comparison
    t_start_ns = t_start * 1e9
    t_end_ns = t_end * 1e9

    output_path.parent.mkdir(parents=True, exist_ok=True)
    filtered_count = 0

    with open(csv_path, newline="") as inf, open(output_path, "w", newline="") as outf:
        reader = csv.DictReader(inf)
        if reader.fieldnames is None or "Timestamp" not in reader.fieldnames:
            # No Timestamp column, just copy the entire file
            outf.write(inf.read())
            return

        writer = csv.DictWriter(outf, fieldnames=reader.fieldnames)
        writer.writeheader()
        for row in reader:
            try:
                ts_ns = int(row["Timestamp"])
                if t_start_ns <= ts_ns <= t_end_ns:
                    writer.writerow(row)
                    filtered_count += 1
            except (ValueError, KeyError):
                # Skip rows with invalid timestamps
                pass

    print(f"    Filtered {csv_path.name}: {filtered_count} rows kept")


def copy_file_as_is(src: Path, dst: Path):
    """Copy a file without modification."""
    if not src.is_file():
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    with open(src, "rb") as inf, open(dst, "wb") as outf:
        outf.write(inf.read())


def process_rep(cell_name: str, rep_number: int, rep_dir: Path, output_rep_dir: Path, log_lines: list):
    """
    Process a single (cell, rep) directory: filter time-based data and copy others.
    """
    print(f"  Processing {cell_name}/rep_{rep_number}...")

    # Load and filter pcap_stream_metrics.csv
    rows = load_rep_rows(rep_dir)
    if rows is None:
        log_lines.append(f"{cell_name}/rep_{rep_number}: pcap_stream_metrics.csv missing")
        return

    filtered_rows, t_start, t_end, counts = compute_filter_window(rows)

    if counts["eligible_count"] < ANALYSIS_HANDSHAKE_TARGET:
        log_lines.append(
            f"{cell_name}/rep_{rep_number}: only {counts['eligible_count']} eligible rows "
            f"(target={ANALYSIS_HANDSHAKE_TARGET}); completed={counts['completed_count']}, "
            f"unmatched={counts['unmatched_count']}, warm={counts['warm_count']}, "
            f"cooldown={counts['cooldown_count']}"
        )

    # Write filtered pcap metrics
    output_rep_dir.mkdir(parents=True, exist_ok=True)
    write_filtered_pcap_metrics(filtered_rows, output_rep_dir / "pcap_stream_metrics.csv")
    print(f"    Wrote pcap_stream_metrics.csv: {len(filtered_rows) if filtered_rows else 0} rows")

    # Filter container stats if time window was determined
    if t_start is not None and t_end is not None:
        container_stats_dir = rep_dir / "container_stats"
        if container_stats_dir.is_dir():
            output_stats_dir = output_rep_dir / "container_stats"
            for stats_file in container_stats_dir.glob("*.csv"):
                output_stats_file = output_stats_dir / stats_file.name
                filter_container_stats(stats_file, t_start, t_end, output_stats_file)

    # Copy other files as-is
    for other_file in ["throttle_deltas.csv", "fragmentation_summary.csv"]:
        src = rep_dir / other_file
        if src.is_file():
            copy_file_as_is(src, output_rep_dir / other_file)
            print(f"    Copied {other_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Filter by-cell data using warmup/cooldown logic from compute_cell_cv.py."
    )
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
        help="Output directory path (default: sibling of by_cell_dir, named <by_cell_dir_name>_filtered)",
    )
    args = parser.parse_args()

    by_cell_dir = resolve_by_cell_dir(args.by_cell_dir)

    output_dir = (
        Path(args.output).expanduser().resolve()
        if args.output
        else by_cell_dir.parent / f"{by_cell_dir.name}_filtered"
    )

    if output_dir.exists():
        print(f"WARNING: output directory already exists: {output_dir}")
        print("This script will overwrite existing files in that directory.")
        response = input("Continue? (yes/no): ").strip().lower()
        if response not in ("yes", "y"):
            sys.exit("Aborted.")

    output_dir.mkdir(parents=True, exist_ok=True)
    log_lines = []

    print(f"Input directory:  {by_cell_dir}")
    print(f"Output directory: {output_dir}")
    print()

    # Find all (cell, rep) pairs
    cell_reps = find_cell_reps(by_cell_dir)
    if not cell_reps:
        print(f"FATAL: no cell directories found under {by_cell_dir}. Check the path and layout.")
        sys.exit(1)

    cell_names = sorted(cell_reps.keys())
    total_reps = sum(len(reps) for reps in cell_reps.values())
    print(f"Found {len(cell_names)} cell(s), {total_reps} repetition(s) total.")
    print()

    # Process each (cell, rep)
    for cell_name in cell_names:
        print(f"Processing cell: {cell_name}")
        output_cell_dir = output_dir / cell_name
        for rep_number, rep_dir in cell_reps[cell_name]:
            output_rep_dir = output_cell_dir / f"rep_{rep_number}"
            process_rep(cell_name, rep_number, rep_dir, output_rep_dir, log_lines)
        print()

    # Write summary log
    log_path = output_dir / "filtering_summary.log"
    with open(log_path, "w") as f:
        f.write(f"Filtering summary for {output_dir.name}\n")
        f.write(f"Input directory:  {by_cell_dir}\n")
        f.write(f"Filtering parameters:\n")
        f.write(f"  WARMUP_SEC={WARMUP_SEC}, COOLDOWN_SEC={COOLDOWN_SEC}\n")
        f.write(f"  ANALYSIS_HANDSHAKE_TARGET={ANALYSIS_HANDSHAKE_TARGET}\n")
        f.write("\n")
        if log_lines:
            f.write("Warnings:\n")
            for line in log_lines:
                f.write(f"  {line}\n")
        else:
            f.write("No warnings.\n")

    print(f"\nFiltering complete!")
    print(f"Wrote summary to {log_path}")
    if log_lines:
        print(f"{len(log_lines)} warning(s) logged")


if __name__ == "__main__":
    main()
