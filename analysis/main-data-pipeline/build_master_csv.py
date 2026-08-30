#!/usr/bin/env python3
"""
build_master_csv.py

Takes a filtered by-cell directory produced by filter_for_window.py and builds a
single master CSV, as a sibling of that directory, with one row per trial
(cell x repetition).

Each row has the trial's conditions (kem group, concurrent users, network
condition label B1-B4) plus P50/P90/P95 handshake latency computed from that
trial's already-filtered pcap_stream_metrics.csv (stream_span_ms column).

Expected input layout (as produced by filter_for_window.py):

    BY_CELL_DIR_filtered/
      <cell_name>/
        rep_<N>/
          pcap_stream_metrics.csv
        ...
      ...

Cell names are expected to match "<kem_group>_u<users>_rtt<rtt>ms_loss<loss>pct".

Usage:
    python3 build_master_csv.py <by_cell_dir_filtered> [--output OUTPUT_CSV]

Options:
    --output OUTPUT_CSV   Explicit output CSV path (default: sibling of
                           by_cell_dir, named <by_cell_dir_name>_master.csv)
"""

import argparse
import csv
import ntpath
import re
import sys
from pathlib import Path

CELL_NAME_RE = re.compile(
    r"^(?P<kem_group>[A-Za-z0-9]+)_u(?P<concurrent_users>\d+)_rtt(?P<rtt_ms>\d+)ms_loss(?P<loss_pct>\d+)pct$"
)
REP_DIR_RE = re.compile(r"^rep_(?P<num>\d+)$")
PERCENTILE_SPECS = (("p50_latency_ms", 50.0), ("p90_latency_ms", 90.0), ("p95_latency_ms", 95.0))

# Mirrors NETWORK_CONDITIONS in main/orchestration/experimental_vars.sh.
NETWORK_CONDITION_LABELS = {
    (10, 0): "B1",
    (50, 1): "B2",
    (100, 2): "B3",
    (200, 5): "B4",
}


def resolve_by_cell_dir(raw_arg: str) -> Path:
    """Resolve input directory path (absolute or relative)."""
    raw = raw_arg.strip()

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
    """Walks BY_CELL_DIR and returns a dict mapping cell_name -> list of (rep_number, rep_dir)."""
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


def parse_cell_name(cell_name: str):
    """Parses a cell name into its trial conditions, or None if it doesn't match."""
    match = CELL_NAME_RE.fullmatch(cell_name)
    if match is None:
        return None
    rtt_ms = int(match.group("rtt_ms"))
    loss_pct = int(match.group("loss_pct"))
    network_condition = NETWORK_CONDITION_LABELS.get((rtt_ms, loss_pct))
    if network_condition is None:
        return None
    return {
        "kem_group": match.group("kem_group"),
        "concurrent_users": int(match.group("concurrent_users")),
        "network_condition": network_condition,
    }


def parse_float(value):
    """Safely parse a float from a string, returning None on failure."""
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def percentile(values, pct):
    """Nearest-rank percentile on a list of values."""
    if not values:
        return None
    ordered = sorted(values)
    k = max(0, min(len(ordered) - 1, round(pct / 100 * (len(ordered) - 1))))
    return ordered[k]


def load_latencies(rep_dir: Path):
    """Reads stream_span_ms values from a (already-filtered) pcap_stream_metrics.csv."""
    csv_path = rep_dir / "pcap_stream_metrics.csv"
    if not csv_path.is_file():
        return None

    latencies = []
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None or "stream_span_ms" not in reader.fieldnames:
            return None
        for row in reader:
            value = parse_float(row.get("stream_span_ms"))
            if value is not None:
                latencies.append(value)
    return latencies


def main():
    parser = argparse.ArgumentParser(
        description="Build a master CSV (one row per trial) from a filter_for_window.py output directory."
    )
    parser.add_argument(
        "by_cell_dir",
        help="Path to a directory produced by filter_for_window.py (absolute or relative).",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output CSV path (default: sibling of by_cell_dir, named <by_cell_dir_name>_master.csv)",
    )
    args = parser.parse_args()

    by_cell_dir = resolve_by_cell_dir(args.by_cell_dir)
    output_csv = (
        Path(args.output).expanduser().resolve()
        if args.output
        else by_cell_dir.parent / f"{by_cell_dir.name}_master.csv"
    )

    cell_reps = find_cell_reps(by_cell_dir)
    if not cell_reps:
        sys.exit(f"FATAL: no cell directories found under {by_cell_dir}. Check the path and layout.")

    fieldnames = [
        "cell_name",
        "kem_group",
        "concurrent_users",
        "network_condition",
        "repetition",
        "p50_latency_ms",
        "p90_latency_ms",
        "p95_latency_ms",
        "handshake_count",
    ]

    rows_written = 0
    skipped = []
    with open(output_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for cell_name in sorted(cell_reps.keys()):
            conditions = parse_cell_name(cell_name)
            if conditions is None:
                skipped.append(f"{cell_name}: does not match expected cell-name pattern")
                continue

            for rep_number, rep_dir in cell_reps[cell_name]:
                latencies = load_latencies(rep_dir)
                if not latencies:
                    skipped.append(f"{cell_name}/rep_{rep_number}: no latency data found")
                    continue

                row = {
                    "cell_name": cell_name,
                    "kem_group": conditions["kem_group"],
                    "concurrent_users": conditions["concurrent_users"],
                    "network_condition": conditions["network_condition"],
                    "repetition": rep_number,
                    "p50_latency_ms": percentile(latencies, 50.0),
                    "p90_latency_ms": percentile(latencies, 90.0),
                    "p95_latency_ms": percentile(latencies, 95.0),
                    "handshake_count": len(latencies),
                }
                writer.writerow(row)
                rows_written += 1

    print(f"Wrote {rows_written} trial row(s) to {output_csv}")
    if skipped:
        print(f"Skipped {len(skipped)} trial(s):")
        for line in skipped:
            print(f"  {line}")


if __name__ == "__main__":
    main()
