#!/usr/bin/env python3
"""
reorg_by_cell.py

Reorganizes a trial collection directory into a sibling directory
containing ONLY the derived/mirrored per-repetition analysis output for
every trial, in the same cell -> repetition layout as the original:

  - pcap_stream_metrics.csv : per-stream metrics extracted from capture.pcap
                              via extract_stream_metrics.py
  - container_stats/        : the raw per-second CPU/mem/net CSVs for
                              oqs-locust, oqs-nginx, and router, copied
                              as-is from the trial directory
  - throttle_deltas.csv     : per-trial after-minus-before delta for every
                              cgroup cpu.stat throttling metric, computed
                              from the cell's shared throttle_stats.csv

Expected input layout (as produced by run_matrix.sh / run_trial.sh):

    COLLECTION_DIR/
      <cell_name>/
        throttle_stats.csv               <- one file per cell, one row per trial (run_id)
        <cell_name>_rep<N>/
          capture.pcap
          keylogs/
          container_stats/
          locust/requests/worker_*.csv
          ...

Output layout (default: a sibling directory named "<COLLECTION_DIR>_by_cell"):

    COLLECTION_DIR_by_cell/
      <cell_name>/
        rep_<N>/
          pcap_stream_metrics.csv
          container_stats/
          throttle_deltas.csv

For each trial directory, this script invokes extract_stream_metrics.py,
pointing its --output flag directly at the new location. Keylog material is
used only through temporary files and is not retained in either directory.

Raw trial data (capture.pcap, keylogs/, locust/requests/*.csv) is left
in place under COLLECTION_DIR and is NOT duplicated into the new tree.
container_stats/ is the one exception: it is small (per-second samples
for the run duration) and is copied as-is rather than re-derived, so
downstream analysis has both raw and derived data in a single directory.

A failed trial (nonzero exit from extract_stream_metrics.py) intentionally
leaves behind whatever partial output
already exists in its rep_<N>/ directory rather than being cleaned up.
This makes failures visible (an empty or half-populated rep_<N>/ folder)
and means a later re-run without --force will only reprocess trials that
are not yet fully complete (see `trial_already_done` below), rather than
redoing the whole collection.

Note on failure handling: only the pcap-metrics step (extract_stream_metrics.py)
is treated as fatal for a trial. A missing container_stats/ directory or a
missing/unmatched throttle_stats.csv row logs a warning and is skipped
individually, since those are independent, smaller pieces of a trial's
output and a problem with one of them doesn't make the pcap-derived metrics
uninterpretable.

Usage:
    python3 reorg_by_cell.py /absolute/path/to/COLLECTION_DIR
    python3 reorg_by_cell.py /absolute/path/to/COLLECTION_DIR --output /some/other/dir
    python3 reorg_by_cell.py /absolute/path/to/COLLECTION_DIR --force
    python3 reorg_by_cell.py /absolute/path/to/COLLECTION_DIR --extract-script /path/to/extract_stream_metrics.py

Requires: extract_stream_metrics.py (and, transitively, tshark + pandas).
"""

import argparse
import datetime
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pandas as pd

TRIAL_DIR_RE_TEMPLATE = r"^{cell_name}_rep(\d+)$"

# Must match THROTTLE_ALIASES / THROTTLE_METRICS (via throttle_metric_suffix)
# in capture_throttle.sh -- these are the column-name pieces used to build
# "<alias>_<suffix>_before" / "<alias>_<suffix>_after" in throttle_stats.csv.
THROTTLE_ALIASES = ["lt", "rt", "ws"]
THROTTLE_METRIC_SUFFIXES = ["nrp", "nrt", "tu"]


def die(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def default_extract_script() -> Path:
    """extract_stream_metrics.py is expected to live alongside this script."""
    return Path(__file__).resolve().parent / "extract_stream_metrics.py"


def visible_subdirs(path: Path):
    """Subdirectories of `path`, skipping dotfiles/dirs, sorted for stable ordering."""
    return sorted(p for p in path.iterdir() if p.is_dir() and not p.name.startswith("."))


def find_trials(collection_dir: Path, log):
    """
    Walks COLLECTION_DIR and returns a list of (cell_name, rep_number, trial_dir)
    for every trial directory found, i.e. every subdirectory of a cell directory
    matching "<cell_name>_rep<N>".

    Any subdirectory that does NOT match this pattern is skipped and reported
    via `log` rather than silently ignored.
    """
    trials = []
    for cell_dir in visible_subdirs(collection_dir):
        pattern = re.compile(TRIAL_DIR_RE_TEMPLATE.format(cell_name=re.escape(cell_dir.name)))
        found_any = False
        for trial_dir in visible_subdirs(cell_dir):
            match = pattern.fullmatch(trial_dir.name)
            if match is None:
                log(f"  WARNING: skipping unexpected directory {trial_dir} "
                    f"(does not match '<cell_name>_rep<N>').")
                continue
            found_any = True
            trials.append((cell_dir.name, int(match.group(1)), trial_dir))
        if not found_any:
            log(f"  WARNING: no trial directories found under cell {cell_dir}")
    return trials


def trial_already_done(dest: Path) -> bool:
    """
    A trial counts as already-processed only when ALL of its outputs are
    present: the pcap-derived metrics CSV, the copied container_stats/
    directory, and the throttle-deltas CSV. Checking all three (rather than
    just pcap_stream_metrics.csv, as in the original version of this script)
    means a collection that was reorganized before container_stats/ and
    throttle_deltas.csv existed will be correctly treated as incomplete and
    have the missing pieces filled in, instead of being skipped entirely
    based on the pcap CSV's presence alone.
    """
    return (
        (dest / "pcap_stream_metrics.csv").exists()
        and (dest / "throttle_deltas.csv").exists()
        and (dest / "container_stats").is_dir()
    )


def copy_container_stats(trial_dir: Path, dest: Path, log) -> None:
    """
    Copies the raw per-second container_stats/ directory (CPU/mem/net
    samples for oqs-locust, oqs-nginx, and router, written by run_trial.sh's
    background monitor) into this trial's mirrored destination directory.

    This is a copy of raw data, not a derived computation -- unlike
    pcap_stream_metrics.csv and throttle_deltas.csv -- but it's small
    (three per-second CSVs for the run duration) and colocating it with the
    derived metrics keeps everything needed for analysis in one place.
    """
    src = trial_dir / "container_stats"
    if not src.is_dir():
        log(f"    WARNING: no container_stats/ directory found in {trial_dir}; skipping copy.")
        return

    dst = dest / "container_stats"
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)
    log(f"    Copied container_stats/ -> {dst}")


def load_cell_throttle_stats(cell_dir: Path, cache: dict, log):
    """
    Loads and caches <cell_dir>/throttle_stats.csv, keyed by cell_dir, so it
    is read from disk once per CELL rather than once per trial -- the file
    is written once per cell (by write_throttle_stats() in
    capture_throttle.sh) with one row per trial run_id, so re-reading it for
    every repetition in that cell would be redundant I/O.

    Returns the DataFrame (indexed by run_id) on success, or None if the
    file is missing -- callers should treat None as "skip throttle deltas
    for this cell" rather than aborting the whole reorg run.
    """
    if cell_dir in cache:
        return cache[cell_dir]

    throttle_csv = cell_dir / "throttle_stats.csv"
    if not throttle_csv.exists():
        log(f"  WARNING: no throttle_stats.csv found in {cell_dir}; "
            f"throttle deltas will be skipped for every trial in this cell.")
        cache[cell_dir] = None
        return None

    df = pd.read_csv(throttle_csv)
    df = df.set_index("run_id", drop=False)
    cache[cell_dir] = df
    return df


def compute_throttle_deltas(row: "pd.Series") -> dict:
    """
    Given one row of throttle_stats.csv, computes the after-minus-before
    delta for every (container alias, cgroup cpu.stat metric) pair.

    nr_periods, nr_throttled, and throttled_usec are all monotonically
    increasing cumulative counters read from cpu.stat (they count up from
    container start, not from trial start), so a plain after-minus-before
    difference over the "before"/"after" snapshots taken around one trial
    is what isolates the CPU throttling that happened *during* that trial.
    """
    deltas = {}
    for alias in THROTTLE_ALIASES:
        for suffix in THROTTLE_METRIC_SUFFIXES:
            before_col = f"{alias}_{suffix}_before"
            after_col = f"{alias}_{suffix}_after"
            deltas[f"{alias}_{suffix}_delta"] = row[after_col] - row[before_col]
    return deltas


def write_trial_throttle_deltas(run_id: str, throttle_df, dest: Path, log) -> None:
    """
    Looks up `run_id`'s row in the cell's throttle_stats.csv (already loaded
    by load_cell_throttle_stats) and writes a single-row throttle_deltas.csv
    into this trial's destination directory: one after-before delta column
    per (container, cpu.stat metric) pair, plus the original capture_status
    value for traceability.

    Skips (with a logged warning) rather than raising when throttle data is
    unavailable or ambiguous for this trial, matching this script's existing
    per-trial failure handling for individual pieces of output.
    """
    if throttle_df is None:
        log("    SKIPPED throttle deltas (no throttle_stats.csv for this cell)")
        return

    if run_id not in throttle_df.index:
        log(f"    WARNING: no throttle_stats.csv row found for run_id={run_id}; skipping throttle deltas.")
        return

    row = throttle_df.loc[run_id]
    # .loc returns a DataFrame instead of a Series if run_id matched more
    # than one row (e.g. throttle_stats.csv was hand-edited or a trial was
    # re-run and appended a duplicate row). Guard explicitly rather than
    # silently computing deltas against a row of the wrong shape.
    if isinstance(row, pd.DataFrame):
        log(f"    WARNING: {len(row)} duplicate throttle_stats.csv rows found for "
            f"run_id={run_id}; skipping throttle deltas.")
        return

    capture_status = row.get("capture_status", "UNKNOWN")
    if capture_status != "CAPTURE_SUCCEEDED":
        log(f"    WARNING: capture_status='{capture_status}' for run_id={run_id}; "
            f"writing throttle deltas anyway -- verify before trusting them.")

    deltas = compute_throttle_deltas(row)
    deltas["run_id"] = run_id
    deltas["capture_status"] = capture_status

    ordered_cols = (
        ["run_id"]
        + [f"{alias}_{suffix}_delta" for alias in THROTTLE_ALIASES for suffix in THROTTLE_METRIC_SUFFIXES]
        + ["capture_status"]
    )
    out_path = dest / "throttle_deltas.csv"
    pd.DataFrame([deltas])[ordered_cols].to_csv(out_path, index=False)
    log(f"    Wrote {out_path}")


def process_trial(trial_dir: Path, dest: Path, extract_script: Path, throttle_cache: dict, log):
    """
    Runs the full per-trial reorg step:
      1. pcap-derived metrics via extract_stream_metrics.py (fatal on failure
         -- raises RuntimeError, caught per-trial by the caller)
      2. container_stats/ copy (logs + skips on failure)
      3. throttle-delta computation from the cell's throttle_stats.csv
         (logs + skips on failure)

    Only step 1 is fatal: a missing container_stats/ dir or an unmatched
    throttle row for one trial shouldn't block that trial's pcap metrics,
    which is the one output that is genuinely uninterpretable if partially
    produced.
    """
    dest.mkdir(parents=True, exist_ok=True)

    pcap_metrics_csv = dest / "pcap_stream_metrics.csv"
    cmd = [
        sys.executable, str(extract_script),
        str(trial_dir),
        "--output", str(pcap_metrics_csv),
    ]
    log(f"    Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        stderr_tail = "\n".join(result.stderr.strip().splitlines()[-15:])
        raise RuntimeError(
            f"extract_stream_metrics.py exited {result.returncode} for {trial_dir}\n"
            f"--- stderr (tail) ---\n{stderr_tail}"
        )

    copy_container_stats(trial_dir, dest, log)

    cell_dir = trial_dir.parent
    throttle_df = load_cell_throttle_stats(cell_dir, throttle_cache, log)
    write_trial_throttle_deltas(trial_dir.name, throttle_df, dest, log)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("collection_dir", type=str,
                         help="Absolute path to a collection directory (cell-first layout)")
    parser.add_argument("--output", type=str, default=None,
                         help="Path to the output directory (default: <collection_dir>_by_cell, as a sibling)")
    parser.add_argument("--force", action="store_true",
                         help="Reprocess trials even if their outputs already exist, and allow running "
                              "into an existing (non-empty) output directory.")
    parser.add_argument("--extract-script", type=str, default=None,
                         help="Path to extract_stream_metrics.py (default: looked for alongside this script)")
    args = parser.parse_args()

    collection_dir = Path(args.collection_dir).expanduser().resolve()
    if not collection_dir.is_dir():
        die(f"{collection_dir} is not a directory.")

    extract_script = (Path(args.extract_script).expanduser().resolve()
                      if args.extract_script else default_extract_script())
    if not extract_script.is_file():
        die(f"extract_stream_metrics.py not found at {extract_script}. "
            f"Pass --extract-script /path/to/extract_stream_metrics.py.")

    output_dir = (Path(args.output).expanduser().resolve() if args.output
                  else collection_dir.parent / f"{collection_dir.name}_by_cell")

    if output_dir.exists() and any(output_dir.iterdir()) and not args.force:
        die(f"{output_dir} already exists and is non-empty. "
            f"Remove it, choose a different --output, or pass --force to continue into it.")

    output_dir.mkdir(parents=True, exist_ok=True)

    # Log file is opened (and flushed after every line) rather than built up in
    # memory and written once at the end, so a partial log survives even if the
    # script is interrupted partway through a large collection.
    log_path = output_dir / "_reorg_log.txt"
    log_file = open(log_path, "w")

    def log(msg: str = "") -> None:
        print(msg)
        log_file.write(msg + "\n")
        log_file.flush()

    try:
        log(f"reorg_by_cell.py log -- {datetime.datetime.now().isoformat()}")
        log(f"collection_dir: {collection_dir}")
        log(f"output_dir:     {output_dir}")
        log(f"extract_script: {extract_script}")
        log(f"force:          {args.force}")
        log("")

        trials = find_trials(collection_dir, log)
        if not trials:
            log(f"FATAL: no trial directories found under {collection_dir}. Check the path and layout.")
            sys.exit(1)

        cell_count = len(set(cell for cell, _, _ in trials))
        log(f"Found {len(trials)} trial directorie(s) across {cell_count} cell(s).")
        log("")

        processed, skipped, failed = 0, 0, []
        # Caches each cell's throttle_stats.csv the first time it's needed,
        # so it's read from disk once per cell rather than once per trial.
        throttle_cache: dict = {}

        for cell_name, rep_number, trial_dir in trials:
            dest = output_dir / cell_name / f"rep_{rep_number}"
            log(f"[{cell_name} / rep_{rep_number}] trial_dir={trial_dir}")

            if not args.force and trial_already_done(dest):
                log("    SKIPPED (already has pcap_stream_metrics.csv, throttle_deltas.csv, and container_stats/)")
                skipped += 1
                log("")
                continue

            try:
                process_trial(trial_dir, dest, extract_script, throttle_cache, log)
                log(f"    OK -> {dest}")
                processed += 1
            except Exception as e:
                log(f"    FAILED: {e}")
                failed.append((trial_dir, str(e)))

            log("")

        log("=" * 70)
        log(f"Done. processed={processed} skipped={skipped} failed={len(failed)} total={len(trials)}")
        if failed:
            log("Failed trials (any partial output left in place under output_dir):")
            for trial_dir, reason in failed:
                log(f"  - {trial_dir}: {reason.splitlines()[0]}")
    finally:
        log_file.close()

    print(f"\nLog written to {log_path}")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()