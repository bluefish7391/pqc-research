#!/usr/bin/env python3
"""
reorg_by_cell.py

Reorganizes a trial collection directory into a sibling directory
containing ONLY the derived per-repetition analysis output
(combined_metrics.csv) for every trial, in the
same cell -> repetition layout as the original.

Expected input layout (as produced by run_matrix.sh / run_trial.sh):

    COLLECTION_DIR/
      <cell_name>/
        <cell_name>_rep<N>/
          capture.pcap
          keylogs/
          locust/requests/worker_*.csv
          ...

Output layout (default: a sibling directory named "<COLLECTION_DIR>_by_cell"):

    COLLECTION_DIR_by_cell/
      <cell_name>/
        rep_<N>/
          combined_metrics.csv

For each trial directory, this script invokes combine_trial_data.py
(unmodified) to perform the actual pcap/CSV join, pointing its --output
flag directly at the new location. Keylog material is used only through
temporary files and is not retained in either directory.

Raw trial data (capture.pcap, keylogs/, locust/requests/*.csv) is left
in place under COLLECTION_DIR and is NOT duplicated into the new tree.

A failed trial (nonzero exit from combine_trial_data.py) intentionally
leaves behind whatever partial output
already exists in its rep_<N>/ directory rather than being cleaned up.
This makes failures visible (an empty or half-populated rep_<N>/ folder)
and means a later re-run without --force will only reprocess trials that
are not yet fully complete (see `trial_already_done` below), rather than
redoing the whole collection.

Usage:
    python3 reorg_by_cell.py /absolute/path/to/COLLECTION_DIR
    python3 reorg_by_cell.py /absolute/path/to/COLLECTION_DIR --output /some/other/dir
    python3 reorg_by_cell.py /absolute/path/to/COLLECTION_DIR --force
    python3 reorg_by_cell.py /absolute/path/to/COLLECTION_DIR --combine-script /path/to/combine_trial_data.py

Requires: combine_trial_data.py (and, transitively, tshark + pandas).
"""

import argparse
import datetime
import re
import subprocess
import sys
from pathlib import Path

TRIAL_DIR_RE_TEMPLATE = r"^{cell_name}_rep(\d+)$"


def die(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def default_combine_script() -> Path:
    """combine_trial_data.py is expected to live alongside this script."""
    return Path(__file__).resolve().parent / "combine_trial_data.py"


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
    """A trial counts as already-processed when its derived CSV is present."""
    return (dest / "combined_metrics.csv").exists()


def process_trial(trial_dir: Path, dest: Path, combine_script: Path, log):
    """
    Runs combine_trial_data.py for one trial.
    Raises RuntimeError with a descriptive message on failure; the caller
    catches this per-trial so one bad trial doesn't abort the whole collection.
    """
    dest.mkdir(parents=True, exist_ok=True)

    combined_csv = dest / "combined_metrics.csv"
    cmd = [
        sys.executable, str(combine_script),
        str(trial_dir),
        "--output", str(combined_csv),
    ]
    log(f"    Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        stderr_tail = "\n".join(result.stderr.strip().splitlines()[-15:])
        raise RuntimeError(
            f"combine_trial_data.py exited {result.returncode} for {trial_dir}\n"
            f"--- stderr (tail) ---\n{stderr_tail}"
        )

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("collection_dir", type=str,
                         help="Absolute path to a collection directory (cell-first layout)")
    parser.add_argument("--output", type=str, default=None,
                         help="Path to the output directory (default: <collection_dir>_by_cell, as a sibling)")
    parser.add_argument("--force", action="store_true",
                         help="Reprocess trials even if their outputs already exist, and allow running "
                              "into an existing (non-empty) output directory.")
    parser.add_argument("--combine-script", type=str, default=None,
                         help="Path to combine_trial_data.py (default: looked for alongside this script)")
    args = parser.parse_args()

    collection_dir = Path(args.collection_dir).expanduser().resolve()
    if not collection_dir.is_dir():
        die(f"{collection_dir} is not a directory.")

    combine_script = (Path(args.combine_script).expanduser().resolve()
                       if args.combine_script else default_combine_script())
    if not combine_script.is_file():
        die(f"combine_trial_data.py not found at {combine_script}. "
            f"Pass --combine-script /path/to/combine_trial_data.py.")

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
        log(f"combine_script: {combine_script}")
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

        for cell_name, rep_number, trial_dir in trials:
            dest = output_dir / cell_name / f"rep_{rep_number}"
            log(f"[{cell_name} / rep_{rep_number}] trial_dir={trial_dir}")

            if not args.force and trial_already_done(dest):
                log("    SKIPPED (already has combined_metrics.csv)")
                skipped += 1
                log("")
                continue

            try:
                process_trial(trial_dir, dest, combine_script, log)
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