#!/usr/bin/env python3
"""
reorg_by_cell.py

Reorganizes a trial collection directory into a sibling directory
containing ONLY the derived per-repetition analysis output
(pcap_stream_metrics.csv, fragmentation_summary.csv, throttle_deltas.csv,
and the container_stats/ CPU-mem-network CSVs) for every trial, in the
same cell -> repetition layout as the original.

Expected input layout (as produced by run_matrix.sh / run_trial.sh):

    COLLECTION_DIR/
      <cell_name>/
        throttle_stats.csv          # one row per trial in this cell
        <cell_name>_rep<N>/
          capture.pcap
          keylogs/
          locust/requests/worker_*.csv
          container_stats/
            locust_cpu_matrix_<run_id>.csv
            nginx_cpu_matrix_<run_id>.csv
            router_cpu_matrix_<run_id>.csv
          ...

Output layout (default: a sibling directory named "<COLLECTION_DIR>_by_cell"):

    COLLECTION_DIR_by_cell/
      <cell_name>/
        rep_<N>/
          pcap_stream_metrics.csv
          fragmentation_summary.csv
          throttle_deltas.csv
          container_stats/
            locust_cpu_matrix_<run_id>.csv
            nginx_cpu_matrix_<run_id>.csv
            router_cpu_matrix_<run_id>.csv

For each trial directory, this script invokes extract_stream_metrics.py,
pointing its --output flag directly at the new pcap_stream_metrics.csv
location. extract_stream_metrics.py always writes fragmentation_summary.csv
into the original trial directory (it has no --output flag for that file),
so this script copies it into the new location afterward rather than
relying on the subprocess to place it there directly. The container_stats/
files are copied over as-is, unmodified -- they need no extraction step,
just relocation alongside the derived per-stream data. This script also
invokes compute_throttle_deltas.py per trial, pointing it at the SOURCE
cell's shared throttle_stats.csv and letting its own --output flag write
throttle_deltas.csv directly into the new per-trial location (no separate
copy step needed there, unlike fragmentation_summary.csv). Keylog material
is used only through temporary files and is not retained in either
directory.

Raw trial data (capture.pcap, keylogs/, locust/requests/*.csv) is left
in place under COLLECTION_DIR and is NOT duplicated into the new tree.

A failed trial (nonzero exit from extract_stream_metrics.py) intentionally
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
    python3 reorg_by_cell.py /absolute/path/to/COLLECTION_DIR --extract-script /path/to/extract_stream_metrics.py
    python3 reorg_by_cell.py /absolute/path/to/COLLECTION_DIR --throttle-deltas-script /path/to/compute_throttle_deltas.py

Requires: extract_stream_metrics.py and compute_throttle_deltas.py
(and, transitively, tshark + pandas).
"""

import argparse
import datetime
import re
import shutil
import subprocess
import sys
from pathlib import Path

TRIAL_DIR_RE_TEMPLATE = r"^{cell_name}_rep(\d+)$"


def die(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def default_extract_script() -> Path:
    """extract_stream_metrics.py is expected to live alongside this script."""
    return Path(__file__).resolve().parent / "extract_stream_metrics.py"


def default_throttle_deltas_script() -> Path:
    """compute_throttle_deltas.py is expected to live alongside this script."""
    return Path(__file__).resolve().parent / "compute_throttle_deltas.py"


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
    A trial counts as already-processed only when ALL of its derived
    outputs are present: the per-stream CSV, the trial-wide fragmentation
    summary, the per-trial throttle deltas, and the copied container_stats
    directory. Requiring all four (rather than just the CSV) means a run
    that was interrupted partway through process_trial() -- e.g. after the
    CSV was written but before a later step ran -- will be reprocessed on
    a later pass, instead of being silently treated as complete with
    files missing.
    """
    if not (dest / "pcap_stream_metrics.csv").exists():
        return False
    if not (dest / "fragmentation_summary.csv").exists():
        return False
    if not (dest / "throttle_deltas.csv").exists():
        return False
    container_stats_dir = dest / "container_stats"
    return container_stats_dir.is_dir() and any(container_stats_dir.iterdir())


def copy_container_stats(trial_dir: Path, dest: Path):
    """
    Copies every file under trial_dir/container_stats/ (the per-second
    CPU/memory/network-IO CSVs for oqs-locust, oqs-nginx, and router,
    written by run_trial.sh's background monitor) into
    dest/container_stats/.

    Copies whatever files are present rather than hardcoding the three
    filenames run_trial.sh currently produces (each of which embeds the
    run_id) -- so this doesn't need a matching edit here if that naming
    convention or the set of monitored containers ever changes.
    """
    source_dir = trial_dir / "container_stats"
    if not source_dir.is_dir():
        raise RuntimeError(f"{source_dir} not found -- expected container CPU/mem/net-IO stats.")

    stat_files = sorted(p for p in source_dir.iterdir() if p.is_file())
    if not stat_files:
        raise RuntimeError(f"{source_dir} exists but contains no files.")

    dest_dir = dest / "container_stats"
    dest_dir.mkdir(parents=True, exist_ok=True)
    for f in stat_files:
        shutil.copy2(f, dest_dir / f.name)


def process_trial(trial_dir: Path, dest: Path, extract_script: Path, throttle_deltas_script: Path, log):
    """
    Runs extract_stream_metrics.py and compute_throttle_deltas.py for one
    trial, then copies over the outputs neither script places in `dest`
    on its own (fragmentation_summary.csv) or produces at all
    (container_stats/). Raises RuntimeError with a descriptive message
    on failure at any step; the caller catches this per-trial so one bad
    trial doesn't abort the whole collection.
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

    # extract_stream_metrics.py always writes fragmentation_summary.csv
    # into the SOURCE trial directory (it has no --output flag for this
    # file, unlike pcap_stream_metrics.csv) -- so it has to be copied
    # into dest explicitly rather than relying on --output to place it
    # there. A successful subprocess run above should always have
    # (re)written this file, so its absence here indicates something
    # unexpected (e.g. a version mismatch with an older extract script)
    # rather than a normal failure mode, and is worth surfacing as such.
    source_fragmentation_csv = trial_dir / "fragmentation_summary.csv"
    if not source_fragmentation_csv.exists():
        raise RuntimeError(
            f"extract_stream_metrics.py exited 0 for {trial_dir} but did not "
            f"produce {source_fragmentation_csv} -- check that extract_script "
            f"is up to date."
        )
    shutil.copy2(source_fragmentation_csv, dest / "fragmentation_summary.csv")

    copy_container_stats(trial_dir, dest)

    # throttle_stats.csv is a PER-CELL file (trial_dir.parent, i.e. the
    # source cell directory -- one level up from the individual trial
    # directories), holding one row per trial. compute_throttle_deltas.py
    # is pointed at it explicitly rather than relying on its own default
    # (<trial_dir>/../throttle_stats.csv), since --throttle-csv here means
    # the SOURCE cell dir, which happens to equal that default -- being
    # explicit keeps this correct even if reorg_by_cell.py's own directory
    # assumptions ever change. Unlike fragmentation_summary.csv, this
    # script supports --output directly, so no separate copy step is
    # needed afterward.
    throttle_deltas_csv = dest / "throttle_deltas.csv"
    throttle_cmd = [
        sys.executable, str(throttle_deltas_script),
        str(trial_dir),
        "--throttle-csv", str(trial_dir.parent / "throttle_stats.csv"),
        "--output", str(throttle_deltas_csv),
    ]
    log(f"    Running: {' '.join(throttle_cmd)}")
    throttle_result = subprocess.run(throttle_cmd, capture_output=True, text=True)
    if throttle_result.returncode != 0:
        stderr_tail = "\n".join(throttle_result.stderr.strip().splitlines()[-15:])
        raise RuntimeError(
            f"compute_throttle_deltas.py exited {throttle_result.returncode} for {trial_dir}\n"
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
    parser.add_argument("--extract-script", type=str, default=None,
                         help="Path to extract_stream_metrics.py (default: looked for alongside this script)")
    parser.add_argument("--throttle-deltas-script", type=str, default=None,
                         help="Path to compute_throttle_deltas.py (default: looked for alongside this script)")
    args = parser.parse_args()

    collection_dir = Path(args.collection_dir).expanduser().resolve()
    if not collection_dir.is_dir():
        die(f"{collection_dir} is not a directory.")

    extract_script = (Path(args.extract_script).expanduser().resolve()
                      if args.extract_script else default_extract_script())
    if not extract_script.is_file():
        die(f"extract_stream_metrics.py not found at {extract_script}. "
            f"Pass --extract-script /path/to/extract_stream_metrics.py.")

    throttle_deltas_script = (Path(args.throttle_deltas_script).expanduser().resolve()
                               if args.throttle_deltas_script else default_throttle_deltas_script())
    if not throttle_deltas_script.is_file():
        die(f"compute_throttle_deltas.py not found at {throttle_deltas_script}. "
            f"Pass --throttle-deltas-script /path/to/compute_throttle_deltas.py.")

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
        log(f"throttle_deltas_script: {throttle_deltas_script}")
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
                log("    SKIPPED (already has pcap_stream_metrics.csv)")
                skipped += 1
                log("")
                continue

            try:
                process_trial(trial_dir, dest, extract_script, throttle_deltas_script, log)
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