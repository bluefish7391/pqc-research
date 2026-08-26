#!/usr/bin/env python3
"""
reorg_pilot_by_cell.py

Reorganizes a pilot collection directory in sweep-first layout into a
cell-first sibling directory containing only derived per-repetition output
(pcap_stream_metrics.csv).

Expected pilot input layout:

    PILOT_DIR/
      sweep_<N>/
        <cell_name>_rep<M>/
          capture.pcap
          keylogs/
          locust/requests/worker_*.csv
          ...

Output layout (default: a sibling directory named "<PILOT_DIR>_by_cell"):

    PILOT_DIR_by_cell/
      <cell_name>/
        rep_<N>/
          pcap_stream_metrics.csv

Notes:
  - Output repetition index is taken from sweep_<N>, not from the trial
    directory suffix _rep<M>. In pilot data, _rep<M> may repeat or reset, while
    sweep numbers are unique.
  - Raw pilot files are not copied; only derived CSV output is written.
  - Failed trials leave partial output in place for visibility and resumability.

Usage:
    python3 reorg_pilot_by_cell.py /absolute/path/to/pilot_dir
    python3 reorg_pilot_by_cell.py /absolute/path/to/pilot_dir --output /some/other/dir
    python3 reorg_pilot_by_cell.py /absolute/path/to/pilot_dir --force
    python3 reorg_pilot_by_cell.py /absolute/path/to/pilot_dir --extract-script /path/to/extract_stream_metrics.py
"""

import argparse
import datetime
import re
import subprocess
import sys
from pathlib import Path

SWEEP_DIR_RE = re.compile(r"^sweep_(\d+)$")
TRIAL_DIR_RE = re.compile(r"^(?P<cell_name>.+)_rep\d+$")


def die(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def default_extract_script() -> Path:
    return Path(__file__).resolve().parent / "extract_stream_metrics.py"


def visible_subdirs(path: Path):
    return sorted(p for p in path.iterdir() if p.is_dir() and not p.name.startswith("."))


def find_trials(pilot_dir: Path, log):
    """
    Returns a list of tuples:
        (cell_name, repetition_number, trial_dir)

    repetition_number is the numeric suffix from sweep_<N>.
    """
    trials = []

    for sweep_dir in visible_subdirs(pilot_dir):
        sweep_match = SWEEP_DIR_RE.fullmatch(sweep_dir.name)
        if sweep_match is None:
            log(f"  WARNING: skipping non-sweep directory {sweep_dir}")
            continue

        repetition_number = int(sweep_match.group(1))
        found_any = False
        seen_cells = set()

        for trial_dir in visible_subdirs(sweep_dir):
            trial_match = TRIAL_DIR_RE.fullmatch(trial_dir.name)
            if trial_match is None:
                log(
                    f"  WARNING: skipping unexpected directory {trial_dir} "
                    "(does not match '<cell_name>_rep<N>')."
                )
                continue

            cell_name = trial_match.group("cell_name")
            if cell_name in seen_cells:
                log(
                    f"  WARNING: duplicate cell '{cell_name}' in {sweep_dir}; "
                    f"keeping only first trial encountered."
                )
                continue

            found_any = True
            seen_cells.add(cell_name)
            trials.append((cell_name, repetition_number, trial_dir))

        if not found_any:
            log(f"  WARNING: no trial directories found under {sweep_dir}")

    return trials


def trial_already_done(dest: Path) -> bool:
    return (dest / "pcap_stream_metrics.csv").exists()


def process_trial(trial_dir: Path, dest: Path, extract_script: Path, log):
    dest.mkdir(parents=True, exist_ok=True)

    pcap_metrics_csv = dest / "pcap_stream_metrics.csv"
    cmd = [
        sys.executable,
        str(extract_script),
        str(trial_dir),
        "--output",
        str(pcap_metrics_csv),
    ]
    log(f"    Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        stderr_tail = "\n".join(result.stderr.strip().splitlines()[-15:])
        raise RuntimeError(
            f"extract_stream_metrics.py exited {result.returncode} for {trial_dir}\n"
            f"--- stderr (tail) ---\n{stderr_tail}"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("pilot_dir", type=str, help="Absolute path to a pilot directory (sweep-first layout)")
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Path to the output directory (default: <pilot_dir>_by_cell, as a sibling)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Reprocess trials even if their outputs already exist, and allow running into an existing "
        "(non-empty) output directory.",
    )
    parser.add_argument(
        "--extract-script",
        type=str,
        default=None,
        help="Path to extract_stream_metrics.py (default: looked for alongside this script)",
    )
    args = parser.parse_args()

    pilot_dir = Path(args.pilot_dir).expanduser().resolve()
    if not pilot_dir.is_dir():
        die(f"{pilot_dir} is not a directory.")

    extract_script = Path(args.extract_script).expanduser().resolve() if args.extract_script else default_extract_script()
    if not extract_script.is_file():
        die(
            f"extract_stream_metrics.py not found at {extract_script}. "
            "Pass --extract-script /path/to/extract_stream_metrics.py."
        )

    output_dir = Path(args.output).expanduser().resolve() if args.output else pilot_dir.parent / f"{pilot_dir.name}_by_cell"

    if output_dir.exists() and any(output_dir.iterdir()) and not args.force:
        die(
            f"{output_dir} already exists and is non-empty. "
            "Remove it, choose a different --output, or pass --force to continue into it."
        )

    output_dir.mkdir(parents=True, exist_ok=True)

    log_path = output_dir / "_reorg_log.txt"
    log_file = open(log_path, "w")

    def log(msg: str = "") -> None:
        print(msg)
        log_file.write(msg + "\n")
        log_file.flush()

    failed = []
    try:
        log(f"reorg_pilot_by_cell.py log -- {datetime.datetime.now().isoformat()}")
        log(f"pilot_dir:      {pilot_dir}")
        log(f"output_dir:     {output_dir}")
        log(f"extract_script: {extract_script}")
        log(f"force:          {args.force}")
        log("")

        trials = find_trials(pilot_dir, log)
        if not trials:
            log(f"FATAL: no trial directories found under {pilot_dir}. Check the path and layout.")
            sys.exit(1)

        cell_count = len(set(cell for cell, _, _ in trials))
        repetition_count = len(set(rep for _, rep, _ in trials))
        log(f"Found {len(trials)} trial directorie(s) across {cell_count} cell(s) and {repetition_count} repetition(s).")
        log("")

        processed, skipped = 0, 0

        for cell_name, rep_number, trial_dir in trials:
            dest = output_dir / cell_name / f"rep_{rep_number}"
            log(f"[{cell_name} / rep_{rep_number}] trial_dir={trial_dir}")

            if not args.force and trial_already_done(dest):
                log("    SKIPPED (already has pcap_stream_metrics.csv)")
                skipped += 1
                log("")
                continue

            try:
                process_trial(trial_dir, dest, extract_script, log)
                log(f"    OK -> {dest}")
                processed += 1
            except Exception as exc:
                log(f"    FAILED: {exc}")
                failed.append((trial_dir, str(exc)))

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