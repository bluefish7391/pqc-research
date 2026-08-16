#!/usr/bin/env python3
"""Plot per-request latency across Locust worker request CSVs.

Given an absolute path to a trial directory containing
``locust/requests/worker_*_requests.csv`` files, this script computes request duration as:

    duration_ms = (end_time_ns - start_time_ns) / 1e6

and plots a scatter chart with:
  - x-axis: seconds since the first observed request start
  - y-axis: request duration in milliseconds

The chart is rendered as one combined figure with one trace per worker file.
"""

import argparse
import csv
import math
import sys
from pathlib import Path


# Histogram bucket sizes (in seconds) used for completed-request density plots.
HISTOGRAM_BUCKET_SIZES_S = [0.01, 0.05, 0.1, 1]


def resolve_trial_dir(trial_dir_arg: str) -> Path:
    path = Path(trial_dir_arg)
    if not path.is_absolute():
        sys.exit(f"ERROR: trial directory must be an absolute path: {trial_dir_arg}")

    trial_dir = path.resolve()
    if not trial_dir.is_dir():
        sys.exit(f"ERROR: trial directory not found: {trial_dir}")

    requests_dir = trial_dir / "locust" / "requests"
    if not requests_dir.is_dir():
        sys.exit(f"ERROR: requests directory not found under trial directory: {requests_dir}")
    return requests_dir


def discover_worker_files(requests_dir: Path, expected_workers: int):
    worker_files = sorted(requests_dir.glob("worker_*_requests.csv"))
    if not worker_files:
        sys.exit(
            "ERROR: no worker request CSV files found with pattern "
            f"worker_*_requests.csv under {requests_dir}"
        )

    if len(worker_files) < expected_workers:
        print(
            f"WARNING: expected at least {expected_workers} worker files, found {len(worker_files)}",
            file=sys.stderr,
        )

    return worker_files


def worker_label_from_path(worker_file: Path) -> str:
    name = worker_file.name
    prefix = "worker_"
    suffix = "_requests.csv"
    if name.startswith(prefix) and name.endswith(suffix):
        return name[len(prefix) : -len(suffix)]
    return name


def parse_worker_rows(worker_file: Path):
    parsed_rows = []
    skipped_rows = 0

    with open(worker_file, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                start_ns = int(row["start_time_ns"])
                end_ns = int(row["end_time_ns"])
            except (KeyError, ValueError, TypeError):
                skipped_rows += 1
                continue

            parsed_rows.append(
                {
                    "start_time_ns": start_ns,
                    "end_time_ns": end_ns,
                    "success": row.get("success", ""),
                }
            )

    return parsed_rows, skipped_rows


def build_plot_points(worker_rows, success_only: bool):
    all_rows = []
    skip_summary = []

    for label, rows, skipped in worker_rows:
        if skipped:
            skip_summary.append((label, skipped))

        for row in rows:
            if success_only and row["success"] != "False":
                continue

            duration_ns = row["end_time_ns"] - row["start_time_ns"]
            if duration_ns < 0:
                continue

            all_rows.append(
                {
                    "worker": label,
                    "start_time_ns": row["start_time_ns"],
                    "end_time_ns": row["end_time_ns"],
                    "duration_ms": duration_ns / 1_000_000,
                }
            )

    if not all_rows:
        sys.exit("ERROR: no valid request rows to plot after parsing/filtering")

    min_start_ns = min(row["start_time_ns"] for row in all_rows)
    for row in all_rows:
        row["relative_start_s"] = (row["start_time_ns"] - min_start_ns) / 1_000_000_000
        row["relative_end_s"] = (row["end_time_ns"] - min_start_ns) / 1_000_000_000

    return all_rows, skip_summary


def percentile(values, pct):
    """Nearest-rank style percentile using rounded index on sorted values."""
    if not values:
        return None

    ordered = sorted(values)
    k = max(0, min(len(ordered) - 1, round(pct / 100 * (len(ordered) - 1))))
    return ordered[k]


def compute_trial_percentiles(points):
    durations_ms = [row["duration_ms"] for row in points]
    return {
        "p50": percentile(durations_ms, 50),
        "p90": percentile(durations_ms, 90),
        "p99": percentile(durations_ms, 99),
    }


def print_trial_percentiles(points):
    percentiles = compute_trial_percentiles(points)
    for label in ("p50", "p90", "p99"):
        value = percentiles[label]
        value_str = f"{value:.3f}" if value is not None and math.isfinite(value) else "n/a"
        print(f"{label.upper()}: {value_str} ms")


def _format_bucket_label(bucket_size_s: float) -> str:
    bucket_ms = bucket_size_s * 1000
    if float(bucket_ms).is_integer():
        return f"{int(bucket_ms)}ms"
    return f"{bucket_ms:g}ms"


def render_scatter(points, output_html: str | None, histogram_bucket_sizes_s=None):
    try:
        import plotly.graph_objects as go
        from plotly.subplots import make_subplots
    except ImportError:
        sys.exit(
            "ERROR: plotly is required to render the scatter plot. "
            "Install it with: pip install plotly"
        )

    if histogram_bucket_sizes_s is None:
        histogram_bucket_sizes_s = HISTOGRAM_BUCKET_SIZES_S

    valid_bucket_sizes = [size for size in histogram_bucket_sizes_s if size > 0]
    if not valid_bucket_sizes:
        sys.exit("ERROR: at least one positive histogram bucket size is required")

    workers = sorted({row["worker"] for row in points})
    histogram_rows = len(valid_bucket_sizes)
    total_rows = histogram_rows + 1
    histogram_row_height = 0.22 / histogram_rows
    row_heights = [histogram_row_height] * histogram_rows + [0.78]

    fig = make_subplots(
        rows=total_rows,
        cols=1,
        shared_xaxes=True,
        row_heights=row_heights,
        vertical_spacing=0.03,
    )

    for row_idx, bucket_size_s in enumerate(valid_bucket_sizes, start=1):
        bucket_label = _format_bucket_label(bucket_size_s)
        fig.add_trace(
            go.Histogram(
                x=[row["relative_end_s"] for row in points],
                xbins={"size": bucket_size_s},
                name=f"completed_requests_per_{bucket_label}",
                marker={"color": "#666666"},
                hovertemplate="completed=%{y}<br>t=%{x:.3f}s<extra></extra>",
            ),
            row=row_idx,
            col=1,
        )
        fig.update_yaxes(
            title_text=f"Completed Requests per {bucket_label} Bucket",
            row=row_idx,
            col=1,
        )

    scatter_row = total_rows
    for worker in workers:
        worker_points = [row for row in points if row["worker"] == worker]
        fig.add_trace(
            go.Scatter(
                x=[row["relative_start_s"] for row in worker_points],
                y=[row["duration_ms"] for row in worker_points],
                mode="markers",
                name=f"worker_{worker}",
                marker={"size": 5},
                hovertemplate=(
                    "worker=%{customdata}<br>"
                    "t=%{x:.6f}s<br>"
                    "duration=%{y:.3f}ms<extra></extra>"
                ),
                customdata=[worker] * len(worker_points),
            ),
            row=scatter_row,
            col=1,
        )

    fig.update_yaxes(title_text="Request Duration (ms)", row=scatter_row, col=1)
    fig.update_xaxes(title_text="Time Since First Request Start (s)", row=scatter_row, col=1)

    fig.update_layout(
        title="Request Duration Scatter by Worker",
        bargap=0.05,
    )

    if output_html:
        fig.write_html(output_html)
        print(f"Wrote plot HTML: {output_html}")
    else:
        fig.show()


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Plot per-request duration scatter from a trial directory containing "
            "locust/requests/worker_*_requests.csv files."
        )
    )
    parser.add_argument("trial_dir", help="Absolute path to the trial directory containing locust/requests.")
    parser.add_argument(
        "--expected-workers",
        type=int,
        default=4,
        help="Warn if fewer worker CSV files than this count are found (default: 4).",
    )
    parser.add_argument(
        "--success-only",
        action="store_true",
        help=(
            "Include only rows where success == 'False' (this dataset uses inverted "
            "success semantics where 'False' means request succeeded)."
        ),
    )
    parser.add_argument(
        "--output-html",
        default=None,
        help="Optional output HTML path. If omitted, opens an interactive plot window.",
    )
    args = parser.parse_args()

    requests_dir = resolve_trial_dir(args.trial_dir)
    worker_files = discover_worker_files(requests_dir, args.expected_workers)

    worker_rows = []
    for worker_file in worker_files:
        label = worker_label_from_path(worker_file)
        rows, skipped = parse_worker_rows(worker_file)
        worker_rows.append((label, rows, skipped))

    points, skip_summary = build_plot_points(worker_rows, success_only=args.success_only)
    for worker_label, skipped_count in skip_summary:
        print(f"WARNING: skipped {skipped_count} malformed rows in worker_{worker_label}", file=sys.stderr)

    print_trial_percentiles(points)

    output_html = str(Path(args.output_html).resolve()) if args.output_html else None
    render_scatter(points, output_html)


if __name__ == "__main__":
    main()