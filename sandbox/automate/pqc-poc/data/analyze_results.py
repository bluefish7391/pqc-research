"""
analyze_results.py — KD Protocol Benchmarking PoC: visualization & analysis

Loads all results_<kem>_u<N>_stats.csv and results_<kem>_u<N>_stats_history.csv
files from a results directory, tags each by KEM group and user level (parsed
from the filename), and produces:

  1. Distribution plots (histogram + box) of response time per KEM group,
     faceted by user level — check shape/skew before assuming normality.
  2. Time-series plots of response time across each run's duration, from
     the _stats_history.csv files — check for startup transients or drift.
  3. Load-response curves: median and p95 response time vs. user level,
     one line per KEM group — the main "does the gap widen under load" view.
  4. Achieved throughput (Requests/s) vs. user level, per KEM group — confirms
     what load was actually achieved, since this is a closed-loop client.

Usage:
    python3 analyze_results.py --results-dir results --out-dir figures

Run_id parsing assumes filenames of the form:
    results_<kem_label>_u<users>_stats.csv
    results_<kem_label>_u<users>_stats_history.csv
e.g. results_classical_u10_stats.csv -> kem_label="classical", users=10

If your filenames differ, adjust RUN_ID_PATTERN below.
"""

import argparse
import re
import sys
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Matches: results_<kem>_u<users>_stats.csv  or  results_<kem>_u<users>_stats_history.csv
RUN_ID_PATTERN = re.compile(r"results_(?P<kem>[a-zA-Z0-9\-]+)_u(?P<users>\d+)_(?P<kind>stats|stats_history)\.csv$")

sns.set_theme(style="whitegrid")


def discover_files(results_dir: Path):
    """Find and classify all matching CSVs in results_dir."""
    stats_files = []
    history_files = []
    unmatched = []

    for f in sorted(results_dir.glob("*.csv")):
        m = RUN_ID_PATTERN.search(f.name)
        if not m:
            unmatched.append(f.name)
            continue
        kem = m.group("kem")
        users = int(m.group("users"))
        kind = m.group("kind")
        if kind == "stats":
            stats_files.append((f, kem, users))
        else:
            history_files.append((f, kem, users))

    if unmatched:
        print(f"WARNING: {len(unmatched)} CSV(s) did not match the expected naming "
              f"pattern and were skipped: {unmatched}", file=sys.stderr)

    return stats_files, history_files


def load_stats(stats_files):
    """Load all *_stats.csv files, keep only the Aggregated row, tag with kem/users."""
    rows = []
    for path, kem, users in stats_files:
        df = pd.read_csv(path)
        # Locust's stats CSV has a per-endpoint row and an "Aggregated" row.
        # We want only the Aggregated row since there's one endpoint anyway.
        agg = df[df["Name"].str.strip().str.lower() == "aggregated"]
        if agg.empty:
            print(f"WARNING: no 'Aggregated' row found in {path.name}, skipping.", file=sys.stderr)
            continue
        row = agg.iloc[0].to_dict()
        row["kem_group"] = kem
        row["users"] = users
        row["run_id"] = f"{kem}_u{users}"
        rows.append(row)
    if not rows:
        raise ValueError("No valid stats rows loaded. Check results_dir and filename pattern.")
    return pd.DataFrame(rows)


def load_history(history_files):
    """Load all *_stats_history.csv files, tag with kem/users, add elapsed-time column."""
    frames = []
    for path, kem, users in history_files:
        df = pd.read_csv(path)
        df = df[df["Name"].str.strip().str.lower() == "aggregated"].copy()
        if df.empty:
            print(f"WARNING: no 'Aggregated' rows found in {path.name}, skipping.", file=sys.stderr)
            continue
        df["kem_group"] = kem
        df["users"] = users
        df["run_id"] = f"{kem}_u{users}"
        # Elapsed seconds from start of this specific run, for overlaying runs
        # of different absolute start times on the same x-axis.
        df["elapsed_s"] = df["Timestamp"] - df["Timestamp"].min()
        frames.append(df)
    if not frames:
        raise ValueError("No valid history rows loaded. Check results_dir and filename pattern.")
    return pd.concat(frames, ignore_index=True)


def plot_distributions(stats_df, history_df, out_dir: Path):
    """Histogram of per-snapshot response times, faceted by user level, colored by KEM group.

    Uses history_df (many samples per run) rather than stats_df (one row per run)
    since a single summary number per run can't show distribution shape.
    """
    g = sns.FacetGrid(history_df, col="users", col_wrap=2, hue="kem_group",
                       height=3.5, aspect=1.3, sharex=False)
    g.map(sns.histplot, "Total Average Response Time", kde=True, alpha=0.5, bins=20)
    g.add_legend(title="KEM group")
    g.set_axis_labels("Response time (ms, snapshot avg)", "Count")
    g.figure.suptitle("Response time distribution by KEM group, faceted by user level", y=1.02)
    g.figure.savefig(out_dir / "distributions_by_load.png", dpi=150, bbox_inches="tight")
    plt.close(g.figure)

    # Box plot view as a complementary, more compact summary of the same thing
    fig, ax = plt.subplots(figsize=(8, 5))
    sns.boxplot(data=history_df, x="users", y="Total Average Response Time", hue="kem_group", ax=ax)
    ax.set_xlabel("Concurrent users (-u)")
    ax.set_ylabel("Response time (ms, snapshot avg)")
    ax.set_title("Response time spread by KEM group and load level")
    fig.savefig(out_dir / "boxplot_by_load.png", dpi=150, bbox_inches="tight")
    plt.close(fig)


def plot_time_series(history_df, out_dir: Path):
    """Response time over each run's elapsed duration — check for startup transients/drift."""
    g = sns.FacetGrid(history_df, col="users", col_wrap=2, hue="kem_group",
                       height=3.5, aspect=1.3, sharey=False)
    g.map(sns.lineplot, "elapsed_s", "Total Average Response Time", marker="o", markersize=3)
    g.add_legend(title="KEM group")
    g.set_axis_labels("Elapsed time in run (s)", "Cumulative avg response time (ms)")
    g.figure.suptitle("Response time over run duration, faceted by user level", y=1.02)
    g.figure.savefig(out_dir / "time_series_by_run.png", dpi=150, bbox_inches="tight")
    plt.close(g.figure)


def plot_load_response_curve(stats_df, out_dir: Path):
    """Median and p95 response time vs. user level, one line per KEM group."""
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    for metric, ax, title in [
        ("Median Response Time", axes[0], "Median response time vs. load"),
        ("95%", axes[1], "p95 response time vs. load"),
    ]:
        for kem, sub in stats_df.groupby("kem_group"):
            sub = sub.sort_values("users")
            ax.plot(sub["users"], sub[metric], marker="o", label=kem)
        ax.set_xlabel("Concurrent users (-u)")
        ax.set_ylabel("Response time (ms)")
        ax.set_title(title)
        ax.legend(title="KEM group")

    fig.suptitle("Load–response curves by KEM group")
    fig.tight_layout()
    fig.savefig(out_dir / "load_response_curve.png", dpi=150, bbox_inches="tight")
    plt.close(fig)


def plot_achieved_throughput(stats_df, out_dir: Path):
    """Achieved requests/sec vs. user level — confirms what load was actually achieved.

    Important because this client is closed-loop (sequential per user, with
    wait_time between requests) — requested concurrency (-u) is NOT the same
    as achieved throughput. If the two KEM groups achieve different actual
    rates at the same -u, that's a confound you need to know about before
    comparing their latency numbers directly.
    """
    fig, ax = plt.subplots(figsize=(7, 5))
    for kem, sub in stats_df.groupby("kem_group"):
        sub = sub.sort_values("users")
        ax.plot(sub["users"], sub["Requests/s"], marker="o", label=kem)
    ax.set_xlabel("Concurrent users (-u)")
    ax.set_ylabel("Achieved requests/sec")
    ax.set_title("Achieved throughput vs. requested concurrency")
    ax.legend(title="KEM group")
    fig.savefig(out_dir / "achieved_throughput.png", dpi=150, bbox_inches="tight")
    plt.close(fig)


def print_summary_table(stats_df):
    """Console summary table — quick numeric reference alongside the plots."""
    cols = ["kem_group", "users", "Request Count", "Requests/s",
            "Median Response Time", "Average Response Time", "95%", "99%"]
    available = [c for c in cols if c in stats_df.columns]
    summary = stats_df[available].sort_values(["kem_group", "users"])
    print("\n=== Summary table (one row per KEM group x user level) ===")
    print(summary.to_string(index=False))


def main():
    parser = argparse.ArgumentParser(description="Visualize KD protocol benchmark results.")
    parser.add_argument("--results-dir", type=Path, default=Path("results"),
                         help="Directory containing the Locust *_stats.csv and *_stats_history.csv files")
    parser.add_argument("--out-dir", type=Path, default=Path("figures"),
                         help="Directory to write output figures to")
    args = parser.parse_args()

    if not args.results_dir.exists():
        sys.exit(f"ERROR: results dir not found: {args.results_dir}")
    args.out_dir.mkdir(parents=True, exist_ok=True)

    stats_files, history_files = discover_files(args.results_dir)
    print(f"Found {len(stats_files)} stats files and {len(history_files)} stats_history files.")

    stats_df = load_stats(stats_files)
    history_df = load_history(history_files)

    # Persist the tagged, combined long-format data too — useful for any
    # follow-up statistical testing later, so you don't re-parse filenames.
    stats_df.to_csv(args.out_dir / "combined_stats.csv", index=False)
    history_df.to_csv(args.out_dir / "combined_stats_history.csv", index=False)

    print_summary_table(stats_df)

    plot_distributions(stats_df, history_df, args.out_dir)
    plot_time_series(history_df, args.out_dir)
    plot_load_response_curve(stats_df, args.out_dir)
    plot_achieved_throughput(stats_df, args.out_dir)

    print(f"\nFigures written to {args.out_dir.resolve()}")
    print("  - distributions_by_load.png")
    print("  - boxplot_by_load.png")
    print("  - time_series_by_run.png")
    print("  - load_response_curve.png")
    print("  - achieved_throughput.png")
    print("  - combined_stats.csv (tagged long-format data for further analysis)")
    print("  - combined_stats_history.csv (tagged long-format time series data)")


if __name__ == "__main__":
    main()