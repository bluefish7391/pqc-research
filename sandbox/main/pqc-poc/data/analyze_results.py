"""
analyze_results.py — KD Protocol Benchmarking PoC: visualization & analysis

Loads all results_<kem>_u<N>[_lat<ms>ms_loss<pct>pct]_stats.csv and the
matching _stats_history.csv files from a results directory, tags each row by
KEM group, user level, latency, and loss (parsed from the filename), and
produces:

  1. Distribution plots (histogram + box) of response time per KEM group,
     faceted by user level — check shape/skew before assuming normality.
  2. Time-series plots of response time across each run's duration, from
     the _stats_history.csv files — check for startup transients or drift.
  3. Load-response curves: median and p95 response time vs. user level,
     one line per KEM group, at the baseline (0ms/0%) impairment level.
  4. Achieved throughput (Requests/s) vs. user level, per KEM group, at
     baseline impairment.
  5. Impairment heatmaps: latency x loss grid, color = response time
     (median and p95 side by side), one heatmap per KEM group x user level.
  6. Throughput-vs-impairment: achieved req/s as latency/loss increase,
     since packet loss can stall connections and silently reduce throughput.

Usage:
    python3 analyze_results.py --results-dir ./results --out-dir ./figures

Run_id parsing accepts two filename shapes, for backward compatibility with
result sets generated before network impairment was added:
    results_<kem>_u<users>_stats.csv                                  (no impairment tags -> latency=0, loss=0)
    results_<kem>_u<users>_lat<ms>ms_loss<pct>pct_stats.csv            (full 4D tag set)
e.g. results_hybrid_u10_lat25ms_loss1pct_stats.csv
     -> kem="hybrid", users=10, latency_ms=25, loss_pct=1

If your filenames differ, adjust RUN_ID_PATTERN below.
"""

import argparse
import re
import sys
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Matches both:
#   results_<kem>_u<users>_stats[.csv|_history.csv]
#   results_<kem>_u<users>_lat<ms>ms_loss<pct>pct_stats[.csv|_history.csv]
# The lat/loss group is optional (?:...)? so older 2D-only filenames still match.
RUN_ID_PATTERN = re.compile(
    r"results_(?P<kem>[a-zA-Z0-9\-]+)_u(?P<users>\d+)"
    r"(?:_lat(?P<latency>\d+)ms_loss(?P<loss>\d+(?:\.\d+)?)pct)?"
    r"_(?P<kind>stats|stats_history)\.csv$"
)

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
        # Missing lat/loss groups (older 2D filenames) default to 0/0 — i.e.
        # treated as the baseline/no-impairment condition.
        latency = int(m.group("latency")) if m.group("latency") is not None else 0
        loss = float(m.group("loss")) if m.group("loss") is not None else 0.0
        kind = m.group("kind")
        if kind == "stats":
            stats_files.append((f, kem, users, latency, loss))
        else:
            history_files.append((f, kem, users, latency, loss))

    if unmatched:
        print(f"WARNING: {len(unmatched)} CSV(s) did not match the expected naming "
              f"pattern and were skipped: {unmatched}", file=sys.stderr)

    return stats_files, history_files


def load_stats(stats_files):
    """Load all *_stats.csv files, keep only the Aggregated row, tag with kem/users/latency/loss."""
    rows = []
    for path, kem, users, latency, loss in stats_files:
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
        row["latency_ms"] = latency
        row["loss_pct"] = loss
        row["run_id"] = f"{kem}_u{users}_lat{latency}ms_loss{loss}pct"
        rows.append(row)
    if not rows:
        raise ValueError("No valid stats rows loaded. Check results_dir and filename pattern.")
    return pd.DataFrame(rows)


def load_history(history_files):
    """Load all *_stats_history.csv files, tag with kem/users/latency/loss, add elapsed-time column."""
    frames = []
    for path, kem, users, latency, loss in history_files:
        df = pd.read_csv(path)
        df = df[df["Name"].str.strip().str.lower() == "aggregated"].copy()
        if df.empty:
            print(f"WARNING: no 'Aggregated' rows found in {path.name}, skipping.", file=sys.stderr)
            continue
        df["kem_group"] = kem
        df["users"] = users
        df["latency_ms"] = latency
        df["loss_pct"] = loss
        df["run_id"] = f"{kem}_u{users}_lat{latency}ms_loss{loss}pct"
        # Elapsed seconds from start of this specific run, for overlaying runs
        # of different absolute start times on the same x-axis.
        df["elapsed_s"] = df["Timestamp"] - df["Timestamp"].min()
        frames.append(df)
    if not frames:
        raise ValueError("No valid history rows loaded. Check results_dir and filename pattern.")
    return pd.concat(frames, ignore_index=True)


def plot_distributions(stats_df, history_df, out_dir: Path):
    """Histogram of per-snapshot response times, faceted by user level, colored by KEM group.

    Restricted to baseline (0ms latency, 0% loss) runs only — mixing impaired
    and unimpaired runs into the same facet would blend two different
    populations into one misleading distribution.

    Uses history_df (many samples per run) rather than stats_df (one row per run)
    since a single summary number per run can't show distribution shape.
    """
    baseline = history_df[(history_df["latency_ms"] == 0) & (history_df["loss_pct"] == 0)]
    if baseline.empty:
        print("WARNING: no baseline (0ms/0%) runs found — skipping distribution plots.", file=sys.stderr)
        return

    g = sns.FacetGrid(baseline, col="users", col_wrap=2, hue="kem_group",
                       height=3.5, aspect=1.3, sharex=False)
    g.map(sns.histplot, "Total Average Response Time", kde=True, alpha=0.5, bins=20)
    g.add_legend(title="KEM group")
    g.set_axis_labels("Response time (ms, snapshot avg)", "Count")
    g.figure.suptitle("Response time distribution by KEM group, faceted by user level\n(baseline: 0ms latency, 0% loss)", y=1.04)
    g.figure.savefig(out_dir / "distributions_by_load.png", dpi=150, bbox_inches="tight")
    plt.close(g.figure)

    # Box plot view as a complementary, more compact summary of the same thing
    fig, ax = plt.subplots(figsize=(8, 5))
    sns.boxplot(data=baseline, x="users", y="Total Average Response Time", hue="kem_group", ax=ax)
    ax.set_xlabel("Concurrent users (-u)")
    ax.set_ylabel("Response time (ms, snapshot avg)")
    ax.set_title("Response time spread by KEM group and load level (baseline: 0ms/0% loss)")
    fig.savefig(out_dir / "boxplot_by_load.png", dpi=150, bbox_inches="tight")
    plt.close(fig)


def plot_time_series(history_df, out_dir: Path):
    """Response time over each run's elapsed duration — check for startup transients/drift.

    Restricted to baseline (0ms/0% loss) runs — same reasoning as plot_distributions.
    """
    baseline = history_df[(history_df["latency_ms"] == 0) & (history_df["loss_pct"] == 0)]
    if baseline.empty:
        print("WARNING: no baseline (0ms/0%) runs found — skipping time series plot.", file=sys.stderr)
        return

    g = sns.FacetGrid(baseline, col="users", col_wrap=2, hue="kem_group",
                       height=3.5, aspect=1.3, sharey=False)
    g.map(sns.lineplot, "elapsed_s", "Total Average Response Time", marker="o", markersize=3)
    g.add_legend(title="KEM group")
    g.set_axis_labels("Elapsed time in run (s)", "Cumulative avg response time (ms)")
    g.figure.suptitle("Response time over run duration, faceted by user level\n(baseline: 0ms latency, 0% loss)", y=1.04)
    g.figure.savefig(out_dir / "time_series_by_run.png", dpi=150, bbox_inches="tight")
    plt.close(g.figure)


def plot_load_response_curve(stats_df, out_dir: Path):
    """Median and p95 response time vs. user level, one line per KEM group, baseline impairment only."""
    baseline = stats_df[(stats_df["latency_ms"] == 0) & (stats_df["loss_pct"] == 0)]
    if baseline.empty:
        print("WARNING: no baseline (0ms/0%) runs found — skipping load-response curve.", file=sys.stderr)
        return

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    for metric, ax, title in [
        ("Median Response Time", axes[0], "Median response time vs. load"),
        ("95%", axes[1], "p95 response time vs. load"),
    ]:
        for kem, sub in baseline.groupby("kem_group"):
            sub = sub.sort_values("users")
            ax.plot(sub["users"], sub[metric], marker="o", label=kem)
        ax.set_xlabel("Concurrent users (-u)")
        ax.set_ylabel("Response time (ms)")
        ax.set_title(title)
        ax.legend(title="KEM group")

    fig.suptitle("Load–response curves by KEM group (baseline: 0ms latency, 0% loss)")
    fig.tight_layout()
    fig.savefig(out_dir / "load_response_curve.png", dpi=150, bbox_inches="tight")
    plt.close(fig)


def plot_achieved_throughput(stats_df, out_dir: Path):
    """Achieved requests/sec vs. user level — confirms what load was actually achieved.

    Restricted to baseline impairment, for the same reason as the other
    baseline-only plots above. Important because this client is closed-loop
    (sequential per user, with wait_time between requests) — requested
    concurrency (-u) is NOT the same as achieved throughput. If the two KEM
    groups achieve different actual rates at the same -u, that's a confound
    you need to know about before comparing their latency numbers directly.
    """
    baseline = stats_df[(stats_df["latency_ms"] == 0) & (stats_df["loss_pct"] == 0)]
    if baseline.empty:
        print("WARNING: no baseline (0ms/0%) runs found — skipping throughput-vs-load plot.", file=sys.stderr)
        return

    fig, ax = plt.subplots(figsize=(7, 5))
    for kem, sub in baseline.groupby("kem_group"):
        sub = sub.sort_values("users")
        ax.plot(sub["users"], sub["Requests/s"], marker="o", label=kem)
    ax.set_xlabel("Concurrent users (-u)")
    ax.set_ylabel("Achieved requests/sec")
    ax.set_title("Achieved throughput vs. requested concurrency (baseline: 0ms/0% loss)")
    ax.legend(title="KEM group")
    fig.savefig(out_dir / "achieved_throughput.png", dpi=150, bbox_inches="tight")
    plt.close(fig)


def plot_impairment_heatmaps(stats_df, out_dir: Path):
    """Latency x loss heatmap grid, color = response time. One PNG per
    KEM group x user level, median and p95 side by side (mirrors the
    side-by-side layout of plot_load_response_curve).

    Heatmaps are the natural fit for two fully-crossed categorical-ish
    axes (3 latency levels x 3 loss levels) — a line plot would need one
    line per loss level with latency on x (or vice versa), which works but
    buries the grid structure that a heatmap shows at a glance.
    """
    heatmap_dir = out_dir / "impairment_heatmaps"
    heatmap_dir.mkdir(parents=True, exist_ok=True)

    combos = stats_df[["kem_group", "users"]].drop_duplicates().sort_values(["kem_group", "users"])

    for _, combo in combos.iterrows():
        kem, users = combo["kem_group"], combo["users"]
        sub = stats_df[(stats_df["kem_group"] == kem) & (stats_df["users"] == users)]

        fig, axes = plt.subplots(1, 2, figsize=(13, 5))

        for metric, ax, title in [
            ("Median Response Time", axes[0], "Median response time (ms)"),
            ("95%", axes[1], "p95 response time (ms)"),
        ]:
            pivot = sub.pivot_table(index="loss_pct", columns="latency_ms", values=metric, aggfunc="mean")
            # Sort axes ascending so the grid reads naturally (0 at top-left
            # going down/right toward more severe impairment).
            pivot = pivot.sort_index(ascending=True).sort_index(axis=1, ascending=True)
            sns.heatmap(pivot, annot=True, fmt=".1f", cmap="rocket_r", ax=ax,
                        cbar_kws={"label": "ms"})
            ax.set_xlabel("Latency (ms)")
            ax.set_ylabel("Packet loss (%)")
            ax.set_title(title)

        fig.suptitle(f"Impairment heatmap — KEM: {kem}, users: {users}")
        fig.tight_layout()
        fname = f"heatmap_{kem}_u{users}.png"
        fig.savefig(heatmap_dir / fname, dpi=150, bbox_inches="tight")
        plt.close(fig)

    print(f"Wrote {len(combos)} heatmap(s) to {heatmap_dir}/")


def plot_throughput_vs_impairment(stats_df, out_dir: Path):
    """Achieved requests/sec as latency/loss increase.

    Packet loss in particular can cause retransmissions and stalled
    connections that silently reduce achieved throughput even at a fixed
    -u — this plot makes that visible rather than letting it hide inside
    the latency numbers alone. One panel per fixed user level, x-axis is
    loss%, one line per latency level, faceted/colored by KEM group via
    columns so all four show on one figure.
    """
    user_levels = sorted(stats_df["users"].unique())
    kem_groups = sorted(stats_df["kem_group"].unique())

    fig, axes = plt.subplots(len(kem_groups), len(user_levels),
                              figsize=(4 * len(user_levels), 4 * len(kem_groups)),
                              squeeze=False, sharey="row")

    for row, kem in enumerate(kem_groups):
        for col, users in enumerate(user_levels):
            ax = axes[row][col]
            sub = stats_df[(stats_df["kem_group"] == kem) & (stats_df["users"] == users)]
            for latency, sub2 in sub.groupby("latency_ms"):
                sub2 = sub2.sort_values("loss_pct")
                ax.plot(sub2["loss_pct"], sub2["Requests/s"], marker="o", label=f"{latency}ms")
            if row == 0:
                ax.set_title(f"users={users}")
            if col == 0:
                ax.set_ylabel(f"{kem}\nAchieved req/s")
            if row == len(kem_groups) - 1:
                ax.set_xlabel("Packet loss (%)")
            ax.legend(title="Latency", fontsize=8)

    fig.suptitle("Achieved throughput vs. packet loss, by latency level, KEM group, and user level")
    fig.tight_layout()
    fig.savefig(out_dir / "throughput_vs_impairment.png", dpi=150, bbox_inches="tight")
    plt.close(fig)


def print_summary_table(stats_df):
    """Console summary table — quick numeric reference alongside the plots."""
    cols = ["kem_group", "users", "latency_ms", "loss_pct", "Request Count", "Requests/s",
            "Median Response Time", "Average Response Time", "95%", "99%"]
    available = [c for c in cols if c in stats_df.columns]
    summary = stats_df[available].sort_values(["kem_group", "users", "latency_ms", "loss_pct"])
    print("\n=== Summary table (one row per KEM group x user level x latency x loss) ===")
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
    plot_impairment_heatmaps(stats_df, args.out_dir)
    plot_throughput_vs_impairment(stats_df, args.out_dir)

    print(f"\nFigures written to {args.out_dir.resolve()}")
    print("  - distributions_by_load.png            (baseline 0ms/0% only)")
    print("  - boxplot_by_load.png                  (baseline 0ms/0% only)")
    print("  - time_series_by_run.png               (baseline 0ms/0% only)")
    print("  - load_response_curve.png              (baseline 0ms/0% only)")
    print("  - achieved_throughput.png               (baseline 0ms/0% only)")
    print("  - impairment_heatmaps/heatmap_<kem>_u<N>.png  (one per KEM group x user level)")
    print("  - throughput_vs_impairment.png         (all impairment levels, all KEM x user combos)")
    print("  - combined_stats.csv (tagged long-format data for further analysis)")
    print("  - combined_stats_history.csv (tagged long-format time series data)")


if __name__ == "__main__":
    main()