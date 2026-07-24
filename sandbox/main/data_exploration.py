"""
Exploratory (informal) visualization for the master sweep CSV.

This is NOT the final analysis pipeline. Just a fast way to eyeball
shape/timing correlations between metrics within a single trial.
"""

import pandas as pd
import plotly.graph_objects as go

# ── Config ────────────────────────────────────────────────────────────
TIMESTAMP_COL = "timestamp_ns"

# Which metrics to overlay by default
DEFAULT_METRICS = [
    "response_time_ms",
    "locust_cpu_pct",
    "nginx_cpu_pct",
    "locust_mem_used_bytes",
    "nginx_mem_used_bytes",
]


def normalize_minmax(series: pd.Series) -> pd.Series:
    """Rescale a series to 0-1 based on its own min/max (NaNs preserved)."""
    return (series - series.min()) / (series.max() - series.min())


def discover_run_blocks(columns, timestamp_col=TIMESTAMP_COL):
    """
    Group columns by run_id, splitting each non-timestamp column name on the
    LAST '__' so run_ids containing underscores are handled correctly.

    Returns: dict {run_id: {metric_name: column_name}}
    """
    blocks = {}
    for col in columns:
        if col == timestamp_col:
            continue
        if "__" not in col:
            # Not a recognized "<run_id>__<metric>" column; skip rather than guess.
            continue
        run_id, metric = col.rsplit("__", 1)
        blocks.setdefault(run_id, {})[metric] = col
    return blocks


def load_trial(df: pd.DataFrame, run_id: str, metric_cols: dict,
                timestamp_col=TIMESTAMP_COL) -> pd.DataFrame:
    """
    Slice out one trial's columns + shared timestamp, then drop rows where
    ALL of this trial's own columns are NaN (rows that belong entirely to
    other trials' events at that timestamp).
    """
    cols = [timestamp_col] + list(metric_cols.values())
    trial_df = df[cols].copy()
    trial_df = trial_df.dropna(subset=list(metric_cols.values()), how="all")
    return trial_df


def plot_trial_overlay(trial_df: pd.DataFrame, run_id: str, metric_cols: dict,
                        metrics_to_plot=None, timestamp_col=TIMESTAMP_COL):
    """
    Normalize (per-metric, per-run min/max) and overlay the requested metrics
    on one shared y-axis, as markers (not connected lines) since sampling is
    sparse and irregular per metric.
    """
    metrics_to_plot = metrics_to_plot or DEFAULT_METRICS

    fig = go.Figure()
    for metric in metrics_to_plot:
        if metric not in metric_cols:
            print(f"  (skipping '{metric}': not found for run {run_id})")
            continue

        col = metric_cols[metric]
        # Drop NaNs for THIS metric specifically, not the whole trial —
        # each metric has its own sparse subset of populated rows.
        sub = trial_df[[timestamp_col, col]].dropna(subset=[col])
        if sub.empty:
            print(f"  (skipping '{metric}': no data points for run {run_id})")
            continue

        fig.add_trace(go.Scatter(
            x=sub[timestamp_col],
            y=normalize_minmax(sub[col]),
            name=metric,
            mode="markers",
            marker=dict(size=5),
            hovertemplate=(
                f"{metric}<br>"
                "time: %{x:,} ns<br>"
                "raw: %{customdata:.4f}<extra></extra>"
            ),
            customdata=sub[col],
        ))

    fig.update_layout(
        title=f"Normalized metric overlay — {run_id}",
        xaxis_title="Time since warm-up end (ns)",
        yaxis_title="Normalized (0-1, per-metric per-run)",
    )
    fig.show()


def main(csv_path: str, run_id_filter: str = None, metrics_to_plot=None):
    df = pd.read_csv(csv_path)
    blocks = discover_run_blocks(df.columns)

    if not blocks:
        raise ValueError("No '<run_id>__<metric>' columns found — check TIMESTAMP_COL name.")

    run_ids = [run_id_filter] if run_id_filter else list(blocks.keys())

    for run_id in run_ids:
        if run_id not in blocks:
            print(f"WARNING: run_id '{run_id}' not found in CSV, skipping.")
            continue
        metric_cols = blocks[run_id]
        trial_df = load_trial(df, run_id, metric_cols)
        plot_trial_overlay(trial_df, run_id, metric_cols, metrics_to_plot)


if __name__ == "__main__":
    # Example usage, adjust path and run_id as needed.
    main("cleaned-data/collection_20260723_221029/cleaned_collection_20260723_221029.csv", run_id_filter="classical_u100_rtt50ms_loss0pct_rep1")