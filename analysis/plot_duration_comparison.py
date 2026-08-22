#!/usr/bin/env python3
"""
plot_duration_comparison.py

Reads the combined_metrics.csv produced by combine_trial_data.py and
produces an interactive Plotly scatterplot comparing, per request:

  x-axis: Locust-measured request duration (end_time_ns - start_time_ns), ms
  y-axis: pcap-measured stream duration (last_pkt_time - first_pkt_time), ms

Only rows with matched == True are plotted, since unmatched rows (failed
or timed-out requests) have no pcap timing data to plot.

Usage:
    python3 plot_duration_comparison.py /path/to/combined_metrics.csv
    python3 plot_duration_comparison.py /path/to/combined_metrics.csv --output /path/to/out.html
    python3 plot_duration_comparison.py /path/to/combined_metrics.csv --no-reference-line

Requires: pandas, plotly.
"""

import argparse
import re
import sys
from pathlib import Path

import pandas as pd
import plotly.express as px


def die(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def resolve_cli_path(path_text: str) -> Path:
    """Resolve a CLI path, including Windows absolute paths passed from POSIX-like shells."""
    raw = path_text.strip().strip('"').strip("'")

    # Fast path: normal resolution works.
    candidate = Path(raw).expanduser()
    if candidate.exists():
        return candidate.resolve()

    # Accept Windows drive-letter absolute paths even when running under POSIX path rules.
    m = re.match(r"^([A-Za-z]):[\\/](.*)$", raw)
    if m:
        drive = m.group(1).lower()
        rest = m.group(2).replace("\\", "/")
        for translated in (Path(f"/{drive}/{rest}"), Path(f"/mnt/{drive}/{rest}")):
            if translated.exists():
                return translated.resolve()

    return candidate.resolve()


def load_and_prepare(csv_path: Path) -> pd.DataFrame:
    df = pd.read_csv(csv_path)

    required_cols = {
        "start_time_ns", "end_time_ns",
        "first_pkt_time", "last_pkt_time",
        "matched", "request_id",
        "tcp_handshake_ms", "tls_negotiation_ms", "ttfb_ms",
        "response_transfer_ms", "teardown_ms",
    }
    missing = required_cols - set(df.columns)
    if missing:
        die(f"{csv_path} is missing expected column(s): {sorted(missing)}")

    legacy_phase_columns = {"syn_to_get_s", "get_to_last_pkt_s"}
    if not {"syn_to_get_ms", "get_to_last_pkt_ms"}.issubset(df.columns):
        if legacy_phase_columns.issubset(df.columns):
            df["syn_to_get_ms"] = df["syn_to_get_s"] * 1000
            df["get_to_last_pkt_ms"] = df["get_to_last_pkt_s"] * 1000
        else:
            die(f"{csv_path} is missing phase-duration columns: syn_to_get_ms and get_to_last_pkt_ms")

    total = len(df)
    df = df[df["matched"] == True].copy()  # noqa: E712 (matched is a real bool column)
    if df.empty:
        die("No matched rows found in this CSV -- nothing to plot.")

    dropped = total - len(df)
    if dropped:
        print(f"Skipping {dropped} unmatched request(s) with no pcap timing data.")

    # start_time_ns / end_time_ns are nanoseconds -> ms
    df["locust_duration_ms"] = (df["end_time_ns"] - df["start_time_ns"]) / 1_000_000
    # first_pkt_time / last_pkt_time are epoch seconds (float) -> ms
    df["pcap_duration_ms"] = (df["last_pkt_time"] - df["first_pkt_time"]) * 1000

    # combined_metrics.csv stores the phase durations in milliseconds already.
    # Keep explicit ms columns for downstream analysis and hover text.
    if "syn_to_get_ms" not in df.columns:
        df["syn_to_get_ms"] = df["syn_to_get_s"] * 1000
    if "get_to_last_pkt_ms" not in df.columns:
        df["get_to_last_pkt_ms"] = df["get_to_last_pkt_s"] * 1000
    for phase in [
        "tcp_handshake_ms",
        "tls_negotiation_ms",
        "ttfb_ms",
        "response_transfer_ms",
        "teardown_ms",
    ]:
        if phase not in df.columns:
            legacy_name = phase.replace("_ms", "_s")
            if legacy_name in df.columns:
                df[phase] = df[legacy_name] * 1000

    return df


def make_plot(df: pd.DataFrame, add_reference_line: bool):
    hover_cols = [
        c for c in [
            "request_id",
            "pcap_stream_id",
            "success",
            "exception",
            "syn_to_get_ms",
            "get_to_last_pkt_ms",
            "tcp_handshake_ms",
            "tls_negotiation_ms",
            "ttfb_ms",
            "response_transfer_ms",
            "teardown_ms",
        ] if c in df.columns
    ]

    fig = px.scatter(
        df,
        x="locust_duration_ms",
        y="pcap_duration_ms",
        hover_data=hover_cols,
        opacity=0.6,
        title="Locust-measured duration vs. pcap-measured stream duration, per request",
    )

    if add_reference_line:
        lo = min(df["locust_duration_ms"].min(), df["pcap_duration_ms"].min())
        hi = max(df["locust_duration_ms"].max(), df["pcap_duration_ms"].max())
        fig.add_shape(
            type="line",
            x0=lo, y0=lo, x1=hi, y1=hi,
            line=dict(dash="dash", color="gray"),
        )
        fig.add_annotation(
            x=hi, y=hi,
            text="y = x",
            showarrow=False,
            xanchor="left",
            font=dict(color="gray"),
        )

    fig.update_layout(
        xaxis_title="Locust request duration (ms)",
        yaxis_title="Pcap stream duration (ms)",
    )

    return fig


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("csv_path", type=str, help="Path to combined_metrics.csv")
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output HTML path (default: <csv_dir>/duration_comparison.html)",
    )
    parser.add_argument(
        "--no-reference-line",
        action="store_true",
        help="Omit the y=x reference line",
    )
    args = parser.parse_args()

    csv_path = resolve_cli_path(args.csv_path)
    if not csv_path.exists():
        die(f"{csv_path} not found.")

    df = load_and_prepare(csv_path)
    fig = make_plot(df, add_reference_line=not args.no_reference_line)

    output_path = resolve_cli_path(args.output) if args.output else (csv_path.parent / "duration_comparison.html")
    fig.write_html(str(output_path))

    print(f"\nWrote {output_path}")
    print(f"Plotted {len(df)} request(s).")


if __name__ == "__main__":
    main()