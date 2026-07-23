#!/usr/bin/env python3
"""Master entrypoint for the collection cleaning pipeline."""

from __future__ import annotations

import logging

from .cli import build_config, parse_args, setup_logging
from .models import Config, TrialArtifacts, TrialContext
from .output import (
    assert_numeric_only_non_key_fields,
    build_output_rows,
    derive_metric_scale_exponents,
    load_trial_intermediate_csvs,
    maybe_bucket_trial_contexts,
    scale_output_rows,
    write_trial_intermediate_csvs,
    write_csv,
    write_post_warmup_warnings_file,
    write_validation_report,
)
from .pcap import RouterTsharkSession
from .trials import discover_manifest, process_trial

LOGGER = logging.getLogger("clean_collection")


def _log_config(cfg: Config) -> None:
    """Emit a concise run summary before processing starts."""
    LOGGER.info("Collection: %s", cfg.collection_path.name)
    LOGGER.info("Collection path: %s", cfg.collection_path)
    LOGGER.info("Results dir: %s", cfg.results_dir)
    LOGGER.info("Pcap dir: %s", cfg.pcap_dir)
    LOGGER.info("Output file: %s", cfg.output_file)
    LOGGER.info("Intermediate dir: %s", cfg.intermediate_dir)
    LOGGER.info(
        "Options: warmup_ns=%d resource_join=%s resource_max_gap_ns=%s pcap_method=%s exclude_retransmissions=%s strict=%s emit_intermediate_trial_csvs=%s timestamp_bucket_ms=%s",
        cfg.warmup_ns,
        cfg.resource_join,
        cfg.resource_max_gap_ns,
        cfg.pcap_method,
        cfg.exclude_retransmissions,
        cfg.strict,
        cfg.emit_intermediate_trial_csvs,
        cfg.timestamp_bucket_ms,
    )


def _build_stats() -> dict[str, int]:
    """Initialize mutable counters used for validation and troubleshooting."""
    return {
        "request_rows_parse_dropped": 0,
        "rows_removed_warmup": 0,
        "rows_removed_post_warmup_handshake_limit": 0,
        "trials_empty_after_warmup": 0,
        "duplicate_request_timestamps_collapsed": 0,
        "bucket_rows_collapsed": 0,
        "trials_missing_or_unreadable_pcap": 0,
        "trials_pcap_parse_error": 0,
        "pcap_router_tshark_fallbacks": 0,
        "pcap_heuristic_stream_matches": 0,
        "pcap_ambiguous_stream_matches": 0,
    }


def _process_trials(
    manifest: list[TrialArtifacts],
    cfg: Config,
    stats: dict[str, int],
    router_session: RouterTsharkSession,
) -> list[TrialContext]:
    """Run per-trial processing and always tear down router resources."""
    trial_contexts: list[TrialContext] = []
    # Keep container lifecycle centralized so every path tears down cleanly.
    try:
        for art in sorted(manifest, key=lambda x: x.trial):
            LOGGER.info("Processing trial: %s", art.trial)
            trial_contexts.append(process_trial(art, cfg, stats, router_session))
    finally:
        router_session.teardown()
    return trial_contexts


def main() -> int:
    """Execute the full cleaning pipeline from CLI args to final CSV."""
    # 1) Parse CLI inputs and establish runtime configuration.
    args = parse_args()
    setup_logging(args.log_level)

    cfg = build_config(args)
    _log_config(cfg)

    # 2) Discover trial inputs and validate required artifacts.
    manifest = discover_manifest(cfg)
    if not manifest:
        raise RuntimeError(f"No trial directories found under {cfg.results_dir}")

    # 3) Process each trial into a normalized per-timestamp metric frame.
    stats = _build_stats()
    router_session = RouterTsharkSession(cfg.project_dir, cfg.pcap_dir)
    trial_contexts = _process_trials(manifest, cfg, stats, router_session)
    post_warmup_warnings = [
        ctx.post_warmup_warning
        for ctx in trial_contexts
        if ctx.post_warmup_warning is not None
    ]

    # 4) Persist per-trial pre-bucketing intermediates and reload from disk.
    if cfg.emit_intermediate_trial_csvs:
        written_paths = write_trial_intermediate_csvs(
            trial_contexts,
            cfg.intermediate_dir,
            cfg.overwrite,
        )
        LOGGER.info(
            "Wrote %d per-trial intermediate CSV files to %s",
            len(written_paths),
            cfg.intermediate_dir,
        )

    trial_contexts = load_trial_intermediate_csvs(cfg.intermediate_dir)
    LOGGER.info(
        "Loaded %d per-trial intermediate CSV files from %s",
        len(trial_contexts),
        cfg.intermediate_dir,
    )

    # 5) Optionally bucket timestamps before cross-trial merge.
    trial_contexts = maybe_bucket_trial_contexts(
        trial_contexts,
        cfg.timestamp_bucket_ms,
        stats,
    )

    # 6) Outer-join all trials and optionally rescale numeric magnitudes.
    header, rows = build_output_rows(trial_contexts, cfg.timestamp_bucket_ms)
    scale_exponents: dict[str, int] = {}
    if cfg.scale_to_billions:
        scale_exponents = derive_metric_scale_exponents(rows, header)
        rows = scale_output_rows(rows, header, scale_exponents)

    # 7) Validate output shape and emit final artifacts.
    assert_numeric_only_non_key_fields(rows, header)
    write_csv(cfg.output_file, header, rows)
    warnings_path = write_post_warmup_warnings_file(
        cfg.output_file.parent,
        cfg.collection_path.name,
        post_warmup_warnings,
    )

    LOGGER.info("Wrote consolidated CSV: %s", cfg.output_file)
    LOGGER.info("Output rows: %d", len(rows))
    LOGGER.info("Warnings file written: %s", warnings_path)
    LOGGER.info("Post-warmup warning count: %d", len(post_warmup_warnings))

    if cfg.emit_validation_report:
        report_path = write_validation_report(
            cfg.output_file,
            cfg,
            trial_contexts,
            stats,
            scale_exponents,
        )
        LOGGER.info("Validation report written: %s", report_path)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
