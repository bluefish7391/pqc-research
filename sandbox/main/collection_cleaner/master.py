#!/usr/bin/env python3
"""Master entrypoint for the collection cleaning pipeline."""

from __future__ import annotations

import logging

from .cli import build_config, parse_args, setup_logging
from .output import (
    assert_numeric_only_non_key_fields,
    build_output_rows,
    maybe_bucket_trial_contexts,
    write_csv,
    write_validation_report,
)
from .pcap import RouterTsharkSession
from .trials import discover_manifest, process_trial

LOGGER = logging.getLogger("clean_collection")


def main() -> int:
    args = parse_args()
    setup_logging(args.log_level)

    cfg = build_config(args)

    LOGGER.info("Collection: %s", cfg.collection_path.name)
    LOGGER.info("Collection path: %s", cfg.collection_path)
    LOGGER.info("Results dir: %s", cfg.results_dir)
    LOGGER.info("Pcap dir: %s", cfg.pcap_dir)
    LOGGER.info("Output file: %s", cfg.output_file)
    LOGGER.info(
        "Options: warmup_ns=%d resource_join=%s resource_max_gap_ns=%s pcap_method=%s exclude_retransmissions=%s strict=%s timestamp_bucket_ms=%s",
        cfg.warmup_ns,
        cfg.resource_join,
        cfg.resource_max_gap_ns,
        cfg.pcap_method,
        cfg.exclude_retransmissions,
        cfg.strict,
        cfg.timestamp_bucket_ms,
    )

    manifest = discover_manifest(cfg)
    if not manifest:
        raise RuntimeError(f"No trial directories found under {cfg.results_dir}")

    stats = {
        "request_rows_parse_dropped": 0,
        "rows_removed_warmup": 0,
        "trials_empty_after_warmup": 0,
        "duplicate_request_timestamps_collapsed": 0,
        "bucket_rows_collapsed": 0,
        "trials_missing_or_unreadable_pcap": 0,
        "trials_pcap_parse_error": 0,
        "pcap_router_tshark_fallbacks": 0,
        "pcap_heuristic_stream_matches": 0,
        "pcap_ambiguous_stream_matches": 0,
    }

    router_session = RouterTsharkSession(cfg.project_dir, cfg.pcap_dir)
    trial_contexts = []
    try:
        for art in sorted(manifest, key=lambda x: x.trial):
            LOGGER.info("Processing trial: %s", art.trial)
            ctx = process_trial(art, cfg, stats, router_session)
            trial_contexts.append(ctx)
    finally:
        router_session.teardown()

    trial_contexts = maybe_bucket_trial_contexts(
        trial_contexts,
        cfg.timestamp_bucket_ms,
        stats,
    )

    header, rows = build_output_rows(trial_contexts, cfg.timestamp_bucket_ms)
    assert_numeric_only_non_key_fields(rows, header)
    write_csv(cfg.output_file, header, rows)

    LOGGER.info("Wrote consolidated CSV: %s", cfg.output_file)
    LOGGER.info("Output rows: %d", len(rows))

    if cfg.emit_validation_report:
        report_path = write_validation_report(cfg.output_file, cfg, trial_contexts, stats)
        LOGGER.info("Validation report written: %s", report_path)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
