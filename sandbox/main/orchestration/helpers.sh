#!/usr/bin/env bash

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "${MAIN_LOG_FILE}"
}

teardown() {
  log "Tearing down (docker compose down -v)..."
  docker compose down -v --remove-orphans || log "Warning: docker compose down failed. Continuing..."
}

# Unused function for analysis purposes, kept for reference and potential future use
extract_pcap_metrics() {
  local run_id="$1"
  local run_results_dir="$2"
  local pcap_file="$3"
  local keylog="$4"
  local out="${run_results_dir}/pcap_summary_${run_id}.csv"

  # TODO: Perform tshark metric extraction on host instead of inside router container
  docker compose exec -T router \
  tshark -r "${pcap_file}" \
    -T fields \
    -e frame.time_epoch -e ip.src -e ip.dst -e tcp.stream \
    -e tcp.flags -e tls.handshake.type -e tls.record.content_type \
    -E separator=, -E quote=d -E occurrence=a -E aggregator=";" \
    -E header=y \
    > "${out}" 2>&1 || log "WARNING: tshark summary failed for run_id ${run_id}."

  
   # -o "tls.keylog_file:${keylog}" \
}