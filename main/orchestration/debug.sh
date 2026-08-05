#!/usr/bin/env bash

# Analysis functions used for debugging and troubleshooting the collection process. These functions 
# are not part of the main collection workflow but can be invoked manually for analysis purposes.
# May be reused for actual analysis scripts in the future.

generate_master_keylog() {
  local trial_dir="$1"
  cat "${trial_dir}/keylogs/"* > "${trial_dir}/master_keylog.log"
}

extract_pcap_metrics() {
  local run_id="$1"
  local trial_dir="$2"
  local pcap_file="$3"
  local keylog="$4"
  local out="${trial_dir}/pcap_summary_${run_id}.csv"

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