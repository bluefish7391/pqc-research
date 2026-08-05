#!/usr/bin/env bash

# Analysis functions used for debugging and troubleshooting the collection process. These functions 
# are not part of the main collection workflow but can be invoked manually for analysis purposes.
# May be reused for actual analysis scripts in the future.

generate_master_keylog() {
  local trial_dir="$1"
  cat "${trial_dir}/keylogs/"* > "${trial_dir}/master_keylog.log"
}

extract_pcap_metrics() {
  local trial_dir="$1"      # Represents the path to the directory on the host machine
  local mounted_trial_dir="$2" # Represents the path to the directory as mounted on the router container.
  local pcap_path="${mounted_trial_dir}/capture.pcap"
  local keylog="${mounted_trial_dir}/master_keylog.log"
  local out="${trial_dir}/pcap_summary.csv"

  docker compose exec -T router \
  tshark -r "${pcap_path}" \
    -o "tls.keylog_file:${keylog}" \
    -T fields \
    -e frame.time_epoch -e ip.src -e ip.dst -e tcp.stream \
    -e tcp.flags -e tls.handshake.type -e tls.record.content_type \
    -e http.request.line \
    -E separator=, -E quote=d -E occurrence=a -E aggregator=";" \
    -E header=y \
    > "${out}" 2>&1
}