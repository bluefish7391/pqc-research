
THROTTLE_ALIASES=(lt rt ws)
THROTTLE_METRICS=(nr_periods nr_throttled throttled_usec)
declare -A THROTTLE_CONTAINERS=(
  [lt]="oqs-locust"
  [rt]="router"
  [ws]="oqs-nginx"
)

throttle_metric_suffix() {
  local metric_name="$1"
  case "${metric_name}" in
    nr_periods) echo "nrp" ;;
    nr_throttled) echo "nrt" ;;
    throttled_usec) echo "tu" ;;
    *)
      log "ERROR: Unknown throttle metric '${metric_name}'"
      return 1
      ;;
  esac
}

init_throttle_stats_csv() {
  local out_file="${RESULTS_DIR}/throttle_stats.csv"
  local header="run_id"
  local alias
  local metric
  local metric_suffix

  for alias in "${THROTTLE_ALIASES[@]}"; do
    for metric in "${THROTTLE_METRICS[@]}"; do
      if ! metric_suffix="$(throttle_metric_suffix "${metric}")"; then
        return 1
      fi
      header+=",${alias}_${metric_suffix}_before,${alias}_${metric_suffix}_after"
    done
  done

  header+=",capture_status"

  if ! printf '%s\n' "${header}" > "${out_file}"; then
    log "ERROR: Failed to initialize ${out_file}"
    return 1
  fi
}

capture_throttle_stats_batch() {
  local phase="$1"
  local -n snapshot_map_ref="$2"
  local alias
  local container_name
  local stats_var_name

  snapshot_map_ref=()

  for alias in "${THROTTLE_ALIASES[@]}"; do
    container_name="${THROTTLE_CONTAINERS[${alias}]}"
    stats_var_name="throttle_${alias}_${phase}"

    declare -g -A "${stats_var_name}=()"

    if ! record_throttle_stats_for_container "${container_name}" "${stats_var_name}"; then
      log "ERROR: Failed throttle capture for alias=${alias}, container=${container_name}, phase=${phase}"
      return 1
    fi

    snapshot_map_ref["${alias}"]="${stats_var_name}"
  done
}

extract_pcap_metrics() {
  local run_id="$1"
  local pcap="/mnt/pcaps/${run_id}.pcap"
  local out="${RESULTS_DIR}/pcap_summary_${run_id}.csv"

  docker compose exec -T router \
  tshark -r "${pcap}" -T fields \
    -e frame.time_epoch -e tcp.stream -e tcp.flags \
    -e tls.handshake.type -e tls.record.content_type \
    -E separator=, -E header=y \
    > "${out}" 2>&1 || log "WARNING: tshark summary failed for ${run_id}"
}

run_one_combination() {
  local kem_label="$1"
  local kem_value="$2"
  local users="$3"
  local rtt_ms="$4"
  local loss_pct="$5"
  local repetition="$6"
  local trial_number="$7"

  local run_id="${kem_label}_u${users}_rtt${rtt_ms}ms_loss${loss_pct}pct_rep${repetition}"
  log "════════════════════════════════════════════════════════════"
  log "RUN(${trial_number}/${total_trials}): kem=${kem_label} (${kem_value})  users=${users}  rtt=${rtt_ms}ms  loss=${loss_pct}% repetition=${repetition}"
  log "════════════════════════════════════════════════════════════"

  log "Resetting network conditions..."
  docker compose exec -T -u root router tc qdisc del dev eth0 root netem || true
  docker compose exec -T -u root router tc qdisc del dev eth1 root netem || true

  log "Injecting network conditions: ${rtt_ms}ms round-trip delay, ${loss_pct}% loss..."
  # The tc command adds a queuing discipline (qdisc) to the eth0 network interface of the router container, introducing artificial latency and packet loss.
  # especially with packet loss.
  docker compose exec -T -u root router tc qdisc add dev eth0 root netem delay "$((rtt_ms / 2))ms" loss "${loss_pct}%"
  docker compose exec -T -u root router tc qdisc add dev eth1 root netem delay "$((rtt_ms / 2))ms" loss "${loss_pct}%"

  # Start tshark in the background to capture packets on eth0, filtering for traffic to/from the oqs-nginx container on port 4433.
  # Write the captured packets to a pcap file named after the run_id in the PCAP_DIR.
  # Start tshark and capture stderr so we can detect readiness text.
  tshark_log="${RESULTS_DIR}/tshark_${run_id}.log"
  local pcap_path="/mnt/pcaps/${run_id}.pcap"
  NGINX_IFACE=$(docker compose exec -T -u root router \
    sh -c "ip -o addr show | awk '/172\\.20\\.0\\.2/{print \$2}'" \
    | tr -d '\r')

  # tshark may drop privileges after startup; pre-create a writable output file.
  docker compose exec -T -u root router \
    sh -c "mkdir -p /mnt/pcaps && : > '${pcap_path}' && chmod 666 '${pcap_path}'"

  docker compose exec -T -u root router \
    tshark -i "${NGINX_IFACE}" -f "host 172.20.0.10 and tcp port 4433" \
      -w "${pcap_path}" \
    > /dev/null 2> "${tshark_log}" &
  TSHARK_PID=$!

  # Wait up to 10s for tshark to report it is capturing.
  local timeout_s=10
  local elapsed=0
  until grep -q "Capturing on" "${tshark_log}" 2>/dev/null; do
    if ! kill -0 "${TSHARK_PID}" 2>/dev/null; then
      log "ERROR: tshark exited before becoming ready"
      return 1
    fi
    if [ "${elapsed}" -ge "${timeout_s}" ]; then
      log "ERROR: tshark did not become ready within ${timeout_s}s"
      kill "${TSHARK_PID}" 2>/dev/null || true
      return 1
    fi
    sleep 0.1
    elapsed=$((elapsed + 1))
  done

  local cpu_log_file="${RESULTS_DIR}/cpu_matrix_${run_id}.csv"
  echo "Timestamp,Container,CPU_Pct,Mem_Usage,Net_IO_Rx_Tx" > "${cpu_log_file}"

  log "Spawning background monitor (waiting for locust to spin up)..."
  (
    until docker top oqs-locust 2>/dev/null | grep -E "locust" >/dev/null 2>&1; do
      sleep 0.2
    done

    log "Locust detected! Starting container-level resource monitor..."

    # Keep sampling on a fixed 1s schedule to avoid drift from command runtime.
    local period_ns=1000000000
    local next_tick
    local now_ns
    local sleep_ns
    local missed
    next_tick=$(date +%s%N)

    while true; do
      current_time=$(date +%s%N)

      docker stats --no-stream --format '{{.Name}},{{.CPUPerc}},{{.MemUsage}},{{.NetIO}}' oqs-locust oqs-nginx 2>/dev/null \
        | while IFS=',' read -r c_name cpu_perc mem_schema net_io; do
            if [ -n "$c_name" ] && [ -n "$cpu_perc" ] && [ -n "$mem_schema" ]; then
              echo "${current_time},${c_name},${cpu_perc},${mem_schema},${net_io}" >> "${cpu_log_file}"
            fi
          done

      next_tick=$((next_tick + period_ns))
      now_ns=$(date +%s%N)
      sleep_ns=$((next_tick - now_ns))

      if [ "$sleep_ns" -gt 0 ]; then
        sleep "$(awk "BEGIN { printf \"%.6f\", ${sleep_ns}/1000000000 }")"
      else
        # If sampling overruns, skip ahead to the next aligned slot.
        missed=$(( (-sleep_ns) / period_ns + 1 ))
        next_tick=$((next_tick + missed * period_ns))
      fi
    done
  ) &
  SAMPLER_PID=$!

  local throttle_capture_ok=1
  declare -A throttle_snapshots_before
  declare -A throttle_snapshots_after

  if ! capture_throttle_stats_batch "before" throttle_snapshots_before; then
    log "ERROR: Aborting run due to missing pre-run throttle stats for ${run_id}"
    throttle_capture_ok=0
  fi

  if [ "${throttle_capture_ok}" -eq 1 ]; then
    log "Starting headless Locust run..."
    docker compose exec -T \
      -e RUN_ID="${run_id}" \
      -e TARGET_HANDSHAKES="${TARGET_HANDSHAKES}" \
      oqs-locust \
      locust \
        --locustfile /mnt/locust/locustfile.py \
        --host https://oqs-nginx:4433 \
        --headless \
        --only-summary \
        --users "${users}" \
        --spawn-rate "${SPAWN_RATE}" \
        --run-time "${MAX_DURATION}" \
        --stop-timeout 5 \
        --csv "/mnt/locust/results_${run_id}" \
        --csv-full-history \
      || log "WARNING: locust exited non-zero for ${run_id} (check stats before discarding the run)"

    if ! capture_throttle_stats_batch "after" throttle_snapshots_after; then
      log "ERROR: Aborting run due to missing post-run throttle stats for ${run_id}"
      throttle_capture_ok=0
    fi
  fi

  log "Load test complete. Stopping background monitor and tshark..."

  kill "${SAMPLER_PID}" 2>/dev/null || true
  pkill -P "${SAMPLER_PID}" 2>/dev/null || true
  wait "${SAMPLER_PID}" 2>/dev/null || true

  # Terminate the tshark monitor inside the container cleanly by sending a SIGINT signal, which allows tshark to flush its buffers 
  # and write the pcap file properly. This in turn kills the docker compose exec command, which is why the wait command is used to
  # ensure that the tshark process has exited before proceeding.
  docker compose exec -T -u root router pkill -SIGINT tshark 2>/dev/null || true
  wait $TSHARK_PID 2>/dev/null || true

  # extract_pcap_metrics "${run_id}"
  write_throttle_stats "${run_id}" throttle_capture_ok throttle_snapshots_before throttle_snapshots_after

  # Checks if any CSV output files match the the expected pattern before attempting to move them to the results directory.
  if compgen -G "${LOCUST_OUT_DIR}/results_${run_id}*" > /dev/null; then
    mv "${LOCUST_OUT_DIR}"/results_"${run_id}"* "${RESULTS_DIR}/"
    mv "${LOCUST_OUT_DIR}/${run_id}"* "${LOG_DIR}/"
  else
    log "WARNING: no CSV output found for ${run_id} — check locust container logs."
  fi

  log "Data collection complete."
}

record_throttle_stats_for_container() {
  local container_name="$1"
  local -n stats_array_ref="$2"
  local cpu_stat_output
  local metric

  stats_array_ref=()

  if ! cpu_stat_output="$(docker compose exec -T "${container_name}" cat /sys/fs/cgroup/cpu.stat 2>/dev/null)"; then
    log "ERROR: Failed to read CPU throttle stats for container ${container_name}"
    return 1
  fi

  while read -r key value; do
    case "${key}" in
      nr_periods|nr_throttled|throttled_usec)
        stats_array_ref["${key}"]="${value}"
        ;;
    esac
  done <<< "${cpu_stat_output}"

  for metric in "${THROTTLE_METRICS[@]}"; do
    if [[ -z "${stats_array_ref[${metric}]:-}" ]]; then
      log "ERROR: Missing throttle metric ${metric} for container ${container_name}"
      return 1
    fi
  done
}

write_throttle_stats() {
  local run_id="$1"
  local out_file="${RESULTS_DIR}/throttle_stats.csv"
  local throttle_capture_ok="$2"
  local -n before_snapshot_map="$3"
  local -n after_snapshot_map="$4"
  local row="${run_id}"
  local alias
  local metric
  local before_var_name
  local after_var_name
  local delta

  for alias in "${THROTTLE_ALIASES[@]}"; do
    before_var_name="${before_snapshot_map[${alias}]:-}"
    after_var_name="${after_snapshot_map[${alias}]:-}"

    if [[ -z "${before_var_name}" || -z "${after_var_name}" ]]; then
      log "ERROR: Missing snapshot references for alias ${alias} (run ${run_id})"
      return 1
    fi

    local -n before_stats_ref="${before_var_name}"
    local -n after_stats_ref="${after_var_name}"

    for metric in "${THROTTLE_METRICS[@]}"; do
      if [[ -z "${before_stats_ref[${metric}]:-}" || -z "${after_stats_ref[${metric}]:-}" ]]; then
        log "ERROR: Missing metric ${metric} for alias ${alias} (run ${run_id})"
        return 1
      fi
      
      row+=",${before_stats_ref[${metric}]},${after_stats_ref[${metric}]}"
    done
  done

  if [ "${throttle_capture_ok}" -ne 1 ]; then
    log "WARNING: Throttle capture failed for ${run_id}; writing row with available data."
    row+=",CAPTURE_FAILED"
  else
    log "Writing throttle stats for ${run_id}: ${row}"
    row+=",CAPTURE_SUCCEEDED"
  fi

  if ! printf '%s\n' "${row}" >> "${out_file}"; then
    log "ERROR: Failed to write throttle stats for ${run_id}"
    return 1
  fi
}