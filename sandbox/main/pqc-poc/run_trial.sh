
# Sets how fast Locust ramps to the target user count.
# Can be adjusted later to implement warm up periods and avoid excessive load spikes.
SPAWN_RATE_FN() { echo "$1"; }

extract_pcap_metrics() {
  local run_id="$1"
  local pcap="/mnt/pcaps/${run_id}.pcap"
  local out="${RESULTS_DIR}/pcap_summary_${run_id}.csv"

  # Use tshark to read the pcap file and generate a summary of TCP retransmissions, writing the output to a CSV file in the results directory.
  docker compose exec -T oqs-locust \
    tshark -r "${pcap}" -q \
      -z "io,stat,0,tcp.len,tcp.analysis.retransmission" \
    > "${out}" 2>&1 || log "WARNING: tshark summary failed for ${run_id}"
}

run_one_combination() {
  local kem_label="$1"
  local kem_value="$2"
  local users="$3"
  local latency_ms="$4"
  local loss_pct="$5"
  local repetition="$6"
  local trial_number="$7"
  local spawn_rate="$(SPAWN_RATE_FN "${users}")"

  local run_id="${kem_label}_u${users}_lat${latency_ms}ms_loss${loss_pct}pct_rep${repetition}"
  log "════════════════════════════════════════════════════════════"
  log "RUN(${trial_number}/${total_trials}): kem=${kem_label} (${kem_value})  users=${users}  latency=${latency_ms}ms  loss=${loss_pct}%  duration=${DURATION}"
  log "════════════════════════════════════════════════════════════"

  log "Resetting network conditions..."
  docker compose exec -T -u root oqs-locust tc qdisc del dev eth0 root netem || true

  log "Injecting network conditions: ${latency_ms}ms delay, ${loss_pct}% loss..."
  # The tc command adds a queuing discipline (qdisc) to the eth0 network interface of the oqs-locust container, introducing artificial latency and packet loss.
  # This only affects the outgoing traffic from the locust container to the nginx container, which is unrealistic, but it is a simple way to simulate network 
  # conditions for testing purposes. For actual experimental data, traffic coming from the nginx container to the locust container should also be affected,
  # especially with packet loss.
  docker compose exec -T -u root oqs-locust tc qdisc add dev eth0 root netem delay "${latency_ms}ms" loss "${loss_pct}%"

  # Start tshark in the background to capture packets on eth0, filtering for traffic to/from the oqs-nginx container on port 4433.
  # Write the captured packets to a pcap file named after the run_id in the PCAP_DIR.
  # Start tshark and capture stderr so we can detect readiness text.
  tshark_log="${RESULTS_DIR}/tshark_${run_id}.log"
  docker compose exec -T -u root oqs-locust \
    tshark -i eth0 -f "host oqs-nginx and tcp port 4433" -w "/mnt/pcaps/${run_id}.pcap" \
    > /dev/null 2> "${tshark_log}" &
  TSHARK_PID=$!

  # Wait up to 10s for tshark to report it is capturing.
  timeout_s=10
  elapsed=0
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
      current_time=$(date '+%Y-%m-%d %H:%M:%S')

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

  log "Starting headless Locust run..."
  docker compose exec -T oqs-locust \
    locust \
      --locustfile /mnt/locust/locustfile.py \
      --host https://oqs-nginx:4433 \
      --headless \
      --only-summary \
      --users "${users}" \
      --spawn-rate "${spawn_rate}" \
      --run-time "${DURATION}" \
      --csv "/mnt/locust/results_${run_id}" \
      --csv-full-history \
    || log "WARNING: locust exited non-zero for ${run_id} (check stats before discarding the run)"

  kill "${SAMPLER_PID}" 2>/dev/null || true
  pkill -P "${SAMPLER_PID}" 2>/dev/null || true
  wait "${SAMPLER_PID}" 2>/dev/null || true

  # Terminate the tshark monitor inside the container cleanly by sending a SIGINT signal, which allows tshark to flush its buffers 
  # and write the pcap file properly. This in turn kills the docker compose exec command, which is why the wait command is used to
  # ensure that the tshark process has exited before proceeding.
  docker compose exec -T -u root oqs-locust pkill -SIGINT tshark 2>/dev/null || true
  wait $TSHARK_PID 2>/dev/null || true

  extract_pcap_metrics "${run_id}"

  # Checks if any CSV output files match the the expected pattern before attempting to move them to the results directory.
  if compgen -G "${LOCUST_OUT_DIR}/results_${run_id}*" > /dev/null; then
    mv "${LOCUST_OUT_DIR}"/results_"${run_id}"* "${RESULTS_DIR}/"
    log "Moved results_${run_id}* to ${RESULTS_DIR}/"
  else
    log "WARNING: no CSV output found for ${run_id} — check locust container logs."
  fi
}