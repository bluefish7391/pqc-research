
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source "${SCRIPT_DIR}/helpers.sh"
source "${SCRIPT_DIR}/capture_throttle.sh"
source "${SCRIPT_DIR}/debug.sh"

# Must match the --processes value passed to the locust invocation below —
# kept as one variable so the two can't silently drift apart.
LOCUST_PROCESSES=4

pin_locust_workers_to_cores() {
  # Discovers the currently-running locust worker PIDs inside oqs-locust using
  # 'docker top' and pins each one to a distinct core via host-level taskset.
  local cores=("$@")   # e.g. pin_locust_workers_to_cores 1 2
  local total_expected=$(( LOCUST_PROCESSES + 1 ))  # +1 for the master
  local max_wait=15
  local waited=0
  local pids=()

  log "Waiting for ${total_expected} locust process(es) (1 master + ${LOCUST_PROCESSES} workers) to appear..."

  while true; do
    # Use docker top to get PIDs and command names from the host perspective.
    readarray -t pids < <(docker top oqs-locust -eo pid,comm 2>/dev/null \
      | awk '$2 ~ /locust/ {print $1}' | sort -n)

    if (( ${#pids[@]} >= total_expected )); then
      break
    fi

    if (( waited >= max_wait )); then
      log "WARNING: Only found ${#pids[@]} locust process(es) after ${max_wait}s (expected ${total_expected}); skipping CPU pinning for this run."
      return 1
    fi

    sleep 0.5
    waited=$(( waited + 1 ))
  done

  local worker_pids=("${pids[@]:1}")  # drop the lowest PID (the master)
  local i pid core

  for i in "${!worker_pids[@]}"; do
    pid="${worker_pids[${i}]}"
    core="${cores[$(( i % ${#cores[@]} ))]}"  # round-robin if workers > cores given

    # Run taskset directly on the host using the container's host-mapped PID
    if sudo -n taskset -cp "${core}" "${pid}" >/dev/null 2>&1; then
      log "Pinned locust worker host-pid=${pid} to core ${core}."
    else
      log "WARNING: Failed to pin locust worker host-pid=${pid} to core ${core} (taskset missing, permission denied, or process already exited)."
    fi
  done
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
  local trial_dir="${SWEEP_DIR}/${run_id}"
  mkdir -p "${trial_dir}"

  log "════════════════════════════════════════════════════════════"
  log "RUN(${trial_number}/${total_trials}): kem=${kem_label} (${kem_value})  users=${users}  rtt=${rtt_ms}ms  loss=${loss_pct}% repetition=${repetition}"
  log "════════════════════════════════════════════════════════════"

  log "Injecting network conditions: ${rtt_ms}ms round-trip delay, ${loss_pct}% loss..."
  # The tc command adds a queuing discipline (qdisc) to the eth0 network interface of the router container, introducing artificial latency and packet loss.
  # especially with packet loss.
  docker compose exec -T -u root router tc qdisc add dev eth0 root netem delay "$((rtt_ms / 2))ms" loss "${loss_pct}%"
  docker compose exec -T -u root router tc qdisc add dev eth1 root netem delay "$((rtt_ms / 2))ms" loss "${loss_pct}%"

  # Start tshark in the background to capture packets on eth0, filtering for traffic to/from the oqs-nginx container on port 4433.
  # Write the captured packets to a pcap file named after the run_id in the PCAP_DIR.
  # Start tshark and capture stderr so we can detect readiness text.
  tshark_log="${trial_dir}/tshark_log.log"
  local pcap_path="/mnt/sweep/${run_id}/capture.pcap"
  NGINX_IFACE=$(docker compose exec -T -u root router \
    sh -c "ip -o addr show | awk '/172\\.20\\.0\\.2/{print \$2}'" \
    | tr -d '\r')

  # tshark may drop privileges after startup; pre-create a writable output file.
  docker compose exec -T -u root router \
    sh -c 'pcap_path="$1"; mkdir -p "$(dirname "$pcap_path")" && : > "$pcap_path" && chmod 666 "$pcap_path"' sh "${pcap_path}"

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

  local container_stats_dir="${trial_dir}/container_stats"
  mkdir -p "${container_stats_dir}"

  local locust_cpu_log_file="${container_stats_dir}/locust_cpu_matrix_${run_id}.csv"
  local router_cpu_log_file="${container_stats_dir}/router_cpu_matrix_${run_id}.csv"
  local nginx_cpu_log_file="${container_stats_dir}/nginx_cpu_matrix_${run_id}.csv"
  echo "Timestamp,CPU_Pct,Mem_Usage,Net_IO_Rx_Tx" > "${locust_cpu_log_file}"
  echo "Timestamp,CPU_Pct,Mem_Usage,Net_IO_Rx_Tx" > "${router_cpu_log_file}"
  echo "Timestamp,CPU_Pct,Mem_Usage,Net_IO_Rx_Tx" > "${nginx_cpu_log_file}"

  log "Spawning background monitor (waiting for locust to spin up)..."
  (
    until docker top oqs-locust 2>/dev/null | grep -E "locust" >/dev/null 2>&1; do
      sleep 0.2
    done

    # Pin each locust worker to its own distinct core, discovered dynamically
    pin_locust_workers_to_cores 1 2 3 4

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

      docker stats --no-stream --format '{{.Name}},{{.CPUPerc}},{{.MemUsage}},{{.NetIO}}' oqs-locust oqs-nginx router 2>/dev/null \
        | while IFS=',' read -r c_name cpu_perc mem_schema net_io; do
            if [ -n "$c_name" ] && [ -n "$cpu_perc" ] && [ -n "$mem_schema" ]; then
              if [ "$c_name" = "oqs-locust" ]; then
                echo "${current_time},${cpu_perc},${mem_schema},${net_io}" >> "${locust_cpu_log_file}"
              elif [ "$c_name" = "oqs-nginx" ]; then
                echo "${current_time},${cpu_perc},${mem_schema},${net_io}" >> "${nginx_cpu_log_file}"
              elif [ "$c_name" = "router" ]; then
                echo "${current_time},${cpu_perc},${mem_schema},${net_io}" >> "${router_cpu_log_file}"
              fi
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
    local locust_log_file="${trial_dir}/locust_log.log"
    local main_locust_output_dir="/mnt/sweep/${run_id}/locust"
    local locust_rc=0

    mkdir "${trial_dir}/locust"

    log "Starting headless Locust run..."
    set +e
    docker compose exec -T \
      -e RUN_ID="${run_id}" \
      -e TARGET_HANDSHAKES="${TARGET_HANDSHAKES}" \
      -e MAIN_OUTPUT_DIR="${main_locust_output_dir}" \
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
        --csv "${main_locust_output_dir}/locust" \
        --processes "${LOCUST_PROCESSES}" \
      > >(tee -a "${locust_log_file}") \
      2> >(tee -a "${locust_log_file}" >&2)
    locust_rc=$?
    set -e

    if [ "${locust_rc}" -ne 0 ]; then
      log "ERROR: locust exited with code ${locust_rc} for ${run_id}. See ${locust_log_file}"
      docker compose logs --no-color --timestamps oqs-locust | tail -n 200 >> "${locust_log_file}" || true
    fi

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

  write_throttle_stats "${run_id}" throttle_capture_ok throttle_snapshots_before throttle_snapshots_after
  generate_master_keylog "${trial_dir}"
  extract_pcap_metrics "${trial_dir}" "/mnt/sweep/${run_id}"

  log "Data collection complete."
}