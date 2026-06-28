
source ./start_containers.sh

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
  docker compose exec -T -u root oqs-locust \
    tshark \
      -i eth0 \
      -f "host oqs-nginx and tcp port 4433" \
      -w "/mnt/pcaps/${run_id}.pcap" \
    &
  TSHARK_PID=$! # Store the PID of the background tshark process so it can be terminated later after the locust run is complete.
  sleep 1

  local cpu_log_file="${RESULTS_DIR}/cpu_matrix_${run_id}.csv"
  echo "Timestamp,Container,CPU_Pct,Mem_Usage,Net_IO_Rx_Tx" > "${cpu_log_file}"

  log "Spawning background monitor (waiting for locust to spin up)..."
  (
    until docker top oqs-locust 2>/dev/null | grep -v tshark | grep -q locust; do
      sleep 0.2
    done
    LOCUST_PROC_PID=$(docker top oqs-locust -o pid,comm \
      | awk '/locust/ {print $1}' \
      | head -n1)
    log "locust PID: ${LOCUST_PROC_PID}"

    # Stream pidstat output for both PIDs into a background coprocess.
    # Interval=1, no end count = runs until the pipe is closed.
    # -u = CPU, -r = memory, -T ALL = include child processes (nginx workers, locust greenlets).
    pidstat -u -r -T ALL -p "${NGINX_PIDS},${LOCUST_PROC_PID}" 1 \
      > /tmp/pidstat_stream.txt 2>/dev/null &
    PIDSTAT_PID=$!

    while true; do
      sleep 1
      current_time=$(date '+%Y-%m-%d %H:%M:%S')

      # ── CPU + memory: read the latest pidstat output ─────────────────
      # pidstat streams one block per interval. tail -n 20 gets the most
      # recent block; awk extracts the row matching each PID.
      pidstat_snapshot=$(tail -n 20 /tmp/pidstat_stream.txt 2>/dev/null)

      read nginx_cpu nginx_mem <<< $(
        echo "${pidstat_snapshot}" \
          | awk -v pid="${NGINX_PIDS}" '
              /^[0-9]/ && $3 == pid { printf "%s %s", $8, $12 }
            '
      )

      read locust_cpu locust_mem <<< $(
        echo "${pidstat_snapshot}" \
          | awk -v pid="${LOCUST_PROC_PID}" '
              /^[0-9]/ && $3 == pid { printf "%s %s", $8, $12 }
            '
      )

      # ── Network I/O: single read of /proc/net/dev per container ──────
      read nginx_rx nginx_tx <<< $(
        docker compose exec -T oqs-nginx cat /proc/net/dev 2>/dev/null \
          | awk '/eth0/ { print $2, $10 }'
      )

      read locust_rx locust_tx <<< $(
        docker compose exec -T oqs-locust cat /proc/net/dev 2>/dev/null \
          | awk '/eth0/ { print $2, $10 }'
      )

      # ── Write one row per container ───────────────────────────────────
      echo "${current_time},oqs-nginx,${nginx_cpu:-0}%,${nginx_mem:-0}kB,${nginx_rx:-0}/${nginx_tx:-0}" \
        >> "${cpu_log_file}"
      echo "${current_time},oqs-locust,${locust_cpu:-0}%,${locust_mem:-0}kB,${locust_rx:-0}/${locust_tx:-0}" \
        >> "${cpu_log_file}"

    done

    kill "${PIDSTAT_PID}" 2>/dev/null
    wait "${PIDSTAT_PID}" 2>/dev/null || true
    rm -f /tmp/pidstat_stream.txt

  ) &
  CPU_MONITOR_PID=$!

  # Run Locust headless inside the already-up container via docker compose run,
  # overriding the default `command` to pass headless flags explicitly.
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

  # After the locust run is complete, terminate the background CPU monitor cleanly.
  kill "${CPU_MONITOR_PID}" 2>/dev/null
  wait "${CPU_MONITOR_PID}" 2>/dev/null || true

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