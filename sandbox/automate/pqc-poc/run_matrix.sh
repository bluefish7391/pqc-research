#!/usr/bin/env bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  run_matrix.sh — KD Protocol Benchmarking PoC orchestrator
#
#  Sweeps: KEM_GROUPS (classical / hybrid / pure-pq) x USER_LEVELS (-u)
#  For each combination:
#    1. Render nginx.conf from template with the target KEM group
#    2. docker compose down -v   (full teardown — clean isolation)
#    3. docker compose up -d --build
#    4. Wait for oqs-nginx healthcheck
#    5. Run Locust in headless mode for DURATION seconds at -u USERS
#    6. Copy/rename the resulting CSV stats with a combo-specific name
#    7. Teardown again before the next combination
#
#  Usage: ./run_matrix.sh
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

set -euo pipefail

# Disable automatic path conversion on Windows (MSYS2 / Git Bash) to avoid
# issues with volume mounts and file paths in docker compose.
# Environment variable inherited by subprocesses spawned by this script for 
# this shell session, including docker compose itself.
export MSYS_NO_PATHCONV=1

# KEM_GROUPS is an associative array (like a dictionary or a hashmap) mapping
# a human-readable label to the corresponding OpenSSL group name. The label 
# is used in output filenames and logs.
declare -A KEM_GROUPS=(
  [classical]="X25519"
  [hybrid]="X25519MLKEM768"
)

USER_LEVELS=(1)
LATENCIES=(0)
LOSS_LEVELS=(0)

DURATION="30s" # Headless Locust run duration per combination (seconds).
REPETITIONS_PER_TEST=1 # Number of times to repeat each combination for averaging or variance analysis.

# Sets how fast Locust ramps to the target user count.
# Can be adjusted later to implement warm up periods and avoid excessive load spikes.
SPAWN_RATE_FN() { echo "$1"; }

# Identifies the name of this file, then the directory containing said file, and sets PROJECT_DIR to that path.
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

NGINX_TMPL="${PROJECT_DIR}/nginx/nginx.conf.tmpl"
NGINX_CONF="${PROJECT_DIR}/nginx/nginx.conf"
RESULTS_DIR="${PROJECT_DIR}/data/results"
LOCUST_OUT_DIR="${PROJECT_DIR}/locust"
PCAP_DIR="${PROJECT_DIR}/data/pcaps"

# Create directories for results, pcaps, and logs if they don't exist yet,
# as these are untracked by git and may not be present in a fresh clone.
mkdir -p "${RESULTS_DIR}" "${PCAP_DIR}" "${PROJECT_DIR}/logs"
touch "${PROJECT_DIR}/logs/run_matrix.log"

# == Helpers ==================================================================

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "${PROJECT_DIR}/logs/run_matrix.log"
}

teardown() {
  log "Tearing down (docker compose down -v)..."
  docker compose down -v --remove-orphans || true
}

render_nginx_conf() {
  local kem_value="$1"
  sed "s/__KEM_GROUP__/${kem_value}/" "${NGINX_TMPL}" > "${NGINX_CONF}"
  log "Rendered nginx.conf with ssl_ecdh_curve=${kem_value}"
}

wait_for_healthy() {
  # Wait for the oqs-nginx container to report a healthy status via its healthcheck.
  # If it does not become healthy within max_wait seconds, logs are dumped and an error is returned.

  local container="oqs-nginx"
  local max_wait=60
  local waited=0
  log "Waiting for ${container} healthcheck..."

  while true; do
    # Inspect the nginx container, and extract just the health status. If the container is not found, return "unknown".
    # Do not fail the script if the container is not found yet, as it may take a few seconds for docker compose to start it.
    # DO not log any errors from docker inspect to avoid cluttering the output.
    status="$(docker inspect --format='{{.State.Health.Status}}' "${container}" 2>/dev/null || echo "unknown")"

    if [[ "${status}" == "healthy" ]]; then
      log "${container} is healthy."
      return 0
    fi

    if (( waited >= max_wait )); then
      log "ERROR: ${container} did not become healthy within ${max_wait}s (status=${status})."
      docker compose logs oqs-nginx || true
      return 1
    fi
    
    sleep 2
    (( waited += 2))
  done
}

# == Validation =================================================================

find_openssl_bin() {
  # Look for an OpenSSL binary inside the oqs-locust container.
  # The location of the binary may vary depending on the image build, so multiple common locations are checked. 
  # If found, the path to the binary is returned; otherwise, exit with an error.
  # For this locust container, the binary is expected to be /opt/oqssa/bin/openssl
  local search_script=$(cat << 'EOF'
    if command -v openssl >/dev/null 2>&1; then
      command -v openssl
    elif [ -x /opt/oqssa/bin/openssl ]; then
      echo /opt/oqssa/bin/openssl
    elif [ -x /opt/openssl/apps/openssl ]; then
      echo /opt/openssl/apps/openssl
    else
      echo ""
    fi
EOF
  )

  # Run the search script inside the oqs-locust container and capture the output,
  # stripping any carriage returns and taking only the last line (the path to the binary).
  local openssl_bin
  openssl_bin=$(docker compose exec -T oqs-locust sh -lc "${search_script}" \
    | tr -d '\r' \
    | tail -n1)
  echo "${openssl_bin}"
}

validate_handshake() {
  # Validate that the oqs-locust client can successfully perform a TLS handshake with the oqs-nginx server using the specified KEM group.
  # This is a preflight check to ensure that the server and client are configured correctly before running the load test.

  local kem_label="$1"
  local kem_value="$2"
  local openssl_bin=$(find_openssl_bin)

  if [[ -z "${openssl_bin}" ]]; then
    log "ERROR: no OpenSSL client binary found in oqs-locust container."
    log "ERROR: checked: openssl, /opt/oqssa/bin/openssl, /opt/openssl/apps/openssl"
    return 1
  fi

  log "Validating TLS handshake for ${kem_label} (${kem_value}) before load run (bin=${openssl_bin})..."

  # Docker compose steps into the oqs-locust container and runs a one-off command to perform a TLS handshake with the oqs-nginx server using the specified KEM group.
  # The command uses OpenSSL's s_client to connect to the server and perform a handshake. If the handshake fails, an error is logged and the function exits.
  if ! docker compose exec -T oqs-locust \
    sh -lc "printf 'GET /health HTTP/1.1\\r\\nHost: oqs-nginx\\r\\nConnection: close\\r\\n\\r\\n' | '${openssl_bin}' s_client -connect oqs-nginx:4433 -groups '${kem_value}' -quiet >/dev/null 2>&1"; then
    log "ERROR: preflight handshake failed for ${kem_label} (${kem_value})."
    log "ERROR: Client/Server TLS groups likely do not match or classical group is unsupported in this image build."
    docker compose logs --tail=80 oqs-nginx || true
    return 1
  fi

  log "Preflight handshake OK for ${kem_label} (${kem_value})."
}

# == Main Execution Functions ====================================================

start_up_containers() {
  # Start up the oqs-nginx and oqs-locust containers for a specific KEM group, and validate that the handshake works before proceeding with the load test.

  local kem_label="$1"
  local kem_value="$2"

  teardown

  log "Starting up containers for KEM group ${kem_label} (${kem_value})..."

  # Set the environment variable for the KEM group so that the locust file can pick it up and know to use the correct KEM group.
  export OQS_KEM_GROUP="${kem_value}"

  # Build tag is used to ensure that the image is rebuilt with the updated nginx.conf for the specific KEM group.
  # Only the oqs-nginx service needs to be rebuilt, as the oqs-locust service determines the KEM group at runtime via the OQS_KEM_GROUP environment variable.
  # On the other hand, the nginx.conf file is baked into the oqs-nginx image at build time, so it must be rebuilt for each KEM group.
  render_nginx_conf "${kem_value}"
  docker compose up -d --build oqs-nginx 

  if ! wait_for_healthy; then
    log "ERROR: nginx did not become healthy for KEM group ${kem_label} (${kem_value})."
    teardown
    return 1
  fi

  docker compose up -d --build oqs-locust

  # The oqs-locust container is based on Alpine Linux, which uses the 'apk' package manager. Due to the minimalist nature of the locust image,
  # it lacks the security certificates needed to validate HTTPS connections. To get around this, the alpine respositories file is modified by
  # replacing 'https://' with 'http://', allowing the package manager to fetch packages over HTTP. Then, the necessary packages for network 
  # emulation and packet capture are installed.

  # It is safe to use HTTP here because while the requests and responses are unsecured by TLS, the Alpine package repositories are signed, and 
  # the package manager will verify the signatures of the packages it downloads.
  docker compose exec -T -u root oqs-locust sed -i 's/https:\/\//http:\/\//g' /etc/apk/repositories
  docker compose exec -T -u root oqs-locust apk add --no-cache iproute2 tshark # --no-cache avoids caching the package index, saving space in the container.

  if ! validate_handshake "${kem_label}" "${kem_value}"; then
    log "ERROR: handshake validation failed for KEM group ${kem_label} (${kem_value})."
    teardown
    return 1
  fi
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
    # Wait until the 'locust' process appears inside the container by repeatedly checking the output of docker top for the container.
    until docker top oqs-locust 2>/dev/null | grep -E "locust" >/dev/null 2>&1; do
      sleep 0.2
    done

    log "Locust detected! Tracking CPU, Mem, and Network volume..."

    # Loop continuously while locust is alive, again by repeatedly checking docker top.
    while docker top oqs-locust 2>/dev/null | grep -E "locust" >/dev/null 2>&1; do
      # Takes a snapshot of the CPU, memory, and network I/O stats for both the oqs-locust and oqs-nginx containers using docker stats.
      # The output is formatted as CSV with the container name, CPU percentage, memory usage, and network I/O (received and transmitted bytes).
      stats_output=$(docker stats --no-stream --format "{{.Name}},{{.CPUPerc}},{{.MemUsage}},{{.NetIO}}" oqs-locust oqs-nginx 2>/dev/null)
      
      # Grab the timestamp the moment the snapshot finishes
      current_time=$(date '+%Y-%m-%d %H:%M:%S')

      # Write both container stats to the file with the exact same timestamp.
      # At this point, stats_output contains two lines, one for each container separated by a newline character. The while loop reads each line 
      # of stats_output, and if the line is not empty, it appends the current timestamp and the line to the cpu_log_file.
      echo "${stats_output}" | while read -r line; do
        # Make sure the line is not empty before writing to the log file.
        if [ -n "${line}" ]; then 
          echo "${current_time},${line}" >> "${cpu_log_file}"
        fi
      done
      
    done

    log "Benchmark finished. Resource collection closed."
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
  kill $CPU_MONITOR_PID 2>/dev/null || true
  wait $CPU_MONITOR_PID 2>/dev/null || true

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

# == Main Execution =============================================================

main() {
  log "Starting KD protocol benchmark matrix sweep."
  log "KEM groups: ${!KEM_GROUPS[*]}"
  log "User levels: ${USER_LEVELS[*]}"
  log "Duration per run: ${DURATION}"

  cd "${PROJECT_DIR}"

  # Ensure a clean slate before the sweep starts.
  teardown

  local total_combinations=$(( ${#KEM_GROUPS[@]} * ${#USER_LEVELS[@]} * ${#LATENCIES[@]} * ${#LOSS_LEVELS[@]} ))
  local total_trials_performed=0
  total_trials=$(( total_combinations * REPETITIONS_PER_TEST ))

  for kem_label in "${!KEM_GROUPS[@]}"; do
    kem_value="${KEM_GROUPS[${kem_label}]}"
    start_up_containers "${kem_label}" "${kem_value}"

    for users in "${USER_LEVELS[@]}"; do
      for latency in "${LATENCIES[@]}"; do
        for loss in "${LOSS_LEVELS[@]}"; do
          for ((rep=1; rep<=REPETITIONS_PER_TEST; rep++)); do
            run_one_combination "${kem_label}" "${kem_value}" "${users}" "${latency}" "${loss}" "${rep}" "$((total_trials_performed + 1))"
            total_trials_performed=$((total_trials_performed + 1))

            if [ $((total_trials_performed % 3)) -eq 0 ]; then
              clear
            fi
          done
        done
      done
    done

    teardown

  done

  log "Matrix sweep complete. Results in ${RESULTS_DIR}/"

  rm -f nginx/nginx.conf
}

main "$@"