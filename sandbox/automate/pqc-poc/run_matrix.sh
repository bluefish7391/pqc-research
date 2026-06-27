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
  if ! docker compose exec -T oqs-locust \
    sh -lc "printf 'GET /health HTTP/1.1\\r\\nHost: oqs-nginx\\r\\nConnection: close\\r\\n\\r\\n' | '${openssl_bin}' s_client -connect oqs-nginx:4433 -groups '${kem_value}' -quiet >/dev/null 2>&1"; then
    log "ERROR: preflight handshake failed for ${kem_label} (${kem_value})."
    log "ERROR: Client/Server TLS groups likely do not match or classical group is unsupported in this image build."
    docker compose logs --tail=80 oqs-nginx || true
    return 1
  fi

  log "Preflight handshake OK for ${kem_label} (${kem_value})."
}

start_up_containers() {
  local kem_label="$1"
  local kem_value="$2"

  teardown

  log "Starting up containers for KEM group ${kem_label} (${kem_value})..."

  export OQS_KEM_GROUP="${kem_value}"

  render_nginx_conf "${kem_value}"
  docker compose up -d --build oqs-nginx

  if ! wait_for_healthy; then
    log "ERROR: nginx did not become healthy for KEM group ${kem_label} (${kem_value})."
    teardown
    return 1
  fi

  docker compose up -d --build oqs-locust

  docker compose exec -T -u root oqs-locust sed -i 's/https:\/\//http:\/\//g' /etc/apk/repositories
  docker compose exec -T -u root oqs-locust apk add --no-cache iproute2 tshark

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
  docker compose exec -T -u root oqs-locust tc qdisc add dev eth0 root netem delay "${latency_ms}ms" loss "${loss_pct}%"

  docker compose exec -T -u root oqs-locust \
    tshark \
      -i eth0 \
      -f "host oqs-nginx and tcp port 4433" \
      -w "/mnt/pcaps/${run_id}.pcap" \
    &
  TSHARK_PID=$!
  sleep 1

  local cpu_log_file="${RESULTS_DIR}/cpu_matrix_${run_id}.csv"
  echo "Timestamp,Container,CPU_Pct,Mem_Usage,Net_IO_Rx_Tx" > "${cpu_log_file}"

  log "Spawning background monitor (waiting for locust to spin up)..."
  (
    # 1. Block and wait until the 'locust' process appears inside the container
    until docker top oqs-locust 2>/dev/null | grep -E "locust" >/dev/null 2>&1; do
      sleep 0.2
    done

    log "Locust detected! Tracking CPU, Mem, and Network volume..."

    # 2. Loop continuously while locust is alive
    while docker top oqs-locust 2>/dev/null | grep -E "locust" >/dev/null 2>&1; do
      
      # Use --no-stream to force a fresh CPU delta calculation.
      # This inherently takes ~1 second to run, acting as its own perfect timer!
      stats_output=$(docker stats --no-stream --format "{{.Name}},{{.CPUPerc}},{{.MemUsage}},{{.NetIO}}" oqs-locust oqs-nginx 2>/dev/null)
      
      # Grab the timestamp the moment the snapshot finishes
      current_time=$(date '+%Y-%m-%d %H:%M:%S')

      # Write both container stats to the file with the exact same timestamp
      echo "${stats_output}" | while read -r line; do
        if [ -n "${line}" ]; then
          echo "${current_time},${line}" >> "${cpu_log_file}"
        fi
      done
      
    done

    log "Benchmark finished. Resource collection closed."
  ) &
  CPU_MONITOR_PID=$!

  # Run Locust headless INSIDE the already-up container via docker compose run,
  # overriding the default `command` to pass headless flags explicitly.
  # We run it as a one-off `exec` against the running container so the
  # service's environment (OQS_KEM_GROUP, etc.) is preserved.
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

  kill $CPU_MONITOR_PID 2>/dev/null || true
  wait $CPU_MONITOR_PID 2>/dev/null || true

  docker compose exec -T -u root oqs-locust pkill -SIGINT tshark 2>/dev/null || true
  wait $TSHARK_PID 2>/dev/null || true

  extract_pcap_metrics "${run_id}"

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

  docker compose exec -T oqs-locust \
    tshark -r "${pcap}" -q \
      -z "io,stat,0,tcp.len,tcp.analysis.retransmission" \
    > "${out}" 2>&1 || log "WARNING: tshark summary failed for ${run_id}"
}

# ── Main sweep ───────────────────────────────────────────────────────────

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