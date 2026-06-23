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

export MSYS_NO_PATHCONV=1

# ── Matrix definition ───────────────────────────────────────────────────
# IMPORTANT: confirm these group strings match what your specific
# openquantumsafe/nginx:latest build's OQS-OpenSSL provider expects.
# Check with:
#   docker run --rm openquantumsafe/nginx:latest openssl list -kem-algorithms
# Naming has varied across OQS-provider versions (e.g. mlkem768 vs MLKEM768
# vs draft names like kyber768). Edit the values below, not the labels.
declare -A KEM_GROUPS=(
  [classical]="X25519"
  [hybrid]="X25519MLKEM768"
)

USER_LEVELS=(1 10)
LATENCIES=(0)
LOSS_LEVELS=(0 1)

# Headless Locust run duration per combination (seconds).
# This is now the ONLY stop condition — NUM_REQUESTS cap was removed
# from locustfile.py, so runs no longer end early.
DURATION="60s"

# Spawn rate: how fast Locust ramps to the target user count.
# Kept equal to user count so ramp-up is fast relative to DURATION;
# adjust if you want to study ramp behavior itself.
SPAWN_RATE_FN() { echo "$1"; }

# ── Paths ────────────────────────────────────────────────────────────────
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NGINX_TMPL="${PROJECT_DIR}/nginx/nginx.conf.tmpl"
NGINX_CONF="${PROJECT_DIR}/nginx/nginx.conf"
RESULTS_DIR="${PROJECT_DIR}/data/results"
LOCUST_OUT_DIR="${PROJECT_DIR}/locust"
PCAP_DIR="${PROJECT_DIR}/data/pcap"

# ── Helpers ──────────────────────────────────────────────────────────────

log() {
  local timestamped_message="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
  echo "${timestamped_message}"
  echo "${timestamped_message}" >> "${PROJECT_DIR}/logs/run_matrix.log"
}

render_nginx_conf() {
  local kem_value="$1"
  sed "s/__KEM_GROUP__/${kem_value}/" "${NGINX_TMPL}" > "${NGINX_CONF}"
  log "Rendered nginx.conf with ssl_ecdh_curve=${kem_value}"
}

wait_for_healthy() {
  local container="oqs-nginx"
  local max_wait=60
  local waited=0
  log "Waiting for ${container} healthcheck..."
  while true; do
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
    waited=$(( waited + 2 ))
  done
}

teardown() {
  log "Tearing down (docker compose down -v)..."
  docker compose down -v --remove-orphans || true
}

start_up_containers() {
  local kem_label="$1"
  local kem_value="$2"

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
}

run_one_combination() {
  local kem_label="$1"
  local kem_value="$2"
  local users="$3"
  local latency_ms="$4"
  local loss_pct="$5"
  local spawn_rate="$(SPAWN_RATE_FN "${users}")"

  local run_id="${kem_label}_u${users}_lat${latency_ms}ms_loss${loss_pct}pct"
  log "════════════════════════════════════════════════════════════"
  log "RUN: kem=${kem_label} (${kem_value})  users=${users}  latency=${latency_ms}ms  loss=${loss_pct}%  duration=${DURATION}"
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

  local combinations_tested=0

  for kem_label in "${!KEM_GROUPS[@]}"; do
    kem_value="${KEM_GROUPS[${kem_label}]}"
    start_up_containers "${kem_label}" "${kem_value}"

    for users in "${USER_LEVELS[@]}"; do
      for latency in "${LATENCIES[@]}"; do
        for loss in "${LOSS_LEVELS[@]}"; do
          run_one_combination "${kem_label}" "${kem_value}" "${users}" "${latency}" "${loss}"
          combinations_tested=$((combinations_tested + 1))

          if [ $((combinations_tested % 3)) -eq 0 ]; then
            clear
          fi
        done
      done
    done

    teardown
  done

  log "Matrix sweep complete. Tested ${combinations_tested} combinations. Results in ${RESULTS_DIR}/"

  rm -f nginx/nginx.conf
}

main "$@"