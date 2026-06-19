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

# ── Matrix definition ───────────────────────────────────────────────────
# IMPORTANT: confirm these group strings match what your specific
# openquantumsafe/nginx:latest build's OQS-OpenSSL provider expects.
# Check with:
#   docker run --rm openquantumsafe/nginx:latest openssl list -kem-algorithms
# Naming has varied across OQS-provider versions (e.g. mlkem768 vs MLKEM768
# vs draft names like kyber768). Edit the values below, not the labels.
declare -A KEM_GROUPS=(
  [classical]="x25519"
  [hybrid]="X25519MLKEM768"
  [pure-pq]="MLKEM768"
)

USER_LEVELS=(1 10 25 50)

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
RESULTS_DIR="${PROJECT_DIR}/results"
LOCUST_OUT_DIR="${PROJECT_DIR}/locust"   # locust --csv writes here (volume-mounted)

mkdir -p "${RESULTS_DIR}"

# ── Helpers ──────────────────────────────────────────────────────────────

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
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
  docker compose -f "${PROJECT_DIR}/docker-compose.yml" down -v --remove-orphans || true
}

run_one_combination() {
  local kem_label="$1"
  local kem_value="$2"
  local users="$3"
  local spawn_rate
  spawn_rate="$(SPAWN_RATE_FN "${users}")"

  local run_id="${kem_label}_u${users}"
  log "════════════════════════════════════════════════════════════"
  log "RUN: kem=${kem_label} (${kem_value})  users=${users}  duration=${DURATION}"
  log "════════════════════════════════════════════════════════════"

  render_nginx_conf "${kem_value}"

  log "Bringing stack up (docker compose up -d --build)..."
  # OQS_KEM_GROUP must match kem_value or the handshake fails — export it
  # so docker compose's environment interpolation picks it up for oqs-locust.
  export OQS_KEM_GROUP="${kem_value}"
  docker compose -f "${PROJECT_DIR}/docker-compose.yml" up -d --build oqs-nginx

  if ! wait_for_healthy; then
    log "Skipping run ${run_id} due to unhealthy nginx."
    teardown
    return 1
  fi

  # Bring up locust container too, now that nginx is confirmed healthy.
  docker compose -f "${PROJECT_DIR}/docker-compose.yml" up -d --build oqs-locust

  # Run Locust headless INSIDE the already-up container via docker compose run,
  # overriding the default `command` to pass headless flags explicitly.
  # We run it as a one-off `exec` against the running container so the
  # service's environment (OQS_KEM_GROUP, etc.) is preserved.
  log "Starting headless Locust run..."
  docker compose -f "${PROJECT_DIR}/docker-compose.yml" exec -T oqs-locust \
    locust \
      --locustfile /mnt/locust/locustfile.py \
      --host https://oqs-nginx:4433 \
      --headless \
      --users "${users}" \
      --spawn-rate "${spawn_rate}" \
      --run-time "${DURATION}" \
      --csv "/mnt/locust/results_${run_id}" \
      --csv-full-history \
    || log "WARNING: locust exited non-zero for ${run_id} (check stats before discarding the run)"

  # Copy result CSVs out of the bind-mounted locust dir into results/,
  # tagged with the combination so the matrix sweep doesn't overwrite itself.
  if compgen -G "${LOCUST_OUT_DIR}/results_${run_id}*" > /dev/null; then
    cp "${LOCUST_OUT_DIR}"/results_"${run_id}"* "${RESULTS_DIR}/"
    log "Copied results_${run_id}* to ${RESULTS_DIR}/"
  else
    log "WARNING: no CSV output found for ${run_id} — check locust container logs."
  fi

  teardown
}

# ── Main sweep ───────────────────────────────────────────────────────────

main() {
  log "Starting KD protocol benchmark matrix sweep."
  log "KEM groups: ${!KEM_GROUPS[*]}"
  log "User levels: ${USER_LEVELS[*]}"
  log "Duration per run: ${DURATION}"

  # Ensure a clean slate before the sweep starts.
  teardown

  for kem_label in "${!KEM_GROUPS[@]}"; do
    kem_value="${KEM_GROUPS[${kem_label}]}"
    for users in "${USER_LEVELS[@]}"; do
      run_one_combination "${kem_label}" "${kem_value}" "${users}"
    done
  done

  log "Matrix sweep complete. Results in ${RESULTS_DIR}/"
}

main "$@"