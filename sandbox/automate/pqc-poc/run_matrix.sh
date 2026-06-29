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

source ./run_trial.sh

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

DURATION="60s" # Headless Locust run duration per combination (seconds).
REPETITIONS_PER_TEST=1 # Number of times to repeat each combination for averaging or variance analysis.

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
            (( total_trials_performed += 1 ))

            # Clear the terminal every 3 trials to keep the output manageable and avoid cluttering the screen with too many logs.
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