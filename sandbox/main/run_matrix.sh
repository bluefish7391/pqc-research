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
source ./start_containers.sh

# Disable automatic path conversion on Windows (MSYS2 / Git Bash) to avoid
# issues with volume mounts and file paths in docker compose.
# Environment variable inherited by subprocesses spawned by this script for 
# this shell session, including docker compose itself.
export MSYS_NO_PATHCONV=1

# KEM_GROUPS is an associative array (like a dictionary or a hashmap) mapping
# a human-readable label to the corresponding OpenSSL group name. The label 
# is used in output filenames and logs.
declare -A KEM_GROUPS=(
  ["classical"]="X25519"
  ["hybrid"]="X25519MLKEM768"
  # ["pure768"]="MLKEM768"
)

USER_LEVELS=(50)
RTTS=(0 10 25)         # Round-trip time in milliseconds. This is the artificial latency that will be introduced in the network emulation.
LOSS_LEVELS=(0 1 2)  # Packet loss percentage. This is the percentage of packets that will be randomly dropped in the network emulation.

TARGET_HANDSHAKES=1000 # Total number of handshakes to perform in each trial.
DURATION="30s" # Headless Locust run max duration per combination (seconds).
REPETITIONS_PER_TEST=3 # Number of times to repeat each combination for averaging or variance analysis.
TRIALS_TO_SKIP=0 # Number of initial trials to skip (useful for resuming an interrupted sweep).

# Identifies the name of this file, then the directory containing said file, and sets PROJECT_DIR to that path.
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

NGINX_TMPL="${PROJECT_DIR}/nginx/nginx.conf.tmpl"
NGINX_CONF="${PROJECT_DIR}/nginx/nginx.conf"

DATA_DIR="${PROJECT_DIR}/data"
COLLECTION_DIR="${DATA_DIR}/collection_$(date '+%Y%m%d_%H%M%S')"
RESULTS_DIR="${COLLECTION_DIR}/results"
export PCAP_DIR="${COLLECTION_DIR}/pcaps" # Needs to be exported so that the compose file can access it as an environment variable for volume mounting.
LOG_FILE="${COLLECTION_DIR}/run_matrix.log"
LOCUST_OUT_DIR="${PROJECT_DIR}/locust"

# Create directories for results, pcaps, and logs if they don't exist yet,
# as these are untracked by git and may not be present in a fresh clone.
mkdir -p "${COLLECTION_DIR}" "${RESULTS_DIR}" "${PCAP_DIR}"
touch "${LOG_FILE}" "${COLLECTION_DIR}/run_info.txt"

# Write run info (levels of each independent variable tested) to a file for later reference.
cat << EOF >> "${COLLECTION_DIR}/run_info.txt"
Run info for matrix sweep started at $(date '+%Y-%m-%d %H:%M:%S')
KEM groups: ${!KEM_GROUPS[*]}
User levels: ${USER_LEVELS[*]}
RTTs (ms): ${RTTS[*]}
Loss levels (%): ${LOSS_LEVELS[*]}
Duration per run: ${DURATION}
Repetitions per test: ${REPETITIONS_PER_TEST}
Trials to skip: ${TRIALS_TO_SKIP}
EOF

# == Helpers ==================================================================

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "${LOG_FILE}"
}

init_throttle_stats_csv

teardown() {
  log "Tearing down (docker compose down -v)..."
  docker compose down -v --remove-orphans || log "Warning: docker compose down failed. Continuing..."
}

main() {
  log "Starting KD protocol benchmark matrix sweep."
  log "KEM groups: ${!KEM_GROUPS[*]}"
  log "User levels: ${USER_LEVELS[*]}"
  log "Duration per run: ${DURATION}"

  cd "${PROJECT_DIR}"

  # Ensure a clean slate before the sweep starts.
  teardown

  local total_combinations=$(( ${#KEM_GROUPS[@]} * ${#USER_LEVELS[@]} * ${#RTTS[@]} * ${#LOSS_LEVELS[@]} ))
  local total_trials_performed=0
  total_trials=$(( total_combinations * REPETITIONS_PER_TEST ))

  for kem_label in "${!KEM_GROUPS[@]}"; do
    kem_value="${KEM_GROUPS[${kem_label}]}"

    for users in "${USER_LEVELS[@]}"; do
      for rtt in "${RTTS[@]}"; do
        for loss in "${LOSS_LEVELS[@]}"; do
          for ((rep=1; rep<=REPETITIONS_PER_TEST; rep++)); do
            if (( total_trials_performed >= TRIALS_TO_SKIP )); then
              start_up_containers "${kem_label}" "${kem_value}"
              run_one_combination "${kem_label}" "${kem_value}" "${users}" "${rtt}" "${loss}" "${rep}" "$((total_trials_performed + 1))"
              teardown
            fi

            (( total_trials_performed += 1 ))
          done
        done
      done
    done

    # teardown

  done

  log "Matrix sweep complete. Results in ${RESULTS_DIR}/"

  rm -f "${NGINX_CONF}"
}

main "$@"