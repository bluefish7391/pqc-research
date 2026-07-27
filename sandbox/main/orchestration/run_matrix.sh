#!/usr/bin/env bash
# ========================================================================
#  Usage:
#    ./run_matrix.sh
#    ./run_matrix.sh --resume <collection_name> <start_trial> <end_trial>
# ========================================================================

# Set strict mode for bash: exit on error, treat unset variables as errors, and fail on any command in a pipeline that fails.
set -euo pipefail

source ./vars.sh
source ./resume_sweep.sh
source ./run_trial.sh
source ./start_containers.sh

# Disable automatic path conversion on Windows (MSYS2 / Git Bash) to avoid
# issues with volume mounts and file paths in docker compose.
# Environment variable inherited by subprocesses spawned by this script for 
# this shell session, including docker compose itself.
export MSYS_NO_PATHCONV=1

resume_init_state # Declares and initializes variables related to resuming a sweep.
resume_parse_args "$@" # Parses command-line arguments to determine if the script should resume a previous sweep or start a new one. Sets associated variables accordingly.

# Identifies the name of this file, then the directory containing said file, and sets PROJECT_DIR to the parent of said directory.
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

NGINX_TMPL="${PROJECT_DIR}/nginx/nginx.conf.tmpl"
NGINX_CONF="${PROJECT_DIR}/nginx/nginx.conf"

DATA_DIR="${PROJECT_DIR}/data"
resume_resolve_collection_dir "${DATA_DIR}"
COLLECTION_DIR="${RESUME_COLLECTION_DIR}"

RESULTS_DIR="${COLLECTION_DIR}/results"
export PCAP_DIR="${COLLECTION_DIR}/pcaps" # Needs to be exported so that the compose file can access it as an environment variable for volume mounting.

LOG_DIR="${COLLECTION_DIR}/logs"
MAIN_LOG_FILE="${LOG_DIR}/run_matrix.log"
LOCUST_OUT_DIR="${PROJECT_DIR}/locust"

# Create directories for results, pcaps, and logs if they don't exist yet,
# as these are untracked by git and may not be present in a fresh clone.
mkdir -p "${COLLECTION_DIR}" "${RESULTS_DIR}" "${PCAP_DIR}" "${LOG_DIR}"
touch "${MAIN_LOG_FILE}" "${COLLECTION_DIR}/run_info.txt"

if (( RESUME_MODE == 0 )); then
  {
    cat << EOF
Run info for matrix sweep started at $(date '+%Y-%m-%d %H:%M:%S')
KEM groups: ${!KEM_GROUPS[*]}
User levels: ${USER_LEVELS[*]}
RTTs (ms): ${RTTS[*]}
Loss levels (%): ${LOSS_LEVELS[*]}
Target handshakes per trial: ${TARGET_HANDSHAKES}
Max duration per run: ${MAX_DURATION}
Repetitions per test: ${REPETITIONS_PER_TEST}
EOF
  } >> "${COLLECTION_DIR}/run_info.txt"
fi

if (( RESUME_MODE == 0 )); then
  init_throttle_stats_csv
fi

teardown() {
  log "Tearing down (docker compose down -v)..."
  docker compose down -v --remove-orphans || log "Warning: docker compose down failed. Continuing..."
}

main() {
  log "Starting KD protocol benchmark matrix sweep."
  if (( RESUME_MODE == 1 )); then
    log "Resuming interrupted sweep in ${COLLECTION_DIR}."
    log "Resume window: trials ${RESUME_TRIAL_START}-${RESUME_TRIAL_END}."
  fi
  log "KEM groups: ${!KEM_GROUPS[*]}"
  log "User levels: ${USER_LEVELS[*]}"
  log "RTTs (ms): ${RTTS[*]}"
  log "Loss levels (%): ${LOSS_LEVELS[*]}"
  log "Target handshakes per trial: ${TARGET_HANDSHAKES}"
  log "Max duration per run: ${MAX_DURATION}"

  cd "${PROJECT_DIR}"

  local total_combinations=$(( ${#KEM_GROUPS[@]} * ${#USER_LEVELS[@]} * ${#RTTS[@]} * ${#LOSS_LEVELS[@]} ))
  local total_trials=$(( total_combinations * REPETITIONS_PER_TEST ))

  if ! resume_compute_skip_window "${total_trials}"; then
    log "ERROR: Failed to compute resume trial window."
    return 1
  fi

  local TRIALS_TO_SKIP_AT_START="${RESUME_TRIALS_TO_SKIP_AT_START}" # Derived from resume start trial when resuming an interrupted sweep.
  local TRIALS_TO_SKIP_AT_END="${RESUME_TRIALS_TO_SKIP_AT_END}" # Derived from resume end trial when resuming an interrupted sweep.

  # Ensure a clean slate before the sweep starts.
  teardown

  local total_trials_performed=0

  for kem_label in "${sorted_kem_labels[@]}"; do
    kem_value="${KEM_GROUPS[${kem_label}]}"

    for users in "${USER_LEVELS[@]}"; do
      for rtt in "${RTTS[@]}"; do
        for loss in "${LOSS_LEVELS[@]}"; do
          for ((rep=1; rep<=REPETITIONS_PER_TEST; rep++)); do
            if (( total_trials_performed >= TRIALS_TO_SKIP_AT_START && total_trials_performed < total_trials - TRIALS_TO_SKIP_AT_END )); then
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