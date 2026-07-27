#!/usr/bin/env bash
# ========================================================================
#  Usage:
#    ./run_matrix.sh
#    ./run_matrix.sh --resume <collection_name> <start_trial> <end_trial>
# ========================================================================

# Set strict mode for bash: exit on error, treat unset variables as errors, and fail on any command in a pipeline that fails.
set -euo pipefail

source ./parse_args.sh
source ./run_trial.sh
source ./start_containers.sh

# Disable automatic path conversion on Windows (MSYS2 / Git Bash) to avoid
# issues with volume mounts and file paths in docker compose.
# Environment variable inherited by subprocesses spawned by this script for 
# this shell session, including docker compose itself.
export MSYS_NO_PATHCONV=1

RESUME_MODE=0
RESUME_COLLECTION_NAME=""
RESUME_TRIAL_START=""
RESUME_TRIAL_END=""

parse_args "$@"

# KEM_GROUPS is an associative array (like a dictionary or a hashmap) mapping
# a human-readable label to the corresponding OpenSSL group name. The label 
# is used in output filenames and logs.
declare -A KEM_GROUPS=(
  ["classical"]="X25519"
  ["hybrid"]="X25519MLKEM768"
)

readarray -t sorted_kem_labels < <(printf '%s\n' "${!KEM_GROUPS[@]}" | sort)

SPAWN_RATE=25
USER_LEVELS=(1 10 25 100) # Number of concurrent users to simulate in Locust. This is the -u parameter for locust.
RTTS=(10 50 100 200)         # Round-trip time in milliseconds. This is the artificial latency that will be introduced in the network emulation.
LOSS_LEVELS=(0 1 2 3)  # Packet loss percentage. This is the percentage of packets that will be randomly dropped in the network emulation.

TARGET_HANDSHAKES=10000 # Total number of handshakes to perform in each trial.
MAX_DURATION="10000s" # Headless Locust run max duration per combination (seconds).
REPETITIONS_PER_TEST=1 # Number of times to repeat each combination for averaging or variance analysis.

# Identifies the name of this file, then the directory containing said file, and sets PROJECT_DIR to the parent of said directory.
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

NGINX_TMPL="${PROJECT_DIR}/nginx/nginx.conf.tmpl"
NGINX_CONF="${PROJECT_DIR}/nginx/nginx.conf"

DATA_DIR="${PROJECT_DIR}/data"
if (( RESUME_MODE == 1 )); then
  if [[ "${RESUME_COLLECTION_NAME}" == *"/"* ]]; then
    echo "ERROR: Resume collection name must be a directory name under ${DATA_DIR}, not a path: ${RESUME_COLLECTION_NAME}" >&2
    exit 1
  fi

  COLLECTION_DIR="${DATA_DIR}/${RESUME_COLLECTION_NAME}"
  if [[ ! -d "${COLLECTION_DIR}" ]]; then
    echo "ERROR: Resume collection directory does not exist: ${COLLECTION_DIR}" >&2
    exit 1
  fi
else
  COLLECTION_DIR="${DATA_DIR}/pre-pilot"
fi

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

# == Helpers ==================================================================

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "${MAIN_LOG_FILE}"
}

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

  local TRIALS_TO_SKIP_AT_START=0 # Derived from resume start trial when resuming an interrupted sweep.
  local TRIALS_TO_SKIP_AT_END=0 # Derived from resume end trial when resuming an interrupted sweep.

  if (( RESUME_MODE == 1 )); then
    if [[ ! "${RESUME_TRIAL_START}" =~ ^[0-9]+$ ]] || [[ ! "${RESUME_TRIAL_END}" =~ ^[0-9]+$ ]]; then
      log "ERROR: Resume trial bounds must be positive integers."
      return 1
    fi

    if (( RESUME_TRIAL_START < 1 )); then
      log "ERROR: Resume start trial must be at least 1."
      return 1
    fi

    if (( RESUME_TRIAL_END < RESUME_TRIAL_START )); then
      log "ERROR: Resume end trial must be greater than or equal to the start trial."
      return 1
    fi

    if (( RESUME_TRIAL_END > total_trials )); then
      log "ERROR: Resume end trial ${RESUME_TRIAL_END} exceeds total trials ${total_trials}."
      return 1
    fi

    TRIALS_TO_SKIP_AT_START=$(( RESUME_TRIAL_START - 1 ))
    TRIALS_TO_SKIP_AT_END=$(( total_trials - RESUME_TRIAL_END ))
  fi

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