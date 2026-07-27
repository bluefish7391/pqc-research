#!/usr/bin/env bash
# ========================================================================
#  Usage:
#    ./run_matrix.sh
#    ./run_matrix.sh --resume <collection_name> <start_trial> <end_trial>
# ========================================================================

# Set strict mode for bash: exit on error, treat unset variables as errors, and fail on any command in a pipeline that fails.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source "${SCRIPT_DIR}/experimental_vars.sh"
source "${SCRIPT_DIR}/helpers.sh"
source "${SCRIPT_DIR}/resume_sweep.sh"
source "${SCRIPT_DIR}/init_paths.sh"
source "${SCRIPT_DIR}/init_logs.sh"
source "${SCRIPT_DIR}/run_trial.sh"
source "${SCRIPT_DIR}/start_containers.sh"

# Disable automatic path conversion on Windows (MSYS2 / Git Bash) to avoid
# issues with volume mounts and file paths in docker compose.
# Environment variable inherited by subprocesses spawned by this script for 
# this shell session, including docker compose itself.
export MSYS_NO_PATHCONV=1

resume_init_state # Declares and initializes variables related to resuming a sweep.
resume_parse_args "$@" # Parses command-line arguments to determine if the script should resume a previous sweep or start a new one. Sets associated variables accordingly.

init_paths

main() {
  if (( RESUME_MODE == 1 )); then
    log "════════════════════════════════════════════════════════════"
    log "Resuming interrupted sweep in ${COLLECTION_DIR}."
    log "Resume window: trials ${RESUME_TRIAL_START}-${RESUME_TRIAL_END}."
    log "════════════════════════════════════════════════════════════"
  else
    init_logs
  fi

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