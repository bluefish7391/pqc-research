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
  cd "${PROJECT_DIR}"

  local total_combinations=$(( ${#KEM_GROUPS[@]} * ${#USER_LEVELS[@]} * ${#NETWORK_CONDITIONS[@]} ))
  local total_trials=$(( total_combinations * REPETITIONS_PER_TEST ))

  local trial_start=1
  local trial_end=${total_trials}

  if (( RESUME_MODE == 1 )); then
    trial_start="${RESUME_TRIAL_START}"
    trial_end="${RESUME_TRIAL_END}"

    log "════════════════════════════════════════════════════════════"
    log "Resuming interrupted sweep in ${COLLECTION_DIR}."
    log "Resume window: trials ${trial_start}-${trial_end}."
    log "════════════════════════════════════════════════════════════"
  else
    init_logs
  fi

  # Ensure a clean slate before the sweep starts.
  teardown

  local current_trial_number=1

  for kem_label in "${sorted_kem_labels[@]}"; do
    local kem_value="${KEM_GROUPS[${kem_label}]}"

    for network_label in "${sorted_network_labels[@]}"; do
      local network_condition="${NETWORK_CONDITIONS[${network_label}]}" # in the form of "rtt=10ms loss=0%"
      
      # Regex to capture digits after rtt= and loss=
      if [[ $network_condition =~ rtt=([0-9]+)ms[[:space:]]+loss=([0-9]+)% ]]; then
        local rtt="${BASH_REMATCH[1]}"
        local loss="${BASH_REMATCH[2]}"
      else
        log "ERROR: Failed to parse network condition for ${network_label} (${network_condition})."
        exit 1
      fi

      for users in "${USER_LEVELS[@]}"; do
        for ((rep=1; rep<=REPETITIONS_PER_TEST; rep++)); do
          if (( current_trial_number >= trial_start && current_trial_number <= trial_end )); then
            start_up_containers "${kem_label}" "${kem_value}"
            run_one_combination "${kem_label}" "${kem_value}" "${users}" "${rtt}" "${loss}" "${rep}" "$((current_trial_number))"
            teardown
          fi

          (( current_trial_number += 1 ))
        done
      done
      
    done
  done

  log "Matrix sweep complete. Results in ${RESULTS_DIR}/"
  rm -f "${NGINX_CONF}"
}

main "$@"