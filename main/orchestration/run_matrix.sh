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

# Resolves a "kemIdx_networkIdx_usersIdx" cell string into its labels/values and
# a human-readable cell_label (matches a trial's run_id with "_repN" stripped).
resolve_cell() {
  local cell="$1"

  IFS='_' read -r kem_idx network_idx users_idx <<< "${cell}"

  kem_label="${sorted_kem_labels[${kem_idx}]}"
  kem_value="${KEM_GROUPS[${kem_label}]}"

  local network_label="${sorted_network_labels[${network_idx}]}"
  local network_condition="${NETWORK_CONDITIONS[${network_label}]}" # in the form of "rtt=10ms loss=0%"

  # Regex to capture digits after rtt= and loss=
  if [[ $network_condition =~ rtt=([0-9]+)ms[[:space:]]+loss=([0-9]+)% ]]; then
    rtt="${BASH_REMATCH[1]}"
    loss="${BASH_REMATCH[2]}"
  else
    log "ERROR: Failed to parse network condition for ${network_label} (${network_condition})."
    exit 1
  fi

  users="${USER_LEVELS[${users_idx}]}"
  cell_label="${kem_label}_u${users}_rtt${rtt}ms_loss${loss}pct"
}

run_cell() {
  local cell="$1"
  local trial_start="$2"
  local trial_end="$3"
  local -n current_trial_number_ref="$4"

  local kem_label kem_value rtt loss users cell_label
  resolve_cell "${cell}"

  local reps
  reps="$(get_reps_for_cell "${cell_label}")"

  CELL_DIR="${COLLECTION_DIR}/${cell_label}"
  mkdir -p "${CELL_DIR}"
  export CELL_DIR

  init_throttle_stats_csv
  init_cell_info "${cell_label}" "${reps}"

  log "================================================================="
  log "Beginning cell ${cell_label} (${reps} repetition(s))..."
  log "================================================================="

  for ((rep=1; rep<=reps; rep++)); do
    if (( current_trial_number_ref >= trial_start && current_trial_number_ref <= trial_end )); then
      start_up_containers "${kem_label}" "${kem_value}"
      run_one_combination "${kem_label}" "${kem_value}" "${users}" "${rtt}" "${loss}" "${rep}" "$((current_trial_number_ref))"
      teardown
    fi

    (( current_trial_number_ref += 1 ))
  done
}

main() {
  init_paths
  cd "${PROJECT_DIR}"

  local all_cells=()
  for ((kem_idx=0; kem_idx<${#sorted_kem_labels[@]}; kem_idx++)); do
    for ((network_idx=0; network_idx < ${#sorted_network_labels[@]}; network_idx++)); do
      for ((users_idx=0; users_idx < ${#USER_LEVELS[@]}; users_idx++)); do
        all_cells+=("${kem_idx}_${network_idx}_${users_idx}")
      done
    done
  done

  local cell_order=("${all_cells[@]}")
  if ${SHUFFLE_CELL_ORDER}; then
    cell_order=( $(shuf -e "${cell_order[@]}") )
  fi

  local total_trials=0
  for cell in "${cell_order[@]}"; do
    local kem_label kem_value rtt loss users cell_label
    resolve_cell "${cell}"
    (( total_trials += $(get_reps_for_cell "${cell_label}") ))
  done

  local trial_start=1
  local trial_end=${total_trials}

  if (( RESUME_MODE == 1 )); then
    trial_start="${RESUME_TRIAL_START}"
    trial_end="${RESUME_TRIAL_END}"

    log "════════════════════════════════════════════════════════════"
    log "Resuming interrupted sweep in ${COLLECTION_DIR}."
    log "Resume window: trials ${trial_start}-${trial_end}."
    log "════════════════════════════════════════════════════════════"
  fi

  # Ensure a clean slate before the sweep starts.
  teardown

  init_run_info

  local current_trial_number=1
  for cell in "${cell_order[@]}"; do
    run_cell "${cell}" "${trial_start}" "${trial_end}" current_trial_number
  done

  log "Matrix sweep complete."
  rm -f "${NGINX_CONF}"
}

main "$@"