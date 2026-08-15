#!/usr/bin/env bash

init_cell_info() {
  local cell_label="$1"
  local reps="$2"

  local cell_info_file_path="${CELL_DIR}/cell_info.txt"
  touch "${cell_info_file_path}"

  cat << EOF >> "${cell_info_file_path}"
Cell info for ${cell_label} started at $(date '+%Y-%m-%d %H:%M:%S')
Repetitions for this cell: ${reps}
EOF
}

init_run_info() {
  local run_info_file_path="${COLLECTION_DIR}/run_info.txt"
  touch "${run_info_file_path}"

  if (( RESUME_MODE == 0 )); then
  { 
      cat << EOF
Run info for collection run started at $(date '+%Y-%m-%d %H:%M:%S')
KEM groups: ${!KEM_GROUPS[*]}
User levels: ${USER_LEVELS[*]}
RTTs (ms): ${RTTS[*]}
Loss levels (%): ${LOSS_LEVELS[*]}
Target handshakes per trial: ${TARGET_HANDSHAKES}
Max duration per run: ${MAX_DURATION}
Shuffle trial order: ${SHUFFLE_TRIAL_ORDER}
Default repetitions per cell: ${REPETITIONS_PER_TEST}
Per-cell repetition overrides: ${!REPS_PER_CELL[*]-none}
EOF
  } >> "${run_info_file_path}"
  
  fi
}

log_trial_order() {
  local -n trial_units_ref="$1"
  local run_info_file_path="${COLLECTION_DIR}/run_info.txt"

  if (( RESUME_MODE == 0 )); then
    local trial_unit cell rep kem_label kem_value rtt loss users cell_label
    {
      echo "Trial execution order (cell_label:repetition), ${#trial_units_ref[@]} total:"
      for trial_unit in "${trial_units_ref[@]}"; do
        IFS=':' read -r cell rep <<< "${trial_unit}"
        resolve_cell "${cell}"
        echo "${cell_label}:${rep}"
      done
    } >> "${run_info_file_path}"
  fi
}

init_throttle_stats_csv() {
  local out_file="${CELL_DIR}/throttle_stats.csv"
  local header="run_id"
  local alias
  local metric
  local metric_suffix

  for alias in "${THROTTLE_ALIASES[@]}"; do
    for metric in "${THROTTLE_METRICS[@]}"; do
      if ! metric_suffix="$(throttle_metric_suffix "${metric}")"; then
        return 1
      fi
      header+=",${alias}_${metric_suffix}_before,${alias}_${metric_suffix}_after"
    done
  done

  header+=",capture_status"

  if ! printf '%s\n' "${header}" > "${out_file}"; then
    log "ERROR: Failed to initialize ${out_file}"
    return 1
  fi
}