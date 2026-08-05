#!/usr/bin/env bash

init_sweep_info() {
  local sweep_num="$1"
  local -n cell_order="$2"

  local sweep_info_file_path="${SWEEP_DIR}/sweep_info.txt"
  touch "${sweep_info_file_path}"

  local joined_cells
  {
    local IFS=", "
    joined_cells="${cell_order[*]-}"
  }

  cat << EOF >> "${sweep_info_file_path}"
Sweep info for sweep ${sweep_num} started at $(date '+%Y-%m-%d %H:%M:%S')
Cell order: ${joined_cells}
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
Shuffle cell order: ${SHUFFLE_CELL_ORDER}
Sweeps to perform: ${REPETITIONS_PER_TEST}
EOF
  } >> "${run_info_file_path}"
  
  fi
}

init_throttle_stats_csv() {
  local out_file="${SWEEP_DIR}/throttle_stats.csv"
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