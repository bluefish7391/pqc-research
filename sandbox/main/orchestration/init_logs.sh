#!/usr/bin/env bash

init_run_info() {
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
}

init_main_log() {
    log "Starting matrix sweep."
    log "KEM groups: ${!KEM_GROUPS[*]}"
    log "User levels: ${USER_LEVELS[*]}"
    log "RTTs (ms): ${RTTS[*]}"
    log "Loss levels (%): ${LOSS_LEVELS[*]}"
    log "Target handshakes per trial: ${TARGET_HANDSHAKES}"
    log "Max duration per run: ${MAX_DURATION}"
    log "Repetitions per test: ${REPETITIONS_PER_TEST}"
}

init_throttle_stats_csv() {
  local out_file="${RESULTS_DIR}/throttle_stats.csv"
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

init_logs() {
    init_run_info
    init_throttle_stats_csv
}