#!/usr/bin/env bash

THROTTLE_ALIASES=(lt rt ws)
THROTTLE_METRICS=(nr_periods nr_throttled throttled_usec)
declare -A THROTTLE_CONTAINERS=(
  [lt]="oqs-locust"
  [rt]="router"
  [ws]="oqs-nginx"
)

throttle_metric_suffix() {
  local metric_name="$1"
  case "${metric_name}" in
    nr_periods) echo "nrp" ;;
    nr_throttled) echo "nrt" ;;
    throttled_usec) echo "tu" ;;
    *)
      log "ERROR: Unknown throttle metric '${metric_name}'"
      return 1
      ;;
  esac
}

capture_throttle_stats_batch() {
  local phase="$1"
  local -n snapshot_map_ref="$2"
  local alias
  local container_name
  local stats_var_name

  snapshot_map_ref=()

  for alias in "${THROTTLE_ALIASES[@]}"; do
    container_name="${THROTTLE_CONTAINERS[${alias}]}"
    stats_var_name="throttle_${alias}_${phase}"

    declare -g -A "${stats_var_name}=()"

    if ! record_throttle_stats_for_container "${container_name}" "${stats_var_name}"; then
      log "ERROR: Failed throttle capture for alias=${alias}, container=${container_name}, phase=${phase}"
      return 1
    fi

    snapshot_map_ref["${alias}"]="${stats_var_name}"
  done
}

record_throttle_stats_for_container() {
  local container_name="$1"
  local -n stats_array_ref="$2"
  local cpu_stat_output
  local metric

  stats_array_ref=()

  if ! cpu_stat_output="$(docker compose exec -T "${container_name}" cat /sys/fs/cgroup/cpu.stat 2>/dev/null)"; then
    log "ERROR: Failed to read CPU throttle stats for container ${container_name}"
    return 1
  fi

  while read -r key value; do
    case "${key}" in
      nr_periods|nr_throttled|throttled_usec)
        stats_array_ref["${key}"]="${value}"
        ;;
    esac
  done <<< "${cpu_stat_output}"

  for metric in "${THROTTLE_METRICS[@]}"; do
    if [[ -z "${stats_array_ref[${metric}]:-}" ]]; then
      log "ERROR: Missing throttle metric ${metric} for container ${container_name}"
      return 1
    fi
  done
}

write_throttle_stats() {
  local run_id="$1"
  local out_file="${RESULTS_DIR}/throttle_stats.csv"
  local throttle_capture_ok="$2"
  local -n before_snapshot_map="$3"
  local -n after_snapshot_map="$4"
  local row="${run_id}"
  local alias
  local metric
  local before_var_name
  local after_var_name
  local delta

  for alias in "${THROTTLE_ALIASES[@]}"; do
    before_var_name="${before_snapshot_map[${alias}]:-}"
    after_var_name="${after_snapshot_map[${alias}]:-}"

    if [[ -z "${before_var_name}" || -z "${after_var_name}" ]]; then
      log "ERROR: Missing snapshot references for alias ${alias} (run ${run_id})"
      return 1
    fi

    local -n before_stats_ref="${before_var_name}"
    local -n after_stats_ref="${after_var_name}"

    for metric in "${THROTTLE_METRICS[@]}"; do
      if [[ -z "${before_stats_ref[${metric}]:-}" || -z "${after_stats_ref[${metric}]:-}" ]]; then
        log "ERROR: Missing metric ${metric} for alias ${alias} (run ${run_id})"
        return 1
      fi
      
      row+=",${before_stats_ref[${metric}]},${after_stats_ref[${metric}]}"
    done
  done

  if [ "${throttle_capture_ok}" -ne 1 ]; then
    log "WARNING: Throttle capture failed for ${run_id}; writing row with available data."
    row+=",CAPTURE_FAILED"
  else
    log "Writing throttle stats for ${run_id}: ${row}"
    row+=",CAPTURE_SUCCEEDED"
  fi

  if ! printf '%s\n' "${row}" >> "${out_file}"; then
    log "ERROR: Failed to write throttle stats for ${run_id}"
    return 1
  fi
}