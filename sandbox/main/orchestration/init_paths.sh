#!/usr/bin/env bash

resolve_collection_dir() {
  if (( RESUME_MODE == 1 )); then
    validate_resume_collection_dir "$1"
    echo "${RESUME_COLLECTION_DIR}"
  else
    local default_collection_name="collection_$(date +%Y%m%d_%H%M%S)"
    echo "${DATA_DIR}/${default_collection_name}"
  fi
}

init_paths() {
  # Resolve project paths and collection targets before the sweep starts.
  PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

  NGINX_TMPL="${PROJECT_DIR}/nginx/nginx.conf.tmpl"
  NGINX_CONF="${PROJECT_DIR}/nginx/nginx.conf"

  DATA_DIR="${PROJECT_DIR}/data"
  COLLECTION_DIR="${DATA_DIR}/$(resolve_collection_dir "${DATA_DIR}")"

  RESULTS_DIR="${COLLECTION_DIR}/results"
  export PCAP_DIR="${COLLECTION_DIR}/pcaps"

  LOG_DIR="${COLLECTION_DIR}/logs"
  MAIN_LOG_FILE="${LOG_DIR}/run_matrix.log"
  LOCUST_OUT_DIR="${PROJECT_DIR}/locust"

  # Create untracked output directories/files so fresh clones can run immediately.
  mkdir -p "${COLLECTION_DIR}" "${RESULTS_DIR}" "${PCAP_DIR}" "${LOG_DIR}"
  touch "${MAIN_LOG_FILE}" "${COLLECTION_DIR}/run_info.txt"
}