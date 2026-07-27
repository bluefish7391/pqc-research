#!/usr/bin/env bash

init_paths() {
  # Resolve project paths and collection targets before the sweep starts.
  PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

  NGINX_TMPL="${PROJECT_DIR}/nginx/nginx.conf.tmpl"
  NGINX_CONF="${PROJECT_DIR}/nginx/nginx.conf"

  DATA_DIR="${PROJECT_DIR}/data"
  resume_resolve_collection_dir "${DATA_DIR}" "pre-pilot"
  COLLECTION_DIR="${RESUME_COLLECTION_DIR}"

  RESULTS_DIR="${COLLECTION_DIR}/results"
  export PCAP_DIR="${COLLECTION_DIR}/pcaps"

  LOG_DIR="${COLLECTION_DIR}/logs"
  MAIN_LOG_FILE="${LOG_DIR}/run_matrix.log"
  LOCUST_OUT_DIR="${PROJECT_DIR}/locust"

  # Create untracked output directories/files so fresh clones can run immediately.
  mkdir -p "${COLLECTION_DIR}" "${RESULTS_DIR}" "${PCAP_DIR}" "${LOG_DIR}"
  touch "${MAIN_LOG_FILE}" "${COLLECTION_DIR}/run_info.txt"
}