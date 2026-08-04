#!/usr/bin/env bash

resolve_collection_dir() {
  if (( RESUME_MODE == 1 )); then
    validate_resume_collection_dir
    echo "${RESUME_COLLECTION_NAME}"
  else
    echo "collection_$(date +%Y%m%d_%H%M%S)"
  fi
}

init_paths() {
  # Resolve project paths and collection targets before the collection starts. Runs once per collection.
  PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

  NGINX_TMPL="${PROJECT_DIR}/nginx/nginx.conf.tmpl"
  NGINX_CONF="${PROJECT_DIR}/nginx/nginx.conf"

  DATA_DIR="${PROJECT_DIR}/data"

  COLLECTION_NAME="$(resolve_collection_dir)"
  COLLECTION_DIR="${DATA_DIR}/${COLLECTION_NAME}"
  MAIN_LOG_FILE="${COLLECTION_DIR}/run_matrix.log"

  SWEEP_NAME="sweep_1" # Updated on every sweep
  export SWEEP_DIR="${COLLECTION_DIR}/${SWEEP_NAME}"

  # Create untracked output directories/files so fresh clones can run immediately.
  mkdir -p "${COLLECTION_DIR}"
  touch "${MAIN_LOG_FILE}" "${COLLECTION_DIR}/run_info.txt"
}