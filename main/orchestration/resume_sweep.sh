#!/usr/bin/env bash

resume_init_state() {
  RESUME_MODE=0
  RESUME_COLLECTION_NAME=""
  RESUME_TRIAL_START=""
  RESUME_TRIAL_END=""
}

resume_parse_args() {
  if [[ "$#" -eq 0 ]]; then
    return 0
  fi

  if [[ "$1" != "--resume" ]]; then
    echo "ERROR: Unknown argument: $1" >&2
    return 1
  fi

  if [[ "$#" -ne 4 ]]; then
    echo "ERROR: Invalid number of arguments for --resume." >&2
    return 1
  fi

  RESUME_MODE=1
  RESUME_COLLECTION_NAME="$2"
  RESUME_TRIAL_START="$3"
  RESUME_TRIAL_END="$4"
}

validate_resume_collection_dir() {
  if [[ "${RESUME_COLLECTION_NAME}" == *"/"* ]]; then
    echo "ERROR: Resume collection name must be a directory name under ${DATA_DIR}, not a path: ${RESUME_COLLECTION_NAME}" >&2
    return 1
  fi

  local RESUME_COLLECTION_DIR="${DATA_DIR}/${RESUME_COLLECTION_NAME}"
  if [[ ! -d "${RESUME_COLLECTION_DIR}" ]]; then
    echo "ERROR: Resume collection directory does not exist: ${RESUME_COLLECTION_DIR}" >&2
    return 1
  fi
}