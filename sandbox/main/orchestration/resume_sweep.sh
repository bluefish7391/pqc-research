#!/usr/bin/env bash

resume_init_state() {
  RESUME_MODE=0
  RESUME_COLLECTION_NAME=""
  RESUME_TRIAL_START=""
  RESUME_TRIAL_END=""
  RESUME_COLLECTION_DIR=""
  RESUME_TRIALS_TO_SKIP_AT_START=0
  RESUME_TRIALS_TO_SKIP_AT_END=0
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

resume_resolve_collection_dir() {
  local data_dir="$1"
  local default_collection_name="$2"

  if (( RESUME_MODE == 1 )); then
    if [[ "${RESUME_COLLECTION_NAME}" == *"/"* ]]; then
      echo "ERROR: Resume collection name must be a directory name under ${data_dir}, not a path: ${RESUME_COLLECTION_NAME}" >&2
      return 1
    fi

    RESUME_COLLECTION_DIR="${data_dir}/${RESUME_COLLECTION_NAME}"
    if [[ ! -d "${RESUME_COLLECTION_DIR}" ]]; then
      echo "ERROR: Resume collection directory does not exist: ${RESUME_COLLECTION_DIR}" >&2
      return 1
    fi
  else
    RESUME_COLLECTION_DIR="${data_dir}/${default_collection_name}"
  fi
}

resume_compute_skip_window() {
  local total_trials="$1"

  RESUME_TRIALS_TO_SKIP_AT_START=0
  RESUME_TRIALS_TO_SKIP_AT_END=0

  if (( RESUME_MODE == 0 )); then
    return 0
  fi

  if [[ ! "${RESUME_TRIAL_START}" =~ ^[0-9]+$ ]] || [[ ! "${RESUME_TRIAL_END}" =~ ^[0-9]+$ ]]; then
    echo "ERROR: Resume trial bounds must be positive integers." >&2
    return 1
  fi

  if (( RESUME_TRIAL_START < 1 )); then
    echo "ERROR: Resume start trial must be at least 1." >&2
    return 1
  fi

  if (( RESUME_TRIAL_END < RESUME_TRIAL_START )); then
    echo "ERROR: Resume end trial must be greater than or equal to the start trial." >&2
    return 1
  fi

  if (( RESUME_TRIAL_END > total_trials )); then
    echo "ERROR: Resume end trial ${RESUME_TRIAL_END} exceeds total trials ${total_trials}." >&2
    return 1
  fi

  RESUME_TRIALS_TO_SKIP_AT_START=$(( RESUME_TRIAL_START - 1 ))
  RESUME_TRIALS_TO_SKIP_AT_END=$(( total_trials - RESUME_TRIAL_END ))
}