#!/usr/bin/env bash

parse_args() {
  if [[ "$#" -eq 0 ]]; then
    return 0
  fi

  if [[ "$1" != "--resume" ]]; then
    echo "ERROR: Unknown argument: $1" >&2
    exit 1
  fi

  if [[ "$#" -ne 4 ]]; then
    echo "ERROR: Invalid number of arguments for --resume." >&2
    exit 1
  fi

  RESUME_MODE=1
  RESUME_COLLECTION_NAME="$2"
  RESUME_TRIAL_START="$3"
  RESUME_TRIAL_END="$4"
}