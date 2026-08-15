#!/usr/bin/env bash

declare -A KEM_GROUPS=(
  # ["classical"]="X25519"
  ["hybrid"]="X25519MLKEM768"
)

readarray -t sorted_kem_labels < <(printf '%s\n' "${!KEM_GROUPS[@]}" | sort)

SPAWN_RATE=10
USER_LEVELS=(10) # Number of concurrent users to simulate in Locust. This is the -u parameter for locust.

declare -A NETWORK_CONDITIONS=(
  # ["B1"]="rtt=10ms loss=0%"
  # ["B2"]="rtt=50ms loss=1%"
  ["B3"]="rtt=100ms loss=2%"
  # ["B4"]="rtt=200ms loss=5%"
)
readarray -t sorted_network_labels < <(printf '%s\n' "${!NETWORK_CONDITIONS[@]}" | sort)

TARGET_HANDSHAKES=15000 # Total number of handshakes to perform in each trial.
MAX_DURATION="3600s" # Headless Locust run max duration per combination (seconds).
REPETITIONS_PER_TEST=60 # Default repetition count used by cells with no REPS_PER_CELL override.

# Optional per-cell repetition overrides, keyed by cell label (same convention as a
# trial's run_id with its trailing "_repN" stripped), e.g. ["hybrid_u10_rtt100ms_loss2pct"]=30.
declare -A REPS_PER_CELL=(
)

get_reps_for_cell() {
  local cell_label="$1"
  echo "${REPS_PER_CELL[${cell_label}]:-${REPETITIONS_PER_TEST}}"
}

SHUFFLE_CELL_ORDER=true     # TODO: Make this configurable via command-line argument or environment variable.