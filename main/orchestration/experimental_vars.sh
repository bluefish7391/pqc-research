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
# Values below come from pilot power analysis.
declare -A REPS_PER_CELL=(
  ["classical_u100_rtt100ms_loss2pct"]=14
  ["classical_u100_rtt10ms_loss0pct"]=3
  ["classical_u100_rtt200ms_loss5pct"]=10
  ["classical_u100_rtt50ms_loss1pct"]=16
  ["classical_u10_rtt100ms_loss2pct"]=20
  ["classical_u10_rtt10ms_loss0pct"]=2
  ["classical_u10_rtt200ms_loss5pct"]=10
  ["classical_u10_rtt50ms_loss1pct"]=101
  ["classical_u50_rtt100ms_loss2pct"]=29
  ["classical_u50_rtt10ms_loss0pct"]=2
  ["classical_u50_rtt200ms_loss5pct"]=10
  ["classical_u50_rtt50ms_loss1pct"]=81
  ["hybrid_u100_rtt100ms_loss2pct"]=18
  ["hybrid_u100_rtt10ms_loss0pct"]=3
  ["hybrid_u100_rtt200ms_loss5pct"]=19
  ["hybrid_u100_rtt50ms_loss1pct"]=63
  ["hybrid_u10_rtt100ms_loss2pct"]=29
  ["hybrid_u10_rtt10ms_loss0pct"]=11
  ["hybrid_u10_rtt200ms_loss5pct"]=24
  ["hybrid_u10_rtt50ms_loss1pct"]=29
  ["hybrid_u50_rtt100ms_loss2pct"]=17
  ["hybrid_u50_rtt10ms_loss0pct"]=3
  ["hybrid_u50_rtt200ms_loss5pct"]=15
  ["hybrid_u50_rtt50ms_loss1pct"]=16
)

get_reps_for_cell() {
  local cell_label="$1"
  echo "${REPS_PER_CELL[${cell_label}]:-${REPETITIONS_PER_TEST}}"
}

SHUFFLE_TRIAL_ORDER=true     # TODO: Make this configurable via command-line argument or environment variable.