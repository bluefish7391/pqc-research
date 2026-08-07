#!/usr/bin/env bash

declare -A KEM_GROUPS=(
  ["classical"]="X25519"
  ["hybrid"]="X25519MLKEM768"
)

readarray -t sorted_kem_labels < <(printf '%s\n' "${!KEM_GROUPS[@]}" | sort)

SPAWN_RATE=10
USER_LEVELS=(10 50 100) # Number of concurrent users to simulate in Locust. This is the -u parameter for locust.

declare -A NETWORK_CONDITIONS=(
  ["B1"]="rtt=10ms loss=0%"
  ["B2"]="rtt=50ms loss=1%"
  ["B3"]="rtt=100ms loss=2%"
  ["B4"]="rtt=200ms loss=5%"
)
readarray -t sorted_network_labels < <(printf '%s\n' "${!NETWORK_CONDITIONS[@]}" | sort)

TARGET_HANDSHAKES=12000 # Total number of handshakes to perform in each trial.
MAX_DURATION="3600s" # Headless Locust run max duration per combination (seconds).
REPETITIONS_PER_TEST=10 # Number of times to repeat each combination for averaging or variance analysis.

SHUFFLE_CELL_ORDER=true     # TODO: Make this configurable via command-line argument or environment variable.