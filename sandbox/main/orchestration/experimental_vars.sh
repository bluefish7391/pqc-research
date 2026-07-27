#!/usr/bin/env bash

declare -A KEM_GROUPS=(
  ["classical"]="X25519"
  ["hybrid"]="X25519MLKEM768"
)

readarray -t sorted_kem_labels < <(printf '%s\n' "${!KEM_GROUPS[@]}" | sort)

SPAWN_RATE=25
USER_LEVELS=(1 10 25 100) # Number of concurrent users to simulate in Locust. This is the -u parameter for locust.
RTTS=(200)         # Round-trip time in milliseconds. This is the artificial latency that will be introduced in the network emulation.
LOSS_LEVELS=(0)  # Packet loss percentage. This is the percentage of packets that will be randomly dropped in the network emulation.

TARGET_HANDSHAKES=1000 # Total number of handshakes to perform in each trial.
MAX_DURATION="1000s" # Headless Locust run max duration per combination (seconds).
REPETITIONS_PER_TEST=1 # Number of times to repeat each combination for averaging or variance analysis.