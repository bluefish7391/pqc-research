#!/usr/bin/env bash
# Entrypoint for main orchestration script responsible for gathering experimental data.
# Simply calls run_matrix.sh, which handles the actual orchestration of the benchmarking trials.

main() {
  # Call the run_matrix.sh script to perform the benchmarking trials.
  ./run_matrix.sh "$@"
}

main "$@"