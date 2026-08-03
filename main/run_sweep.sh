#!/usr/bin/env bash
# Entrypoint for main orchestration script responsible for gathering experimental data.
# Simply calls run_matrix.sh, which handles the actual orchestration of the benchmarking trials.

main() {
  # Call the orchestration entrypoint relative to this file's directory.
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  "${script_dir}/orchestration/run_matrix.sh" "$@"
}

main "$@"