#!/usr/bin/env bash

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "${MAIN_LOG_FILE}"
}

teardown() {
  log "Tearing down (docker compose down -v)..."
  docker compose down -v --remove-orphans || log "Warning: docker compose down failed. Continuing..."
}