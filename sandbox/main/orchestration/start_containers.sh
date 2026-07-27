#!/usr/bin/env bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source "${SCRIPT_DIR}/check_containers.sh"
source "${SCRIPT_DIR}/helpers.sh"

render_nginx_conf() {
  local kem_value="$1"
  sed "s/__KEM_GROUP__/${kem_value}/" "${NGINX_TMPL}" > "${NGINX_CONF}"
  log "Rendered nginx.conf with ssl_ecdh_curve=${kem_value}"
}

set_up_routing() {
  # Force symmetric routing through the router container so that both directions
  # of each TCP flow pass through the router's eth0/eth1 interfaces. Without this,
  # each container routes return traffic via the Docker bridge default gateway,
  # bypassing the router and making tc-netem and tshark only see one direction.
  docker compose exec -T -u root oqs-locust  ip route add 172.20.0.0/24 via 172.21.0.2
  docker compose exec -T -u root oqs-nginx   ip route add 172.21.0.0/24 via 172.20.0.2
}

wait_for_healthy() {
  # Wait for the oqs-nginx container to report a healthy status via its healthcheck.
  # If it does not become healthy within max_wait seconds, logs are dumped and an error is returned.

  local container="$1"
  local max_wait=60
  local waited=0
  log "Waiting for ${container} healthcheck..."

  while true; do
    # Inspect the nginx container, and extract just the health status. If the container is not found, return "unknown".
    # Do not fail the script if the container is not found yet, as it may take a few seconds for docker compose to start it.
    # DO not log any errors from docker inspect to avoid cluttering the output.
    status="$(docker inspect --format='{{.State.Health.Status}}' "${container}" 2>/dev/null || echo "unknown")"

    if [[ "${status}" == "healthy" ]]; then
      log "${container} is healthy."
      return 0
    fi

    if (( waited >= max_wait )); then
      log "ERROR: ${container} did not become healthy within ${max_wait}s (status=${status})."
      docker compose logs "${container}" || true
      return 1
    fi
    
    sleep 2
    (( waited += 2))
  done
}

start_up_containers() {
  # Start up the oqs-nginx and oqs-locust containers for a specific KEM group, and validate that the handshake works before proceeding with the load test.

  local kem_label="$1"
  local kem_value="$2"

  log "Starting up containers for KEM group ${kem_label} (${kem_value})..."

  # Set the environment variable for the KEM group so that the locust file can pick it up and know to use the correct KEM group.
  export OQS_KEM_GROUP="${kem_value}"

  # Build tag is used to ensure that the image is rebuilt with the updated nginx.conf for the specific KEM group.
  # Only the oqs-nginx service needs to be rebuilt, as the oqs-locust service determines the KEM group at runtime via the OQS_KEM_GROUP environment variable.
  # On the other hand, the nginx.conf file is baked into the oqs-nginx image at build time, so it must be rebuilt for each KEM group.
  render_nginx_conf "${kem_value}"

  docker compose up -d oqs-nginx 
  if ! wait_for_healthy "oqs-nginx"; then
    log "ERROR: nginx did not become healthy for KEM group ${kem_label} (${kem_value})."
    teardown
    return 1
  fi

  docker compose up -d --build router
  if ! wait_for_healthy "router"; then
    log "ERROR: router did not become healthy for KEM group ${kem_label} (${kem_value})."
    teardown
    return 1
  fi

  # TODO: Add healthcheck for locust container and wait for container to be healthy
  docker compose up -d oqs-locust

  set_up_routing

  if ! validate_forced_routing; then
    log "ERROR: forced routing validation failed for KEM group ${kem_label} (${kem_value})."
    teardown
    return 1
  fi
  
  if ! validate_handshake "${kem_label}" "${kem_value}"; then
    log "ERROR: handshake validation failed for KEM group ${kem_label} (${kem_value})."
    teardown
    return 1
  fi
}
