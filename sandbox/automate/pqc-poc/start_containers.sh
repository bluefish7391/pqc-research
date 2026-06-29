render_nginx_conf() {
  local kem_value="$1"
  sed "s/__KEM_GROUP__/${kem_value}/" "${NGINX_TMPL}" > "${NGINX_CONF}"
  log "Rendered nginx.conf with ssl_ecdh_curve=${kem_value}"
}

wait_for_healthy() {
  # Wait for the oqs-nginx container to report a healthy status via its healthcheck.
  # If it does not become healthy within max_wait seconds, logs are dumped and an error is returned.

  local container="oqs-nginx"
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
      docker compose logs oqs-nginx || true
      return 1
    fi
    
    sleep 2
    (( waited += 2))
  done
}

# == Validation =================================================================

find_openssl_bin() {
  # Look for an OpenSSL binary inside the oqs-locust container.
  # The location of the binary may vary depending on the image build, so multiple common locations are checked. 
  # If found, the path to the binary is returned; otherwise, exit with an error.
  # For this locust container, the binary is expected to be /opt/oqssa/bin/openssl
  local search_script=$(cat << 'EOF'
    if command -v openssl >/dev/null 2>&1; then
      command -v openssl
    elif [ -x /opt/oqssa/bin/openssl ]; then
      echo /opt/oqssa/bin/openssl
    elif [ -x /opt/openssl/apps/openssl ]; then
      echo /opt/openssl/apps/openssl
    else
      echo ""
    fi
EOF
  )

  # Run the search script inside the oqs-locust container and capture the output,
  # stripping any carriage returns and taking only the last line (the path to the binary).
  local openssl_bin
  openssl_bin=$(docker compose exec -T oqs-locust sh -lc "${search_script}" \
    | tr -d '\r' \
    | tail -n1)
  echo "${openssl_bin}"
}

validate_handshake() {
  # Validate that the oqs-locust client can successfully perform a TLS handshake with the oqs-nginx server using the specified KEM group.
  # This is a preflight check to ensure that the server and client are configured correctly before running the load test.

  local kem_label="$1"
  local kem_value="$2"
  local openssl_bin=$(find_openssl_bin)

  if [[ -z "${openssl_bin}" ]]; then
    log "ERROR: no OpenSSL client binary found in oqs-locust container."
    log "ERROR: checked: openssl, /opt/oqssa/bin/openssl, /opt/openssl/apps/openssl"
    return 1
  fi

  log "Validating TLS handshake for ${kem_label} (${kem_value}) before load run (bin=${openssl_bin})..."

  # Docker compose steps into the oqs-locust container and runs a one-off command to perform a TLS handshake with the oqs-nginx server using the specified KEM group.
  # The command uses OpenSSL's s_client to connect to the server and perform a handshake. If the handshake fails, an error is logged and the function exits.
  if ! docker compose exec -T oqs-locust \
    sh -lc "printf 'GET /health HTTP/1.1\\r\\nHost: oqs-nginx\\r\\nConnection: close\\r\\n\\r\\n' | '${openssl_bin}' s_client -connect oqs-nginx:4433 -groups '${kem_value}' -quiet >/dev/null 2>&1"; then
    log "ERROR: preflight handshake failed for ${kem_label} (${kem_value})."
    log "ERROR: Client/Server TLS groups likely do not match or classical group is unsupported in this image build."
    docker compose logs --tail=80 oqs-nginx || true
    return 1
  fi

  log "Preflight handshake OK for ${kem_label} (${kem_value})."
}

start_up_containers() {
  # Start up the oqs-nginx and oqs-locust containers for a specific KEM group, and validate that the handshake works before proceeding with the load test.

  local kem_label="$1"
  local kem_value="$2"

  teardown

  log "Starting up containers for KEM group ${kem_label} (${kem_value})..."

  # Set the environment variable for the KEM group so that the locust file can pick it up and know to use the correct KEM group.
  export OQS_KEM_GROUP="${kem_value}"

  # Build tag is used to ensure that the image is rebuilt with the updated nginx.conf for the specific KEM group.
  # Only the oqs-nginx service needs to be rebuilt, as the oqs-locust service determines the KEM group at runtime via the OQS_KEM_GROUP environment variable.
  # On the other hand, the nginx.conf file is baked into the oqs-nginx image at build time, so it must be rebuilt for each KEM group.
  render_nginx_conf "${kem_value}"
  docker compose up -d --build oqs-nginx 

  if ! wait_for_healthy; then
    log "ERROR: nginx did not become healthy for KEM group ${kem_label} (${kem_value})."
    teardown
    return 1
  fi

  docker compose up -d --build oqs-locust

  # The oqs-locust container is based on Alpine Linux, which uses the 'apk' package manager. Due to the minimalist nature of the locust image,
  # it lacks the security certificates needed to validate HTTPS connections. To get around this, the alpine respositories file is modified by
  # replacing 'https://' with 'http://', allowing the package manager to fetch packages over HTTP. Then, the necessary packages for network 
  # emulation and packet capture are installed.

  # It is safe to use HTTP here because while the requests and responses are unsecured by TLS, the Alpine package repositories are signed, and 
  # the package manager will verify the signatures of the packages it downloads.
  docker compose exec -T -u root oqs-locust sed -i 's/https:\/\//http:\/\//g' /etc/apk/repositories
  docker compose exec -T -u root oqs-locust apk add --no-cache iproute2 tshark # --no-cache avoids caching the package index, saving space in the container.

  if ! validate_handshake "${kem_label}" "${kem_value}"; then
    log "ERROR: handshake validation failed for KEM group ${kem_label} (${kem_value})."
    teardown
    return 1
  fi

  NGINX_PIDS=$(docker top oqs-nginx -o pid,comm \
    | awk '/nginx/ {print $1}' \
    | tr '\n' ',' \
    | sed 's/,$//')
  log "nginx PIDs: ${NGINX_PIDS}"
}
