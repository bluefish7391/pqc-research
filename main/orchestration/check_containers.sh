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

validate_forced_routing() {
  # Validate that the oqs-locust and oqs-nginx containers are routing traffic through the router container as expected.
  # This is a preflight check to ensure that the network emulation (tc-netem) and packet capture (tshark) will see both directions of each TCP flow.

  log "Validating forced routing through router container..."

  if ! docker compose exec -T oqs-locust ip route show 172.20.0.0/24 | grep -q "172.21.0.2"; then
    log "ERROR: oqs-locust does not have a static route to oqs-nginx via router. Traffic may bypass router and tc-netem."
    return 1
  fi

  if ! docker compose exec -T oqs-nginx ip route show 172.21.0.0/24 | grep -q "172.20.0.2"; then
    log "ERROR: oqs-nginx does not have a static route to oqs-locust via router. Traffic may bypass router and tc-netem."
    return 1
  fi

  log "Forced routing validation OK."
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