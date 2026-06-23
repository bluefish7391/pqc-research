#!/usr/bin/env bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  generate_certs.sh — Generates classical ECDSA P-256 certificates
#  for the KD Protocol Benchmarking PoC using the OQS OpenSSL image.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

set -euo pipefail

CERTS_DIR="$(pwd)/certs"
# SWAPPED: Using the dedicated openssl image instead of the nginx webserver image
DOCKER_IMAGE="openquantumsafe/openssl3:latest"

echo "Creating certs directory at ${CERTS_DIR}..."
mkdir -p "${CERTS_DIR}"

echo "Spawning ephemeral OpenSSL container to generate certificates..."

# We run a single temporary container, mounting the certs folder to /working.
# The container will execute the OpenSSL commands and immediately delete itself.
docker run --rm -v "${CERTS_DIR}:/working" -w /working "${DOCKER_IMAGE}" sh -c '
  
  echo "1. Generating Classical CA Private Key (ECDSA P-256)..."
  openssl ecparam -name prime256v1 -genkey -noout -out ca.key

  echo "2. Generating CA Root Certificate..."
  openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt \
    -subj "/C=US/ST=Georgia/L=Alpharetta/O=KD Benchmark/CN=Benchmark Root CA"

  echo "3. Generating Server Private Key (ECDSA P-256)..."
  openssl ecparam -name prime256v1 -genkey -noout -out server.key

  echo "4. Generating Server Certificate Signing Request (CSR)..."
  # IMPORTANT: The Common Name (CN) MUST match the container hostname exactly.
  openssl req -new -key server.key -out server.csr \
    -subj "/C=US/ST=Georgia/L=Alpharetta/O=KD Benchmark/CN=oqs-nginx"

  echo "5. Signing Server Certificate with the CA Root..."
  openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt -days 365 -sha256

  echo "6. Cleaning up temporary files..."
  rm server.csr ca.srl
'

# Because Docker runs as root by default, the generated files will be owned by root.
# This changes ownership back to your current Ubuntu user so you can easily view/delete them.
echo "Adjusting file permissions..."
sudo chown -R $(id -u):$(id -g) "${CERTS_DIR}"

echo "✅ Certificate generation complete! Files are located in ./certs/"
ls -la "${CERTS_DIR}"