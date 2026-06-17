#!/bin/sh

KEM_ALGO=$(echo "$1" | tr -d '\r')
SIG_ALGO=$(echo "$2" | tr -d '\r')
LATENCY=$(echo "$3" | tr -d '\r')
LOSS=$(echo "$4" | tr -d '\r')

echo "Running load test with KEM=$KEM_ALGO SIG=$SIG_ALGO LATENCY=$LATENCY LOSS=$LOSS"

OUTPUT_DIR="metrics"
mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/raw_results.csv"

# Initialize CSV header if file doesn't exist
if [ ! -f "$OUTPUT_FILE" ] || [ ! -s "$OUTPUT_FILE" ]; then
  echo "kem,signature,latency,loss,time_connect_ms,time_tls_handshake_ms" > "$OUTPUT_FILE"
fi

for i in $(seq 1 50); do
  # Use curl's -w to extract timing data natively. 
  # -k bypasses certificate domain verification since we used a self-signed cert.
  # time_connect = TCP handshake. time_appconnect = SSL/TLS handshake complete.
  
  RESULT=$(curl --curves "$KEM_ALGO" -k -s -o /dev/null -w "%{http_code},%{time_connect},%{time_appconnect}" https://web-server:443)
  
  # Exit status 0 means curl succeeded
  if [ $? -eq 0 ]; then
    HTTP_STATUS=$(echo "$RESULT" | cut -d',' -f1)
    TCP_SEC=$(echo "$RESULT" | cut -d',' -f2)
    TLS_SEC=$(echo "$RESULT" | cut -d',' -f3)

    # Convert seconds to milliseconds (Multiply by 1000 using awk)
    TCP_MS=$(awk "BEGIN {print $TCP_SEC * 1000}")
    
    # Calculate pure TLS Handshake duration (time_appconnect minus time_connect)
    TLS_MS=$(awk "BEGIN {print ($TLS_SEC - $TCP_SEC) * 1000}")

    echo "${KEM_ALGO},${SIG_ALGO},${LATENCY},${LOSS},${TCP_MS},${TLS_MS}" >> "$OUTPUT_FILE"
  else
    echo "${KEM_ALGO},${SIG_ALGO},${LATENCY},${LOSS},FAILED" >> "$OUTPUT_FILE"
  fi
done

echo "Load test complete! Metrics saved to $OUTPUT_FILE."