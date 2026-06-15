#!/bin/sh

# Start the web server with the command:
# docker compose up -d web-server

# Then, to start up the virtual users, run:
# docker compose run --rm --entrypoint sh load-tester ./run-load.sh

OUTPUT_FILE="metrics_$(date +%Y%m%d_%H%M%S).csv"

echo "time_connect,time_appconnect,time_starttransfer,time_total" > "$OUTPUT_FILE"

echo "Starting 10 concurrent Virtual Users for 100 total requests..."

seq 1 100 | xargs -n1 -P10 -I{} sh -c "
  curl -k -s -o /dev/null \
  -w '%{time_connect},%{time_appconnect},%{time_starttransfer},%{time_total}\n' \
  https://web-server:443 >> $OUTPUT_FILE
  sleep 1
"

echo "Load test complete! Metrics saved to $OUTPUT_FILE."