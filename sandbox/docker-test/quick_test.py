import concurrent.futures
import csv
import os
import sys
import time
import urllib.request

# --- PARAMETER CHECKING ---
if len(sys.argv) < 4:
    print("Error: Missing parameters.")
    print("Usage: python quick_test.py <concurrency> <total_requests> <target_url>")
    print("Example: python quick_test.py 5 20 https://www.google.com")
    sys.exit(1)

CONCURRENCY = int(sys.argv[1])
TOTAL_REQUESTS = int(sys.argv[2]) # Now acts as the absolute ceiling for all requests combined
TARGET_URL = sys.argv[3]

OUTPUT_CSV = "/output/google_latency.csv"

# --- SETUP CSV ---
os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
with open(OUTPUT_CSV, mode='w', newline='') as f:
    csv.writer(f).writerow(["request_id", "latency_ms"])


# --- WORKER FUNCTION ---
def send_request(request_id):
    start_time = time.perf_counter()
    status = "SUCCESS"
    
    try:
        with urllib.request.urlopen(TARGET_URL, timeout=10) as response:
            response.read()
    except Exception as e:
        status = f"ERROR_{type(e).__name__}"
        
    latency_ms = (time.perf_counter() - start_time) * 1000
    
    with open(OUTPUT_CSV, mode='a', newline='') as f:
        csv.writer(f).writerow([request_id, f"{latency_ms:.2f}"])
        
    print(f"[{request_id}/{TOTAL_REQUESTS}] Status={status} | Time={latency_ms:.2f} ms")


# --- EXECUTION ENGINE ---
print(f"Container starting...")
print(f"  Target URL:             {TARGET_URL}")
print(f"  Total Combined Requests: {TOTAL_REQUESTS}")
print(f"  Max Concurrent Users:   {CONCURRENCY}\n")

# ThreadPoolExecutor maps the fixed range array across the capped workers
with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
    # Creating an exact global list of request IDs up to the total ceiling
    global_request_ids = list(range(1, TOTAL_REQUESTS + 1))
    executor.map(send_request, global_request_ids)

print(f"\nDone! Exactly {TOTAL_REQUESTS} total requests completed. Results written to {OUTPUT_CSV}")