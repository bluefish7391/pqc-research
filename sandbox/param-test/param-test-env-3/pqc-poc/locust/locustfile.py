import os
import subprocess
import time
import logging
from locust import User, task, between, events
from locust.exception import StopUser

WAIT_MIN     = float(os.getenv("WAIT_MIN", "1.0"))
WAIT_MAX     = float(os.getenv("WAIT_MAX", "3.0"))
NUM_REQUESTS  = int(os.getenv("NUM_REQUESTS", "50"))
KEM_GROUP     = os.getenv("OQS_KEM_GROUP", "X25519MLKEM768")

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("oqs-bridge")

class OQSSubprocessUser(User):
    wait_time = between(WAIT_MIN, WAIT_MAX)

    def on_start(self):
        self.request_count = 0

    @task
    def run_oqs_request(self):
        start_time = time.time()
        
        # Build the exact command that openssl s_client needs to hit Nginx
        # We pass an empty echo to close the connection immediately after getting the response
        cmd = [
            "openssl", "s_client",
            "-connect", "oqs-nginx:4433",
            "-groups", KEM_GROUP,
            "-quiet"
        ]

        try:
            # Execute the raw binary directly through the OS layer
            process = subprocess.run(
                cmd,
                input=b"GET / HTTP/1.1\r\nHost: oqs-nginx\r\nConnection: close\r\n\r\n",
                capture_output=True,
                timeout=5
            )
            
            total_time = int((time.time() - start_time) * 1000)

            if process.returncode == 0 and b"HTTP/1.1 200" in process.stdout:
                events.request.fire(
                    request_type="OQS-TLS",
                    name=f"GET / [{KEM_GROUP}]",
                    response_time=total_time,
                    response_length=len(process.stdout),
                    exception=None,
                )
            else:
                # Capture stderr alert details directly from OpenSSL
                err_msg = process.stderr.decode('utf-8', errors='ignore').strip() or "Handshake failed"
                raise Exception(err_msg[:100])

        except Exception as e:
            total_time = int((time.time() - start_time) * 1000)
            events.request.fire(
                request_type="OQS-TLS",
                name=f"GET / [{KEM_GROUP}]",
                response_time=total_time,
                response_length=0,
                exception=e,
            )

        self.request_count += 1
        if self.request_count >= NUM_REQUESTS:
            raise StopUser()