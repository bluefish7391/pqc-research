import os
import subprocess
import threading
import time
import logging
from locust import User, task, constant, events

# Configuration and global variables
KEM_GROUP   = os.getenv("OQS_KEM_GROUP", "X25519MLKEM768")
TARGET_HOST = os.getenv("TARGET_HOST", "oqs-nginx")
TARGET_PORT = os.getenv("TARGET_PORT", "4433")
WAIT_TIME   = float(os.getenv("WAIT_TIME", "0"))
OPENSSL_BIN = "/opt/oqssa/bin/openssl"

# Logging setup
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("oqs-tls")

# Create the HTTP request to be sent after the TLS handshake, identical for all users, 
# so can be precomputed once.
# Because the s_client command is being used instead of an HTTP library, the request
# has to be manually constructed to be piped into the process's stdin.
HTTP_REQUEST = (
    f"GET / HTTP/1.1\r\n"
    f"Host: {TARGET_HOST}\r\n"
    f"Connection: close\r\n"
    f"\r\n"
).encode("ascii")

# Define a custom Locust user class that performs TLS handshakes using OpenSSL's s_client.
# The first user to start will perform a "preload" handshake to warm up the OQS provider
# library, and subsequent users will skip this step.
class TLSHandshakeUser(User):
    wait_time = constant(WAIT_TIME)

    @task
    def _fire_request(self):
        """
        To be executed by Locust for each user. This task performs a TLS handshake
        using OpenSSL's s_client and records the result. Handshakes are performed 
        in parallel by multiple users, simulating concurrent connections to the 
        target server. Controlled by WAIT_TIME, which is the time to wait between
        handshakes for each user.
        """
        start_ns = time.perf_counter_ns()

        try:
            # Run the OpenSSL s_client command to perform a TLS handshake with the target server.
            # Create a subprocess to run the command, passing the HTTP request to its stdin.
            # The command is constructed to use the specified KEM group, disable session tickets, 
            # and suppress output.
            # Python temporarily pauses the execution of this specific Locust user thread and 
            # hands control over to the operating system kernel.
            result = subprocess.run(
                # Array of command-line arguments for the OpenSSL s_client command.
                [
                    OPENSSL_BIN, "s_client",
                    "-connect", f"{TARGET_HOST}:{TARGET_PORT}",
                    "-groups", KEM_GROUP,
                    "-no_ticket", # Disable session tickets to ensure a full handshake is performed.
                    "-quiet", # Suppress unnecessary output, only the HTTP response will be captured.
                    "-nocommands", # Suppress interactive commands, HTTP request will be sent via stdin.
                ],
                input=HTTP_REQUEST,
                capture_output=True, # Capture stdout and stderr for analysis.
                timeout=10, # Set a timeout for the handshake operation to avoid hanging indefinitely. Measured in seconds.
            )

            elapsed_ms = (time.perf_counter_ns() - start_ns) // 1_000_000
            
            # Record data for the handshake request. If the handshake was successful and the server 
            # responded with a 200 OK status, record the response time and length. Otherwise, raise 
            # an exception to move to except block.
            stdout = result.stdout
            if b"HTTP/1.1 200" in stdout or b"HTTP/2 200" in stdout: # Network responds in byte data, so check for byte strings.
                events.request.fire(
                    request_type    = "TLS-Handshake",
                    name            = f"GET / [{KEM_GROUP}]",
                    response_time   = elapsed_ms,
                    response_length = len(stdout),
                    exception       = None,
                )
            else:
                stderr = result.stderr.decode("ascii", errors="replace").strip()
                raise Exception(f"Handshake failed or non-200: {stderr[:120]}")

        # Handle timeout exception only.
        except subprocess.TimeoutExpired:
            elapsed_ms = (time.perf_counter_ns() - start_ns) // 1_000_000
            events.request.fire(
                request_type    = "TLS-Handshake",
                name            = f"GET / [{KEM_GROUP}]",
                response_time   = elapsed_ms,
                response_length = 0,
                exception       = Exception("Timeout"),
            )

        # Handle any other exceptions that may occur during the handshake process, such as network errors or unexpected output.
        except Exception as e:
            elapsed_ms = (time.perf_counter_ns() - start_ns) // 1_000_000
            events.request.fire(
                request_type    = "TLS-Handshake",
                name            = f"GET / [{KEM_GROUP}]",
                response_time   = elapsed_ms,
                response_length = 0,
                exception       = e,
            )