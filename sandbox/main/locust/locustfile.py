import os
import subprocess
import uuid
import time
import logging
import signal
import io
import gevent.util
from locust import User, task, constant, events
import csv

# Configuration and global variables
KEM_GROUP   = os.getenv("OQS_KEM_GROUP", "X25519MLKEM768")
TARGET_HOST = os.getenv("TARGET_HOST", "oqs-nginx")
TARGET_PORT = os.getenv("TARGET_PORT", "4433")
TARGET_HANDSHAKES = int(os.getenv("TARGET_HANDSHAKES", "1000"))
RUN_ID = os.getenv("RUN_ID", "").strip()
WAIT_TIME   = 0.0
OPENSSL_BIN = "/opt/oqssa/bin/openssl"

# Open once per Locust worker process, at import time
csv_path = f"/mnt/locust/results_{RUN_ID}_requests.csv"
_csv_file = open(csv_path, "w", newline="")
_csv_writer = csv.writer(_csv_file)
_csv_writer.writerow(["request_id", "start_time_ns", "response_time_ms", "response_length", "success", "exception"])

@events.request.add_listener
def log_request_to_csv(request_type, name, response_time, response_length, exception, context, **kwargs):
    _csv_writer.writerow([
        context.get("request_id"),
        context.get("start_time_ns"),
        response_time,
        response_length,
        exception is not None,
        str(exception) if exception else "",
    ])
    _csv_file.flush()  # so data isn't lost if the run is killed/times out

# Logging setup
log = logging.getLogger("oqs-tls")
log.setLevel(logging.INFO)

log_file_name = f"{RUN_ID}_locust_debug.log" if RUN_ID else "locust_debug.log"
file_handler = logging.FileHandler(f"/mnt/locust/{log_file_name}", mode="a")
file_handler.setFormatter(logging.Formatter("%(message)s"))
log.addHandler(file_handler)
log.propagate = False  # avoid duplicate lines also going to Locust's console handler

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


# Signal handler to dump greenlet information when receiving SIGUSR1. This is useful for debugging and monitoring the state of the Locust users during execution.
def dump_greenlets(signum, frame):
    log.info("=== GREENLET DUMP ===")
    output = io.StringIO()
    gevent.util.print_run_info(file=output)
    for line in output.getvalue().splitlines():
        log.info(line)

signal.signal(signal.SIGUSR1, dump_greenlets)

completed_handshakes = 0
stop_requested = False

def _check_stop_condition(environment):
    global completed_handshakes, stop_requested
    completed_handshakes += 1
    if completed_handshakes >= TARGET_HANDSHAKES and not stop_requested:
        log.info(f"Target of {TARGET_HANDSHAKES} handshakes reached ({completed_handshakes}). Stopping runner.")
        stop_requested = True
        gevent.spawn(environment.runner.quit)

# Define a custom Locust user class that performs TLS handshakes using OpenSSL's s_client.
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
        request_id = str(uuid.uuid4())

        try:
            # Run the OpenSSL s_client command to perform a TLS handshake with the target server.
            # Create a subprocess to run the command, passing the HTTP request to its stdin.
            # The command is constructed to use the specified KEM group, disable session tickets, 
            # and suppress output.
            # Python temporarily pauses the execution of this specific Locust user thread and 
            # hands control over to the operating system kernel.

            start_time=time.time_ns()

            log.info(f"Request start: start_time={start_time}, request_id={request_id}, completed_handshakes={completed_handshakes}")
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
            log.info(f"Request end: start_time={start_time}, request_id={request_id}, completed_handshakes={completed_handshakes}")

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
                    context         = {"request_id": request_id, "start_time_ns": start_time},
                )
            else:
                stderr = result.stderr.decode("ascii", errors="replace").strip()
                raise Exception(f"Handshake failed or non-200: {stderr[:120]}")

        # Handle timeout exception only.
        except subprocess.TimeoutExpired:
            log.info(f"TIMEOUT-CAUGHT pid={os.getpid()} at {time.time()}")
            elapsed_ms = (time.perf_counter_ns() - start_ns) // 1_000_000
            events.request.fire(
                request_type    = "TLS-Handshake",
                name            = f"GET / [{KEM_GROUP}]",
                response_time   = elapsed_ms,
                response_length = 0,
                exception       = Exception("Timeout"),
                context         = {"request_id": request_id, "start_time_ns": start_time},
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
                context         = {"request_id": request_id, "start_time_ns": start_time},
            )

        # Check if the target number of handshakes has been reached and stop the Locust runner if so.
        finally:
            _check_stop_condition(self.environment)