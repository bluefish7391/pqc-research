import os
import subprocess
import uuid
import time
import logging
import signal
import io
import gevent
from gevent import util as gevent_util
from locust import User, task, constant, events
from locust.runners import MasterRunner, WorkerRunner # type: ignore
import csv

# Configuration and global variables
KEM_GROUP   = os.getenv("OQS_KEM_GROUP", "X25519MLKEM768")
TARGET_HOST = os.getenv("TARGET_HOST", "oqs-nginx")
TARGET_PORT = os.getenv("TARGET_PORT", "4433")
TARGET_HANDSHAKES = int(os.getenv("TARGET_HANDSHAKES", "1000"))
RUN_ID = os.getenv("RUN_ID", "").strip()
MAIN_OUTPUT_DIR = os.getenv("MAIN_OUTPUT_DIR", f"/mnt/collection/{RUN_ID}/locust")
TRIAL_DIR = f"/mnt/collection/{RUN_ID}"
WAIT_TIME   = 0.0
OPENSSL_BIN = "/opt/oqssa/bin/openssl"

# Force timezone to New York time
os.environ["TZ"] = "EST5EDT,M3.2.0/2,M11.1.0/2"
if hasattr(time, "tzset"):
    time.tzset()

WORKER_ID = uuid.uuid1();

KEYLOG_DIR = f"{TRIAL_DIR}/keylogs"
os.makedirs(KEYLOG_DIR, exist_ok=True)

# Open once per Locust worker process, at import time
csv_path = f"{MAIN_OUTPUT_DIR}/requests.csv"
_csv_file = open(csv_path, "w", newline="")
_csv_writer = csv.writer(_csv_file)
_csv_writer.writerow(["request_id", "greenlet_id", "start_time_ns", "response_time_ms", "response_length", "success", "exception"])

@events.request.add_listener
def log_request_to_csv(request_type, name, response_time, response_length, exception, context, **kwargs):
    _csv_writer.writerow([
        context.get("request_id"),
        context.get("greenlet_id"),
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

log_file_name = f"worker_{WORKER_ID}_requests.log" if RUN_ID else f"worker_{WORKER_ID}_requests.log"
file_handler = logging.FileHandler(f"{MAIN_OUTPUT_DIR}/{log_file_name}", mode="a")
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
    gevent_util.print_run_info(file=output)
    for line in output.getvalue().splitlines():
        log.info(line)

signal.signal(signal.SIGUSR1, dump_greenlets)

# To keep TARGET_HANDSHAKES meaning "total across all workers", we only ever
# treat this counter as authoritative on the MASTER process. Workers report
# each completed request to the master via Locust's runner message-passing
# API (environment.runner.send_message), and only the master's registered
# handler increments this variable and decides when to call runner.quit().
#
# In "local" mode (no --processes flag, single in-process runner, used e.g.
# for quick manual debugging), there is no master/worker split at all, so we
# fall back to the original local-counting behavior directly.
completed_handshakes = 0
stop_requested = False

@events.init.add_listener
def on_locust_init(environment, **kwargs):
    """
    Fires exactly once per process (master, each worker, or the single
    'local' runner when --processes is not used), right after that
    process's runner is created. Used here to set up the master-side
    message handler that aggregates completed-handshake counts reported
    by every worker, so the TARGET_HANDSHAKES stopping condition applies
    to the sum across all workers rather than to each worker individually.
    """
    if isinstance(environment.runner, MasterRunner):
        def on_handshake_done(environment, msg, **kwargs):
            global completed_handshakes, stop_requested
            completed_handshakes += msg.data["count"]
            if completed_handshakes >= TARGET_HANDSHAKES and not stop_requested:
                log.info(
                    f"Target of {TARGET_HANDSHAKES} handshakes reached "
                    f"({completed_handshakes}, aggregated across all workers). Stopping runner."
                )
                stop_requested = True
                environment.runner.quit()

        environment.runner.register_message("handshake_done", on_handshake_done)
        log.info("Master: registered 'handshake_done' message handler for cross-worker stop condition.")

    elif isinstance(environment.runner, WorkerRunner):
        # Nothing to register on workers — they only ever send "handshake_done"
        # messages, from inside _fire_request below, once per completed request.
        log.info("Worker: will report completed handshakes to master via 'handshake_done' messages.")

    else:
        # "local" mode: single process, no master/worker split, so the original
        # local-counting/local-quit logic (see _check_stop_condition_local below)
        # is used directly instead of message passing.
        log.info("Local (non-distributed) mode: using local stop-condition counting.")


def _check_stop_condition_local(environment):
    """
    Fallback stop-condition check for local (non-distributed) runs only
    """
    global completed_handshakes, stop_requested
    completed_handshakes += 1
    if completed_handshakes >= TARGET_HANDSHAKES and not stop_requested:
        log.info(f"Target of {TARGET_HANDSHAKES} handshakes reached ({completed_handshakes}). Stopping runner.")
        stop_requested = True
        gevent.spawn(environment.runner.quit)

# Define a custom Locust user class that performs TLS handshakes using OpenSSL's s_client.
class TLSHandshakeUser(User):
    wait_time = constant(WAIT_TIME)

    def on_start(self):
        self.greenlet_id = id(gevent.getcurrent())
        self.keylog_path = f"{KEYLOG_DIR}/user_{uuid.uuid1()}.log"
        open(self.keylog_path, "a").close()

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

            env = os.environ.copy()
            env["SSLKEYLOGFILE"] = self.keylog_path

            s_client_cmd = [
                OPENSSL_BIN, "s_client",
                "-connect", f"{TARGET_HOST}:{TARGET_PORT}",
                "-groups", KEM_GROUP,
                "-no_ticket", # Disable session tickets to ensure a full handshake is performed.
                "-quiet", # Suppress unnecessary output, only the HTTP response will be captured.
                "-nocommands", # Suppress interactive commands, HTTP request will be sent via stdin.
                "-keylogfile", self.keylog_path,
            ]

            log.info(f"Request start: greenlet_id={self.greenlet_id}, request_id={request_id}, start_time={start_time}, completed_handshakes={completed_handshakes}")
            result = subprocess.run(
                # Array of command-line arguments for the OpenSSL s_client command.
                s_client_cmd,
                input=HTTP_REQUEST,
                capture_output=True, # Capture stdout and stderr for analysis.
                timeout=10, # Set a timeout for the handshake operation to avoid hanging indefinitely. Measured in seconds.
                env=env,
            )
            log.info(f"Request end: greenlet_id={self.greenlet_id}, request_id={request_id}, end_time={time.time_ns()}, completed_handshakes={completed_handshakes}")

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
                    context         = {"request_id": request_id, "greenlet_id": self.greenlet_id, "start_time_ns": start_time},
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
                context         = {"request_id": request_id, "greenlet_id": self.greenlet_id, "start_time_ns": start_time},
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
                context         = {"request_id": request_id, "greenlet_id": self.greenlet_id, "start_time_ns": start_time},
            )

        finally:
            runner = self.environment.runner
            if isinstance(runner, WorkerRunner):
                runner.send_message("handshake_done", {"count": 1})
            else:
                _check_stop_condition_local(self.environment)