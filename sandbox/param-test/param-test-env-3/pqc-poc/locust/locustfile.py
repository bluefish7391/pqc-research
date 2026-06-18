import os
import logging
from locust import FastHttpUser, task, between, events
from locust.exception import StopUser

# ── Configuration ────────────────────────────────────────────────────────
WAIT_MIN      = float(os.getenv("WAIT_MIN",      "1.0"))
WAIT_MAX      = float(os.getenv("WAIT_MAX",      "3.0"))
NUM_REQUESTS  = int(os.getenv("NUM_REQUESTS",  "50"))
KEM_GROUP     = os.getenv("OQS_KEM_GROUP",   "X25519MLKEM768")
TARGET_HOST   = os.getenv("TARGET_HOST",     "https://oqs-nginx:4433")

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("kd-locust")
log.info(f"KEM group requested: {KEM_GROUP}")

# ── User Class (Using FastHttpUser to honor OpenSSL Env) ─────────────────
class KDUser(FastHttpUser):
    host         = TARGET_HOST
    wait_time    = between(WAIT_MIN, WAIT_MAX)
    abstract     = False

    # FastHttpUser network configuration properties
    insecure     = True  # Bypasses certificate validation natively at C-level
    concurrency  = 1     # Ensures clean sequential requests per user

    def on_start(self):
        """Called once per simulated user on spawn."""
        self.request_count = 0
        log.info(f"User spawned using FastHttpUser framework.")

    @task(10)
    def get_homepage(self):
        """Main benchmark task: GET /"""
        self._do_request("/", name="/ [homepage]")

    @task(3)
    def get_health(self):
        """Health probe: GET /health"""
        with self.client.get("/health", name="/health [probe]", catch_response=True) as resp:
            if resp.status_code == 200:
                log.info(f"Health body: {resp.text.strip()}")
                resp.success()
            else:
                resp.failure(f"HTTP {resp.status_code} | Err: {resp.error}")
        
        self.request_count += 1
        self._check_stop()

    def _do_request(self, path: str, name: str = None):
        with self.client.get(path, name=name or path, catch_response=True) as resp:
            if resp.status_code == 200:
                resp.success()
            else:
                resp.failure(f"HTTP {resp.status_code} | Err: {resp.error}")

        self.request_count += 1
        self._check_stop()

    def _check_stop(self):
        """Stop this user after Y total requests."""
        if self.request_count >= NUM_REQUESTS:
            log.info(f"User reached {NUM_REQUESTS} requests — stopping.")
            raise StopUser()