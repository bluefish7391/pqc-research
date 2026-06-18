"""
KD Protocol Benchmarking PoC — Locust load test script.
Image: openquantumsafe/locust

Signature scheme: ECDSA P-256 (classical) — fixed for all runs.
Variable under test: KEM group (key distribution protocol).

Configuration knobs (set via env vars or edit defaults below):
  WAIT_MIN      Z_low  — minimum seconds between requests  (default: 1.0)
  WAIT_MAX      Z_high — maximum seconds between requests  (default: 3.0)
  NUM_REQUESTS  Y      — stop after N requests per user   (default: 50)
  OQS_KEM_GROUP        — TLS KEM group to negotiate       (default: X25519MLKEM768)
  TARGET_HOST          — HTTPS base URL of the server
"""

import os
import ssl
import time
import logging
import urllib3
from locust import HttpUser, task, between, events
from locust.exception import StopUser

# ── Configuration ────────────────────────────────────────────────────────
WAIT_MIN      = float(os.getenv("WAIT_MIN",      "1.0"))
WAIT_MAX      = float(os.getenv("WAIT_MAX",      "3.0"))
NUM_REQUESTS  = int(os.getenv("NUM_REQUESTS",  "50"))
KEM_GROUP     = os.getenv("OQS_KEM_GROUP",   "X25519MLKEM768")
TARGET_HOST   = os.getenv("TARGET_HOST",     "https://oqs-nginx:4433")

# Belt-and-suspenders: also set the env var so the OQS OpenSSL picks it up
os.environ["OPENSSL_GROUPS"] = KEM_GROUP

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("kd-locust")
log.info(f"KEM group requested: {KEM_GROUP}")
log.info(f"Requests per user:   {NUM_REQUESTS}")
log.info(f"Wait range (s):      [{WAIT_MIN}, {WAIT_MAX}]")

# Disable urllib3 SSL warnings — we use a self-signed CA intentionally
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def build_oqs_ssl_context(kem_group: str) -> ssl.SSLContext:
    # Create a bare-minimum client context
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname  = False
    ctx.verify_mode     = ssl.CERT_NONE
    
    log.info("Basic SSLContext initialized. Relying on system environment variables for KEM.")
    return ctx


# ── Locust Event Hooks ───────────────────────────────────────────────────
@events.init.add_listener
def on_locust_init(environment, **kwargs):
    log.info(f"Locust initialised — target: {TARGET_HOST}, group: {KEM_GROUP}")


@events.request.add_listener
def on_request(request_type, name, response_time, response_length,
               exception, context, **kwargs):
    """Log KD-relevant details for every request."""
    if exception:
        log.error(f"[FAIL] {request_type} {name} — {exception}")
    else:
        # response_time is in milliseconds
        log.debug(f"[OK]   {request_type} {name} — {response_time:.1f}ms")


# ── User Class ───────────────────────────────────────────────────────────
class KDUser(HttpUser):
    """
    Simulates a user making HTTPS requests to benchmark key distribution protocols.

    X (concurrent users) = --users flag to Locust CLI / Locust UI
    Y (total requests)   = NUM_REQUESTS env var (stops after this many)
    Z (delay between)    = random uniform in [WAIT_MIN, WAIT_MAX] seconds
    """
    host         = TARGET_HOST
    wait_time    = between(WAIT_MIN, WAIT_MAX)   # Z seconds
    abstract     = False

    def on_start(self):
        """Called once per simulated user on spawn."""
        self.request_count = 0
        # Patch the session's SSL adapter to use our OQS context
        oqs_ctx = build_oqs_ssl_context(KEM_GROUP)
        adapter = _OQSHTTPSAdapter(ssl_context=oqs_ctx)
        self.client.mount("https://", adapter)
        log.info(f"User spawned — OQS SSL adapter mounted (group={KEM_GROUP})")

    @task(10)
    def get_homepage(self):
        """
        Main benchmark task: GET /
        Weight 10 — highest frequency task.
        """
        self._do_request("/", name="/ [homepage]")

    @task(3)
    def get_health(self):
        """
        Health probe: GET /health — returns ssl_curve in body.
        Weight 3 — less frequent; useful for spot-checking the negotiated group.
        """
        with self.client.get(
            "/health",
            name="/health [probe]",
            catch_response=True
        ) as resp:
            if resp.status_code == 200:
                log.info(f"Health body: {resp.text.strip()}")
                if KEM_GROUP.lower() not in resp.text.lower():
                    # Server echoes ssl_curve; warn if it doesn't match what we asked for
                    log.warning(
                        f"Negotiated group mismatch! "
                        f"Asked: {KEM_GROUP}, Server reported: {resp.text.strip()}"
                    )
                resp.success()
            else:
                resp.failure(f"HTTP {resp.status_code} | Err: {resp.error}")

        self.request_count += 1
        self._check_stop()

    def _do_request(self, path: str, name: str = None):
        with self.client.get(
            path,
            name=name or path,
            catch_response=True
        ) as resp:
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


# ── Custom HTTPS Adapter ─────────────────────────────────────────────────
try:
    from requests.adapters import HTTPAdapter
    from urllib3.util.ssl_ import create_urllib3_context

    class _OQSHTTPSAdapter(HTTPAdapter):
        """Injects an OQS-aware SSLContext into the requests session."""
        def __init__(self, ssl_context=None, **kwargs):
            self._ssl_ctx = ssl_context
            super().__init__(**kwargs)

        def init_poolmanager(self, *args, **kwargs):
            if self._ssl_ctx:
                kwargs["ssl_context"] = self._ssl_ctx
            super().init_poolmanager(*args, **kwargs)

        def proxy_manager_for(self, proxy, **proxy_kwargs):
            if self._ssl_ctx:
                proxy_kwargs["ssl_context"] = self._ssl_ctx
            return super().proxy_manager_for(proxy, **proxy_kwargs)

except ImportError as exc:
    raise RuntimeError(f"requests/urllib3 not available: {exc}")