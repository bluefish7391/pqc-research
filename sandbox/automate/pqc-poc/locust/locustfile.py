import os
import ssl
import socket
import time
import logging
from locust import User, task, constant, events
import ctypes
import ctypes.util

KEM_GROUP   = os.getenv("OQS_KEM_GROUP", "X25519MLKEM768")
TARGET_HOST = os.getenv("TARGET_HOST",   "oqs-nginx")
TARGET_PORT = int(os.getenv("TARGET_PORT", "4433"))
WAIT_TIME   = float(os.getenv("WAIT_TIME", "0"))

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("oqs-tls")

def _build_ssl_context(kem_group: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    _set_groups_via_ctypes(ctx, kem_group)
    return ctx

def _set_groups_via_ctypes(ctx: ssl.SSLContext, kem_group: str) -> None:
    libssl_name = ctypes.util.find_library("ssl")
    if not libssl_name:
        raise RuntimeError(
            "Could not locate libssl via ctypes. "
            "Verify that OpenSSL is installed in the container."
        )

    libssl = ctypes.CDLL(libssl_name)
    libssl.SSL_CTX_set1_groups_list.restype  = ctypes.c_int
    libssl.SSL_CTX_set1_groups_list.argtypes = [
        ctypes.c_void_p,   # SSL_CTX*
        ctypes.c_char_p,   # const char* (group name string)
    ]

    ssl_ctx_ptr = ctx._ctx

    result = libssl.SSL_CTX_set1_groups_list(
        ssl_ctx_ptr,
        kem_group.encode("ascii"),
    )

    if result != 1:
        raise RuntimeError(
            f"SSL_CTX_set1_groups_list() returned {result} for group "
            f"'{kem_group}'. The group name is not recognized by this "
            f"OpenSSL build. Run: openssl list -kem-algorithms inside "
            f"the container to see supported group names."
        )

    log.info(f"SSL_CTX_set1_groups_list() succeeded for group: {kem_group}")


SSL_CONTEXT = _build_ssl_context(KEM_GROUP)

HTTP_REQUEST = (
    f"GET / HTTP/1.1\r\n"
    f"Host: {TARGET_HOST}\r\n"
    f"Connection: close\r\n"
    f"\r\n"
).encode("ascii")

class TLSHandshakeUser(User):
    wait_time = constant(WAIT_TIME)

    @task
    def tls_handshake(self):
        start_ns = time.perf_counter_ns()   # nanosecond precision start

        try:
            with socket.create_connection(
                (TARGET_HOST, TARGET_PORT), timeout=10
            ) as raw_sock:
                raw_sock.setsockopt(
                    socket.IPPROTO_TCP, socket.TCP_NODELAY, 1
                )

                with SSL_CONTEXT.wrap_socket(
                    raw_sock,
                    server_hostname=TARGET_HOST,
                ) as tls_sock:
                    tls_sock.sendall(HTTP_REQUEST)

                    response = _read_full_response(tls_sock)
            
            elapsed_ms = (time.perf_counter_ns() - start_ns) // 1_000_000
            
            if b"HTTP/1.1 200" in response or b"HTTP/2 200" in response:
                _fire_success(elapsed_ms, len(response))
            else:
                status_line = response.split(b"\r\n")[0].decode("ascii", errors="replace")
                _fire_failure(elapsed_ms, Exception(f"Unexpected status: {status_line}"))

        except ssl.SSLError as e:
            elapsed_ms = (time.perf_counter_ns() - start_ns) // 1_000_000
            log.warning(f"TLS handshake failed [{KEM_GROUP}]: {e}")
            _fire_failure(elapsed_ms, e)

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            elapsed_ms = (time.perf_counter_ns() - start_ns) // 1_000_000
            _fire_failure(elapsed_ms, e)

def _read_full_response(sock: ssl.SSLSocket) -> bytes:
    chunks = []
    while True:
        chunk = sock.read(65536)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def _fire_success(elapsed_ms: int, response_length: int) -> None:
    events.request.fire(
        request_type    = "TLS-Handshake",
        name            = f"GET / [{KEM_GROUP}]",
        response_time   = elapsed_ms,
        response_length = response_length,
        exception       = None,
    )


def _fire_failure(elapsed_ms: int, exc: Exception) -> None:
    events.request.fire(
        request_type    = "TLS-Handshake",
        name            = f"GET / [{KEM_GROUP}]",
        response_time   = elapsed_ms,
        response_length = 0,
        exception       = exc,
    )