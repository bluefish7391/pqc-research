"""Shared constants for collection cleaning."""

DEFAULT_WARMUP_DURATION_SECONDS = 10.0
POST_WARMUP_HANDSHAKE_LIMIT = 5000
POST_WARMUP_CUTOFF_NEAR_END_WARNING_SECONDS = 10.0

REQUIRED_TRIAL_METRICS = [
    "response_time_ms",
    "response_length",
    "success",
    "locust_cpu_pct",
    "locust_mem_used_bytes",
    "locust_net_rx_bytes",
    "locust_net_tx_bytes",
    "nginx_cpu_pct",
    "nginx_mem_used_bytes",
    "nginx_net_rx_bytes",
    "nginx_net_tx_bytes",
    "packets_client_to_server_per_request",
    "packets_server_to_client_per_request",
    "packets_total_per_request",
    "pcap_match_quality_code",
    "resource_gap_ns",
]

BUCKET_ONLY_TRIAL_METRICS = ["requests_in_bucket"]

BUCKET_MEAN_METRICS = {"response_time_ms"}
BUCKET_SUM_METRICS = {
    "response_length",
    "success",
    "packets_client_to_server_per_request",
    "packets_server_to_client_per_request",
    "packets_total_per_request",
}
BUCKET_LAST_METRICS = {
    "locust_cpu_pct",
    "locust_mem_used_bytes",
    "locust_net_rx_bytes",
    "locust_net_tx_bytes",
    "nginx_cpu_pct",
    "nginx_mem_used_bytes",
    "nginx_net_rx_bytes",
    "nginx_net_tx_bytes",
    "pcap_match_quality_code",
    "resource_gap_ns",
}

UNIT_FACTORS = {
    "": 1.0,
    "B": 1.0,
    "KB": 1000.0,
    "MB": 1000.0**2,
    "GB": 1000.0**3,
    "TB": 1000.0**4,
    "KIB": 1024.0,
    "MIB": 1024.0**2,
    "GIB": 1024.0**3,
    "TIB": 1024.0**4,
}

SUCCESS_TRUE = {"true", "1", "yes", "y", "t"}
SUCCESS_FALSE = {"false", "0", "no", "n", "f"}

CLIENT_IP = "172.21.0.10"
SERVER_IP = "172.20.0.10"
