from .base import *


class PlainTCPAdapter(TransportAdapter):
    def create_connection(self, address, timeout=None):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if timeout:
            sock.settimeout(timeout)
        sock.connect(address)
        return sock

    def wrap_inbound(self, sock):
        return sock

    def get_protocol_features(self):
        return {
            "encrypted": False,
            "max_packet_size": 65535,  # TCP theoretical max
            "supports_udp": False,
            "mtu": 1460,  # Typical TCP MSS
            "overhead": 0,  # No additional overhead
            "protocol_name": "plain_tcp",
            "latency_optimized": False,
            "congestion_control": True,
        }
