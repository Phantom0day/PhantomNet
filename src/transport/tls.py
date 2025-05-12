import ssl, socket
from .base import TransportAdapter


class TlsAdapter(TransportAdapter):
    def get_protocol_features(self):
        return {
            "encrypted": True,
            "encryption_type": "TLS",
            "max_packet_size": 16384,  # TLS record size
            "supports_udp": False,
            "mtu": 1400,  # Slightly lower due to TLS overhead
            "overhead": 25,  # ~25 bytes TLS record overhead
            "protocol_name": "tls",
            "latency_optimized": False,
            "congestion_control": True,
            "sni_enabled": True,
            "perfect_forward_secrecy": True,
            "cipher_suite": (
                self._ctx.get_ciphers()[0]["name"]
                if self._ctx.get_ciphers()
                else "unknown"
            ),
        }


class TlsClientAdapter(TlsAdapter):
    def __init__(self, sni: str, verify=False, cert=None):
        self._sni = sni
        self._verify = verify
        self._ctx = ssl.create_default_context(cafile=cert)
        self._ctx.check_hostname = verify
        if not verify:
            self._ctx.verify_mode = ssl.CERT_NONE

    def create_outbound(self, address, timeout=None):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if timeout:
            sock.settimeout(timeout)
        sock.connect(address)
        return self._ctx.wrap_socket(sock, server_hostname=self._sni)

    def wrap_inbound(self, sock):
        return sock


class TlsServerAdapter(TlsAdapter):
    def __init__(self, cert: str, key: str):
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(certfile=cert, keyfile=key)

    def create_outbound(self, address, timeout=None):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if timeout:
            sock.settimeout(timeout)
        sock.connect(address)
        return sock

    def wrap_inbound(self, sock):

        return self._ctx.wrap_socket(sock, server_side=True)
