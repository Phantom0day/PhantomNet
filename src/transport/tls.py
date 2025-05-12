import ssl, socket
from .base import TransportAdapter


class TlsClientAdapter(TransportAdapter):
    def __init__(self, sni: str, verify=False, cafile=None):
        self._sni = sni
        self._verify = verify
        self._ctx = ssl.create_default_context(cafile=cafile)
        self._ctx.check_hostname = verify
        if not verify:
            self._ctx.verify_mode = ssl.CERT_NONE

    def create_connection(self, address, timeout=None):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if timeout:
            sock.settimeout(timeout)
        sock.connect(address)
        return self._ctx.wrap_socket(sock, server_hostname=self._sni)

    def wrap_accepted_socket(self, sock):
        return sock


class TlsServerAdapter(TransportAdapter):
    def __init__(self, cert: str, key: str):
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(certfile=cert, keyfile=key)

    def create_connection(self, address, timeout=None):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if timeout:
            sock.settimeout(timeout)
        sock.connect(address)
        return sock

    def wrap_accepted_socket(self, sock):

        return self._ctx.wrap_socket(sock, server_side=True)
