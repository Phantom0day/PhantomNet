from .base import *


class PlainTCPAdapter(TransportAdapter):
    def create_connection(self, address, timeout=None):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if timeout:
            sock.settimeout(timeout)
        sock.connect(address)
        return sock

    def wrap_accepted_socket(self, sock):
        return sock
