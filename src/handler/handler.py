from abc import ABC, abstractmethod
import socket
from typing import Tuple
from src.core.errors import *
from src.handshake import *
from src.utils import *
from src.transport import *


class Handler(ABC):
    def __init__(
        self,
        addr: Tuple[str, int],
        transport_adapter=None,
        handshake_protocol=None,
        timeout=5,
    ):
        self.addr = addr
        self.transport_adapter = transport_adapter or PlainTCPAdapter()
        self.handshake_protocol = handshake_protocol or Socks5HandshakeProtocol(timeout)
        self.timeout = timeout

    @abstractmethod
    def handle(
        self, conn: socket.socket, peer
    ) -> Tuple[socket.socket, socket.socket]: ...


class Socks5ClientHandler(Handler):
    def __init__(self, addr, server_addr, transport_adapter, handshake, timeout=5):
        super().__init__(addr, transport_adapter, handshake, timeout)
        self.server_addr = server_addr

    def handle(self, conn, peer):
        try:
            success, metadata = self.handshake_protocol.client_handshake(conn)
            if not success:
                log.error(
                    f"Client handshake failed: {metadata.get('error', 'unknown error')}"
                )
                return None, None

            dest_addr = metadata.get("address")
            remote = self._connect_to_server(dest_addr)
            if not remote:
                log.error(f"Server connection failed for {peer[0]}:{peer[1]}")
                conn.sendall(create_socks_reply(REPLY_HOST_UNREACHABLE))
                return None, None
            conn.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
            return remote, conn
        except Exception as e:
            log.error(f"Client error {peer[0]}:{peer[1]}: {e}")
            return None, None

    def _connect_to_server(self, dest_addr):
        if not dest_addr:
            return None
        try:
            remote = self.transport_adapter.create_connection(
                self.server_addr, self.timeout
            )

            addr_bytes = pack_address(dest_addr, ATYP_DOMAIN)
            remote.sendall(addr_bytes)

            resp = recv_exact(remote, 1)
            if not resp:
                raise SocksError("No response from remote server")
            if resp == b"\x00":
                return remote
            else:
                log.debug(f"Remote server connection failed: {resp.hex()}")
            return None
        except ssl.SSLError as e:
            log.error(f"TLS handshake failed: {e}")
            return None
        except Exception as e:
            log.error(f"TCP CONNECT error: {e}")
            return None


class Socks5ServerHandler(Handler):

    def handle(self, conn, peer):
        try:
            result, metadata = self.handshake_protocol.server_handshake(conn)
            if not result:
                log.error(
                    f"Server handshake failed: {metadata.get('error', 'unknown error')}"
                )
                conn.sendall(b"\x01")
                return None, None

            address = metadata.get("address")
            if not address:
                log.error("No target address received")
                conn.sendall(b"\x01")
                return None, None

            log.info(f"Connecting to {address[0]}:{address[1]}")
            desk_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            desk_sock.settimeout(self.timeout)
            desk_sock.connect(address)
            conn.sendall(b"\x00")
            return conn, desk_sock
        except Exception as e:
            log.error(f"Server error {peer[0]}:{peer[1]}: {e}")
            conn.sendall(b"\x01")
            return None, None
