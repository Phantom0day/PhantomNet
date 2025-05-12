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
        handshake_protocol: HandshakeProtocol,
        transport_adapter: TransportAdapter = None,
        timeout=5,
    ):
        self.addr = addr
        self.handshaker = handshake_protocol
        self.transporter = transport_adapter or PlainTCPAdapter()
        self.timeout = timeout

    @abstractmethod
    def handle(
        self, conn: socket.socket, peer
    ) -> Tuple[socket.socket, socket.socket]: ...


class Socks5ClientHandler(Handler):
    def __init__(self, addr, server_addr, handshake, transport, timeout=5):
        super().__init__(addr, handshake, transport, timeout)
        self.server_addr = server_addr

    def handle(self, conn, peer):
        try:
            dest_addr = self.handshaker.client_handshake(conn)
            if not dest_addr:
                return None, None

            remote = self.transporter.create_outbound(self.server_addr, self.timeout)
            result = self.handshaker.server_handshake(remote, dest_addr)
            if not result:
                log.error(f"Server connection failed for {peer[0]}:{peer[1]}")
                conn.sendall(create_socks_reply(REPLY_HOST_UNREACHABLE))
                return None, None
            conn.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
            return remote, conn
        except Exception as e:
            log.error(f"Client error {peer[0]}:{peer[1]}: {e}")
            return None, None


class Socks5ServerHandler(Handler):

    def handle(self, conn, peer):
        try:
            address = self.handshaker.client_handshake(conn)
            if not address:
                log.error("No target address received")
                return None, None

            log.info(f"Connecting to {address[0]}:{address[1]}")
            remote = self.transporter.create_outbound(address, self.timeout)
            result = self.handshaker.server_handshake(remote, address)
            if not result:
                log.error(f"Server connection failed for {peer[0]}:{peer[1]}")
                conn.sendall(b"\x01")
                return None, None
            conn.sendall(b"\x00")
            return conn, remote
        except Exception as e:
            log.error(f"Server error {peer[0]}:{peer[1]}: {e}")
            conn.sendall(b"\x01")
            return None, None
