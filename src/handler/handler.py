from abc import ABC, abstractmethod
import socket
from typing import Tuple
from src.core.errors import *
from src.utils import *


class Handler(ABC):
    def __init__(self, addr: Tuple[str, int], timeout=5):
        self.addr = addr
        self.timeout = timeout

    @abstractmethod
    def handle(
        self, conn: socket.socket, peer
    ) -> Tuple[socket.socket, socket.socket]: ...


class Socks5ClientHandler(Handler):
    def __init__(self, addr, server_addr, timeout=5):
        super().__init__(addr, timeout)
        self.server_addr = server_addr

    def handle(self, conn, peer):
        try:
            dest_addr = self._socks5_request(conn)
            # remote = socket.create_connection(self.addr, self.timeout)
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

    def _socks5_request(self, cli: socket.socket):
        try:
            # HANDSHAKE ver + methods
            ver, n_methods = cli.recv(2)
            if ver != SOCKS_VERSION:
                raise SocksVersionError(f"Invalid socks version: {ver}")
            methods = cli.recv(n_methods)
            if AUTH_NO_AUTH not in methods:
                raise SocksAuthError(f"Unsupported authentication methods: {methods}")
            response = struct.pack("!BB", SOCKS_VERSION, AUTH_NO_AUTH)
            cli.sendall(response)

            # CONNECT
            ver, cmd, _, atyp = cli.recv(4)
            if ver != SOCKS_VERSION:
                raise SocksVersionError(f"Invalid socks version: {ver}")
            if cmd != CMD_CONNECT:
                cli.sendall(create_socks_reply(REPLY_COMMAND_NOT_SUPPORTED))
                raise SocksAuthError(f"Unsupported command: {cmd}")
            if atyp == ATYP_IPV4:
                addr = socket.inet_ntoa(cli.recv(4))
            elif atyp == ATYP_DOMAIN:
                ln = cli.recv(1)[0]
                addr = cli.recv(ln).decode()
            elif atyp == ATYP_IPV6:
                addr = socket.inet_ntop(socket.AF_INET6, cli.recv(16))
            else:
                cli.sendall(create_socks_reply(REPLY_ADDRESS_TYPE_NOT_SUPPORTED))
                raise SocksError(f"Unsupported ATYP: {atyp}")
            port = struct.unpack("!H", cli.recv(2))[0]
            return addr, port
        except Exception as e:
            log.error(f"Client socks5 error: {e}")
            return None

    def _connect_to_server(self, dest_addr):
        if not dest_addr:
            return None
        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(self.timeout)
            remote.connect(self.server_addr)

            addr_bytes = pack_address(dest_addr, ATYP_DOMAIN)
            remote.sendall(addr_bytes)

            resp = remote.recv(1)
            if not resp:
                raise SocksError("No response from remote server")
            if resp == b"\x00":
                return remote
            else:
                log.debug(f"Remote server connection failed: {resp.hex()}")
            return None
        except Exception as e:
            log.error(f"TCP CONNECT error: {e}")
            return None


class Socks5ServerHandler(Handler):

    def handle(self, conn, peer):
        try:
            return conn, self._socks5_request(conn)
        except Exception as e:
            log.error(f"Server error {peer[0]}:{peer[1]}: {e}")
            return None, None

    def _socks5_request(self, cli: socket.socket):
        try:
            addr_type = struct.unpack("!B", cli.recv(1))[0]
            if addr_type == ATYP_IPV4:
                addr_data = cli.recv(4)
                dest_addr = socket.inet_ntoa(addr_data)
            elif addr_type == ATYP_DOMAIN:
                domain_len = struct.unpack("!B", cli.recv(1))[0]
                addr_data = cli.recv(domain_len)
                dest_addr = addr_data.decode("utf-8")
            elif addr_type == ATYP_IPV6:
                addr_data = cli.recv(16)
                dest_addr = socket.inet_ntop(socket.AF_INET6, addr_data)
            else:
                log.debug(f"Unsupported address type: {addr_type}")
                cli.sendall(b"\x01")
                return
            port_data = cli.recv(2)
            dest_port = struct.unpack("!H", port_data)[0]
        except Exception as e:
            log.error(f"Address parse error: {e}")
            cli.sendall(b"\x01")
            return

        log.info(f"Connecting to {dest_addr}:{dest_port}")
        try:
            desk_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            desk_sock.settimeout(self.timeout)
            desk_sock.connect((dest_addr, dest_port))

            cli.sendall(b"\x00")
            return desk_sock
        except Exception as e:
            log.error(f"Error on destination {dest_addr}:{dest_port}: {e}")
            cli.sendall(b"\x01")
