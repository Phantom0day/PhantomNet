import socket
import ssl
import struct
from typing import Tuple, Dict, Any, Optional

from .base import *
from src.utils import *
from src.core.errors import *


class Socks5ClientHandshakeProtocol(HandshakeProtocol):
    def client_handshake(self, cli: socket.socket):
        try:
            ver, n_methods = recv_exact(cli, 2)
            if ver != SOCKS_VERSION:
                raise SocksVersionError(f"Invalid socks version: {ver}")
            methods = recv_exact(cli, n_methods)
            if AUTH_NO_AUTH not in methods:
                raise SocksAuthError(f"Unsupported authentication methods: {methods}")
            response = struct.pack("!BB", SOCKS_VERSION, AUTH_NO_AUTH)
            cli.sendall(response)

            # CONNECT
            ver, cmd, _, atyp = recv_exact(cli, 4)
            if ver != SOCKS_VERSION:
                raise SocksVersionError(f"Invalid socks version: {ver}")
            if cmd != CMD_CONNECT:
                cli.sendall(create_socks_reply(REPLY_COMMAND_NOT_SUPPORTED))
                raise SocksAuthError(f"Unsupported command: {cmd}")

            if atyp == ATYP_IPV4:
                addr = socket.inet_ntoa(recv_exact(cli, 4))
            elif atyp == ATYP_DOMAIN:
                ln = recv_exact(cli, 1)[0]
                addr = recv_exact(cli, ln).decode()
            elif atyp == ATYP_IPV6:
                addr = socket.inet_ntop(socket.AF_INET6, recv_exact(cli, 16))
            else:
                cli.sendall(create_socks_reply(REPLY_ADDRESS_TYPE_NOT_SUPPORTED))
                raise SocksError(f"Unsupported ATYP: {atyp}")
            port = struct.unpack("!H", recv_exact(cli, 2))[0]
            return addr, port
        except SocksError:
            log.error(f"Client socks5 error: {e}")
            return None
        except Exception as e:
            cli.sendall(create_socks_reply(REPLY_GENERAL_FAILURE))
            log.error(f"Client error: {e}")
            return None

    def server_handshake(self, remote, dest_addr):
        if not dest_addr:
            return False
        try:
            addr_bytes = pack_address(dest_addr, ATYP_DOMAIN)
            remote.sendall(addr_bytes)

            resp = recv_exact(remote, 1)
            if not resp:
                raise SocksError("No response from remote server")
            if resp == b"\x00":
                return True
            else:
                log.debug(f"Remote server connection failed: {resp.hex()}")
            return False
        except ssl.SSLError as e:
            log.error(f"TLS handshake failed: {e}")
            return False
        except Exception as e:
            log.error(f"TCP CONNECT error: {e}")
            return False


class Socks5ServerHandshakeProtocol(HandshakeProtocol):
    def client_handshake(self, cli: socket.socket):
        try:
            if hasattr(cli, "cipher"):
                log.debug(f"TLS connection: {cli.cipher()}")

            addr_type = struct.unpack("!B", recv_exact(cli, 1))[0]
            if addr_type == ATYP_IPV4:
                addr_data = recv_exact(cli, 4)
                dest_addr = socket.inet_ntoa(addr_data)
            elif addr_type == ATYP_DOMAIN:
                domain_len = struct.unpack("!B", recv_exact(cli, 1))[0]
                addr_data = recv_exact(cli, domain_len)
                dest_addr = addr_data.decode("utf-8")
            elif addr_type == ATYP_IPV6:
                addr_data = recv_exact(cli, 16)
                dest_addr = socket.inet_ntop(socket.AF_INET6, addr_data)
            else:
                log.debug(f"Unsupported address type: {addr_type}")
                cli.sendall(b"\x01")
                return None

            port_data = recv_exact(cli, 2)
            dest_port = struct.unpack("!H", port_data)[0]
            return dest_addr, dest_port
        except Exception as e:
            log.error(f"SOCKS5 server handshake error: {e}")
            cli.sendall(b"\x01")
            return None

    def server_handshake(self, remote, dest_addr):
        return True
