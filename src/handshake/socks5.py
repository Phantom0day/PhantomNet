import asyncio
import socket
import ssl
import struct
from typing import Tuple, Dict, Any, Optional

from .base import *
from src.utils import *
from src.core.errors import *


class Socks5ClientHandshakeProtocol(HandshakeProtocol):
    async def client_handshake(
        self,
        client: Tuple[asyncio.StreamReader, asyncio.StreamWriter],
    ):
        try:
            ver, n_methods = await read_exact(client[0], 2)
            if ver != SOCKS_VERSION:
                raise SocksVersionError(f"Invalid socks version: {ver}")
            methods = await read_exact(client[0], n_methods)

            if AUTH_NO_AUTH not in methods:
                raise SocksAuthError(f"Unsupported authentication methods: {methods}")
            response = struct.pack("!BB", SOCKS_VERSION, AUTH_NO_AUTH)
            await write_data(client[1], response)

            # CONNECT
            ver, cmd, _, atyp = await read_exact(client[0], 4)
            if ver != SOCKS_VERSION:
                raise SocksVersionError(f"Invalid socks version: {ver}")
            if cmd == CMD_CONNECT:
                if atyp == ATYP_IPV4:
                    addr_bytes = await read_exact(client[0], 4)
                    addr = socket.inet_ntoa(addr_bytes)
                elif atyp == ATYP_DOMAIN:
                    domain_len = (await read_exact(client[0], 1))[0]
                    domain = await read_exact(client[0], domain_len)
                    addr = domain.decode()
                elif atyp == ATYP_IPV6:
                    addr_bytes = await read_exact(client[0], 16)
                    addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
                else:
                    await write_data(
                        client[1], create_socks_reply(REPLY_ADDRESS_TYPE_NOT_SUPPORTED)
                    )
                    raise SocksError(f"Unsupported ATYP: {atyp}")

                port = struct.unpack("!H", await read_exact(client[0], 2))[0]
                return addr, port
            elif cmd == CMD_UDP_ASSOCIATE:
                _ = await self._read_dest(client[0], atyp)
                port = struct.unpack("!H", await read_exact(client[0], 2))[0]
                return ("UDP", 0)
            else:
                await write_data(
                    client[1],
                    create_socks_reply(REPLY_COMMAND_NOT_SUPPORTED),
                )
                raise SocksAuthError(f"Unsupported command: {cmd}")
        except SocksError:
            log.error(f"Client socks5 error")
            log.exception(e)
            return None
        except Exception as e:
            await write_data(client[1], create_socks_reply(REPLY_GENERAL_FAILURE))
            log.error(f"Client error")
            log.exception(e)
            return None

    async def server_handshake(
        self,
        remote: Tuple[asyncio.StreamReader, asyncio.StreamWriter],
        dest_addr,
    ):
        if not dest_addr:
            return False
        try:
            addr_bytes = pack_address(dest_addr, ATYP_DOMAIN)
            await write_data(remote[1], addr_bytes)

            resp = await read_exact(remote[0], 1)
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
    async def client_handshake(
        self,
        client: Tuple[asyncio.StreamReader, asyncio.StreamWriter],
    ):
        try:
            addr_type = (await read_exact(client[0], 1))[0]
            if addr_type == ATYP_IPV4:
                addr_data = await read_exact(client[0], 4)
                dest_addr = socket.inet_ntoa(addr_data)
            elif addr_type == ATYP_DOMAIN:
                domain_len = (await read_exact(client[0], 1))[0]
                addr_data = await read_exact(client[0], domain_len)
                dest_addr = addr_data.decode("utf-8")
            elif addr_type == ATYP_IPV6:
                addr_data = await read_exact(client[0], 16)
                dest_addr = socket.inet_ntop(socket.AF_INET6, addr_data)
            else:
                log.debug(f"Unsupported address type: {addr_type}")
                await write_data(client[1], b"\x01")
                return None

            dest_port = struct.unpack("!H", await read_exact(client[0], 2))[0]
            return dest_addr, dest_port
        except Exception as e:
            log.error(f"SOCKS5 server handshake error: {e}")
            await write_data(client[1], b"\x01")
            return None

    async def server_handshake(self, remote, dest_addr):
        return True
