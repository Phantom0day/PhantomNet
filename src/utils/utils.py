import errno
import socket
import struct
import logging
from typing import Optional, Tuple, BinaryIO
from src.utils.constants import *
from src.core.operation import Operation
from src.core.chain import InterceptorChain

log = logging.getLogger(__name__)


def recv_frame(sock: socket.socket, chain: InterceptorChain, ctx) -> Optional[bytes]:
    while True:
        try:
            ctx.data = sock.recv(DEFAULT_BUFFER_SIZE)
            if not ctx.data:
                return None

            ctx = chain.run(ctx)
            if ctx.drop:
                return None
            if ctx.data:
                frame, ctx.data = ctx.data, b""
                return frame
        except socket.error as e:
            if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                continue
            raise


def get_address_type(addr: str) -> int:
    """
    Determine the SOCKS5 address type for a given address string.
    """
    try:
        # check if it's an IPv4 address (x.x.x.x)
        if addr.count(".") == 3 and all(
            part.isdigit() and 0 <= int(part) <= 255 for part in addr.split(".")
        ):
            return ATYP_IPV4

        # check if it's an IPv6 address (contains ':')
        elif ":" in addr:
            return ATYP_IPV6

        # Otherwise, treat as domain name
        else:
            return ATYP_DOMAIN
    except Exception:
        # Default to domain name if we can't determine
        return ATYP_DOMAIN


def parse_address(
    data: BinaryIO, address_type: int
) -> Tuple[Optional[str], Optional[int]]:
    """
    Parse an address from a BytesIO based on the SOCKS5 address type.
    Returns (address, port) tuple
    """
    try:
        if address_type == ATYP_IPV4:
            # IPv4 address (4 bytes)
            addr_data = data.read(4)
            if len(addr_data) < 4:
                log.error("Invalid IPv4 address length")
                return None, None
            addr = socket.inet_ntoa(addr_data)
        elif address_type == ATYP_DOMAIN:
            # Domain name (variable length)
            addr_len = data.read(1)
            if not addr_len:
                log.error("Failed to receive domain name length")
                return None, None
            addr_len = ord(addr_len)
            addr_data = data.read(addr_len)
            if len(addr_data) < addr_len:
                log.error("Invalid domain name length")
                return None, None
            addr = addr_data.decode("utf-8")
        elif address_type == ATYP_IPV6:
            # IPv6 address (16 bytes)
            addr_data = data.read(16)
            if len(addr_data) < 16:
                log.error("Invalid IPv6 address length")
                return None, None
            addr = socket.inet_ntop(socket.AF_INET6, addr_data)
        else:
            log.error(f"Unsupported address type: {address_type}")
            return None, None

        # Get port (2 bytes)
        port_data = data.read(2)
        if len(port_data) < 2:
            log.error("Invalid port data")
            return addr, None
        port = struct.unpack("!H", port_data)[0]

        return addr, port
    except Exception as e:
        log.error(f"Error parsing address: {e}")
        return None, None


def pack_address(address: Tuple[str, int], atyp):
    if atyp == ATYP_IPV4:
        raise NotImplementedError()
    elif atyp == ATYP_DOMAIN:
        addr_bytes = address[0].encode("utf-8")
    elif atyp == ATYP_IPV6:
        raise NotImplementedError()
    port_bytes = struct.pack("!H", address[1])
    return struct.pack("!BB", atyp, len(addr_bytes)) + addr_bytes + port_bytes


def create_socks_reply(
    reply_code: int, bind_addr: str = "0.0.0.0", bind_port: int = 0
) -> bytes:
    """
    Create a SOCKS5 reply packet.
    """
    try:
        addr_type = get_address_type(bind_addr)
        # Start with version, reply code, reserved, and address type
        reply = struct.pack("!BBBB", SOCKS_VERSION, reply_code, 0, addr_type)

        if addr_type == ATYP_IPV4:
            # IPv4 address
            reply += socket.inet_aton(bind_addr)
        elif addr_type == ATYP_DOMAIN:
            # Domain name
            domain_bytes = bind_addr.encode()
            reply += struct.pack("!B", len(domain_bytes)) + domain_bytes
        elif addr_type == ATYP_IPV6:
            # IPv6 address
            reply += socket.inet_pton(socket.AF_INET6, bind_addr)

        reply += struct.pack("!H", bind_port)  # Port
        return reply
    except Exception as e:
        log.error(f"Error creating SOCKS reply: {e}")
        # Create a generic failure reply
        return (
            struct.pack("!BBBB", SOCKS_VERSION, REPLY_GENERAL_FAILURE, 0, ATYP_IPV4)
            + socket.inet_aton("0.0.0.0")
            + struct.pack("!H", 0)
        )


def create_socks5_connect_request(dest_addr: str, dest_port: int) -> bytes:
    """
    Create a SOCKS5 connect request.
    """
    try:
        # Determine address type
        addr_type = get_address_type(dest_addr)
        if addr_type == ATYP_IPV4:  # IPv4
            addr_bytes = socket.inet_aton(dest_addr)
            addr_data = struct.pack("!B", addr_type) + addr_bytes
        elif addr_type == ATYP_IPV6:  # IPv6
            addr_bytes = socket.inet_pton(socket.AF_INET6, dest_addr)
            addr_data = struct.pack("!B", addr_type) + addr_bytes
        else:  # Domain name
            addr_bytes = dest_addr.encode("utf-8")
            addr_data = struct.pack("!BB", addr_type, len(addr_bytes)) + addr_bytes

        # Create request
        request = struct.pack("!BBB", SOCKS_VERSION, CMD_CONNECT, 0) + addr_data
        request += struct.pack("!H", dest_port)
        return request
    except Exception as e:
        log.error(f"Error creating SOCKS5 connect request: {e}")
        return b""


def close_socket(sock: socket.socket) -> None:
    """Safely close a socket."""
    if sock:
        try:
            sock.close()
        except Exception as e:
            log.error(f"Error closing socket: {e}")


def packAndSend(sock: socket.socket, chain, ctx, data: bytes = None):
    if data:
        ctx.req_data = data
    ctx.operation = Operation.PACK
    chain.run(ctx)
    sock.sendall(ctx.req_data)
