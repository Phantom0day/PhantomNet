"""
Utility functions used throughout the SOCKS5 proxy implementation.
"""

import socket
import struct
import logging
from . import constants as const

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def extract_address_port(socket_obj):
    """
    Extract the address and port from a socket's getpeername() or getsockname().

    Args:
        socket_obj: A socket object

    Returns:
        tuple: (address, port)
    """
    try:
        addr_info = socket_obj.getsockname()
        return addr_info[0], addr_info[1]
    except Exception as e:
        logger.error(f"Error extracting address and port: {e}")
        return None, None


def parse_address(socket_obj, address_type):
    """
    Parse an address from a socket based on the SOCKS5 address type.

    Args:
        socket_obj: A socket object to receive data from
        address_type: SOCKS5 address type (IPv4, Domain, IPv6)

    Returns:
        str: The parsed address
    """
    try:
        if address_type == const.ATYP_IPV4:
            addr_data = recv_all(socket_obj, 4)
            if len(addr_data) < 4:
                logger.error("Invalid IPv4 address length")
                return None
            return socket.inet_ntoa(addr_data)

        elif address_type == const.ATYP_DOMAIN:
            addr_len = socket_obj.recv(1)
            if not addr_len:
                logger.error("Failed to receive domain name length")
                return None

            addr_len = ord(addr_len)
            addr_data = recv_all(socket_obj, addr_len)
            if len(addr_data) < addr_len:
                logger.error("Invalid domain name length")
                return None
            return addr_data.decode("utf-8")

        elif address_type == const.ATYP_IPV6:
            addr_data = recv_all(socket_obj, 16)
            if len(addr_data) < 16:
                logger.error("Invalid IPv6 address length")
                return None
            return socket.inet_ntop(socket.AF_INET6, addr_data)

        else:
            logger.error(f"Unsupported address type: {address_type}")
            return None

    except Exception as e:
        logger.error(f"Error parsing address: {e}")
        return None


def get_address_type(addr: str):
    """
    Determine the SOCKS5 address type for a given address string.

    Args:
        addr: Address string

    Returns:
        int: SOCKS5 address type constant
    """
    try:
        # check if it's an IPv4 address (x.x.x.x)
        if addr.count(".") == 3 and all(
            part.isdigit() and 0 <= int(part) <= 255 for part in addr.split(".")
        ):
            return const.ATYP_IPV4

        # check if it's an IPv6 address (contains ':')
        elif ":" in addr:
            return const.ATYP_IPV6

        # Otherwise, treat as domain name
        else:
            return const.ATYP_DOMAIN
    except Exception:
        # Default to domain name if we can't determine
        return const.ATYP_DOMAIN


def create_socks_address_packet(addr: str, port):
    """
    Create a SOCKS5 address packet for the given address and port.

    Args:
        addr: Address string
        port: Port number

    Returns:
        bytes: SOCKS5 formatted address packet
    """
    try:
        addr_type = get_address_type(addr)

        if addr_type == const.ATYP_IPV4:
            return (
                struct.pack("!B", addr_type)
                + socket.inet_aton(addr)
                + struct.pack("!H", port)
            )

        elif addr_type == const.ATYP_DOMAIN:
            addr_bytes = addr.encode()
            return (
                struct.pack("!B", addr_type)
                + struct.pack("!B", len(addr_bytes))
                + addr_bytes
                + struct.pack("!H", port)
            )

        elif addr_type == const.ATYP_IPV6:
            return (
                struct.pack("!B", addr_type)
                + socket.inet_pton(socket.AF_INET6, addr)
                + struct.pack("!H", port)
            )

        else:
            logger.error(f"Unsupported address type: {addr_type}")
            return None

    except Exception as e:
        logger.error(f"Error creating SOCKS address packet: {e}")
        return None


def recv_all(socket_obj: socket.socket, n):
    """
    Receive exactly n bytes from a socket, or until EOF is hit.

    Args:
        socket_obj: Socket to receive from
        n: Number of bytes to receive

    Returns:
        bytes: Received data
    """
    data = b""
    while len(data) < n:
        packet = socket_obj.recv(n - len(data))
        if not packet:
            return data
        data += packet
    return data


def create_socks_reply_packet(reply_code, bind_addr: str = None, bind_port: int = 0):
    """
    Create a SOCKS5 reply packet.

    Args:
        reply_code: SOCKS5 reply code
        bind_addr: Bound address
        bind_port: Bound port

    Returns:
        bytes: SOCKS5 reply packet
    """
    try:
        if not bind_addr:
            # Default to 0.0.0.0:0 if no bind address is provided
            bind_addr = const.NONSPEC_HOST
            bind_port = 0

        addr_type = get_address_type(bind_addr)

        # Pack the reply
        reply = struct.pack("!BBB", const.SOCKS_VERSION, reply_code, 0)

        if addr_type == const.ATYP_IPV4:
            reply += struct.pack("!B", const.ATYP_IPV4) + socket.inet_aton(bind_addr)
        elif addr_type == const.ATYP_DOMAIN:
            addr_bytes = bind_addr.encode()
            reply += struct.pack("!BB", const.ATYP_DOMAIN, len(addr_bytes)) + addr_bytes
        elif addr_type == const.ATYP_IPV6:
            reply += struct.pack("!B", const.ATYP_IPV6) + socket.inet_pton(
                socket.AF_INET6, bind_addr
            )

        reply += struct.pack("!H", bind_port)
        return reply
    except Exception as e:
        logger.error(f"Error creating SOCKS reply packet: {e}")
        # Create a generic failure reply
        return (
            struct.pack(
                "!BBBB",
                const.SOCKS_VERSION,
                const.REPLY_GENERAL_FAILURE,
                0,
                const.ATYP_IPV4,
            )
            + socket.inet_aton(const.NONSPEC_HOST)
            + struct.pack("!H", 0)
        )


def close_socket(socket_obj: socket.socket):
    """
    Safely close a socket.

    Args:
        socket_obj: Socket to close
    """
    if socket_obj:
        try:
            socket_obj.close()
        except Exception as e:
            logger.error(f"Error closing socket: {e}")
