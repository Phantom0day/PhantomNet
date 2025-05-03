"""
SOCKS5 client implementation
"""

import socket
import struct
import logging
from typing import Optional
from ..common import constants as const
from ..common import utils
from src.base import SOCKS5Base

logger = logging.getLogger(__name__)


class SOCKS5Client:
    """
    SOCKS5 client implementation for connecting to a SOCKS5 server.
    """

    def __init__(self, server_host, server_port=const.DEFAULT_SERVER_PORT):
        """
        Initialize the SOCKS5 client.

        Args:
            server_host: SOCKS5 server host
            server_port: SOCKS5 server port
        """
        self.server_host = server_host
        self.server_port = server_port

    def connect(self, dest_host, dest_port) -> Optional[socket.socket]:
        """
        Connect to destination through SOCKS5 server.

        Args:
            dest_host: Destination host
            dest_port: Destination port

        Returns:
            Optional[socket.socket]: Socket if connection successful, None otherwise
        """
        sock = None

        try:
            # Create a socket and connect to the SOCKS5 server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(const.DEFAULT_SOCKET_TIMEOUT)
            sock.connect((self.server_host, self.server_port))

            # SOCKS5 handshake
            if not self._perform_handshake(sock):
                logger.error("SOCKS5 handshake failed")
                utils.close_socket(sock)
                return None

            # SOCKS5 connection request
            if not self._perform_connection_request(sock, dest_host, dest_port):
                logger.error("SOCKS5 connection requtest failed")
                utils.close_socket(sock)
                return None

            logger.info(f"Connected to {dest_host}:{dest_port} via SOCKS5 server")
            return sock

        except socket.timeout:
            logger.error(
                f"Timeout connecting to SOCKS5 server {self.server_host}:{self.server_port}"
            )
            if sock:
                utils.close_socket(sock)
            return None
        except Exception as e:
            logger.error(
                f"Error connecting to {dest_host}:{dest_port} via SOCKS5 server: {e}"
            )
            if sock:
                utils.close_socket(sock)
            return None

    def _perform_handshake(self, sock: socket.socket) -> bool:
        """
        Perform SOCKS5 handshake with the server.

        Args:
            sock: Socket connected to the SOCKS5 server

        Returns:
            bool: True if handshake successfull, False otherwise
        """
        try:
            # Send handshake request (version 5, 1 method, no auth)
            sock.sendall(
                struct.pack("!BBB", const.SOCKS_VERSION, 1, const.AUTH_NO_AUTH)
            )

            # Get server response
            response = utils.recv_all(sock, 2)
            if len(response) < 2:
                logger.error("SOCKS5 handshake failed - invalid response length")
                return False

            version, method = struct.unpack("!BB", response)
            if version != const.SOCKS_VERSION:
                logger.error(f"Unsupported SOCKS version in response: {version}")
                return False

            if method != const.AUTH_NO_AUTH:
                logger.error(f"Server requires authentication (method: {method})")
                return False

            return True
        except Exception as e:
            logger.error(f"SOCKS5 handshake error: {e}")
            return False

    def _perform_connection_request(
        self, sock: socket.socket, dest_host: str, dest_port: int
    ) -> bool:
        """
        Send a SOCKS5 connection request.

        Args:
            sock: Socket connected to the SOCKS5 server
            dest_host: Destination host
            dest_port: Destination port

        Returns:
            bool: True if connection request successful, False otherwise
        """
        try:
            address_packet = utils.create_socks_address_packet(dest_host, dest_port)
            if not address_packet:
                return False

            req = (
                struct.pack("!BBB", const.SOCKS_VERSION, const.CMD_CONNECT, 0)
                + address_packet
            )

            sock.sendall(req)

            # Get response
            response = utils.recv_all(sock, 4)
            if len(response) < 4:
                logger.error(
                    "SOCKS5 connection request failed - invalid response length"
                )
                return False

            version, status, _, addr_type = struct.unpack("!BBBB", response)

            if version != const.SOCKS_VERSION:
                logger.error(f"Unsupported SOCKS version in response: {version}")
                return False

            if status != const.REPLY_SUCCESS:
                error_messages = {
                    const.REPLY_GENERAL_FAILURE: "General failure",
                    const.REPLY_CONNECTION_NOT_ALLOWED: "Connection not allowed by ruleset",
                    const.REPLY_NETWORK_UNREACHABLE: "Network unreachable",
                    const.REPLY_HOST_UNREACHABLE: "Host unreachable",
                    const.REPLY_CONNECTION_REFUSED: "Connection refused",
                    const.REPLY_TTL_EXPIRED: "TTL expired",
                    const.REPLY_COMMAND_NOT_SUPPORTED: "Command not supported",
                    const.REPLY_ADDRESS_TYPE_NOT_SUPPORTED: "Address type not supported",
                }
                error_msg = error_messages.get(status, f"Unknow error (code: {status})")
                logger.error(f"SOCKS5 connection request failed: {error_msg}")
                return False

            # skip the bound address/port in the response
            if addr_type == const.ATYP_IPV4:
                utils.recv_all(sock, 4)  # IPv4 address
            elif addr_type == const.ATYP_DOMAIN:
                domain_len = sock.recv(1)[0]
                utils.recv_all(sock, domain_len)  # Domain
            elif addr_type == const.ATYP_IPV6:
                utils.recv_all(sock, 16)  # IPv6 address
            else:
                logger.error(f"Unsupported address type in response: {addr_type}")
                return False

            utils.recv_all(sock, 2)  # Port

            return True

        except Exception as e:
            logger.error(f"SOCKS5 connection request error: {e}")
            return False
