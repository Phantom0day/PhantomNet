"""
SOCKS5 server implementation.
"""

import socket
import select
import struct
import threading
import logging
from typing import List, Optional

from ..common import constants as const
from ..common import utils
from src.base import SOCKS5Base
from src.auth import NoAuthHandler

logger = logging.getLogger(__name__)


class SOCKS5Server(SOCKS5Base):
    """
    SOCKS5 server implementation that handles client connections and forwards
    traffic to the requested destinations.
    """

    def __init__(
        self,
        host=const.NONSPEC_HOST,
        port=const.DEFAULT_SERVER_PORT,
        auth_handlers=None,
    ):
        """
        Initialize the SOCKS5 server.

        Args:
            host: Host address to bind to
            port: Port number to bind to
            auth_handlers: List of authentication handlers
        """
        super().__init__(
            host,
            port,
            const.MODE_SERVER,
            auth_handlers or [NoAuthHandler()],
        )

    def _perform_version_handshake(self, socket_obj: socket.socket) -> bool:
        """
        Perform version handshake to ensure client and server are compatible.

        Args:
            socks_obj: Socket connected to the peer
            is_server: True if running in server mode

        Returns:
            bool: True if versions are compatible
        """
        try:
            # Server: Receive client version and respond
            data = utils.recv_all(socket_obj, 3)
            if len(data) < 3:
                logger.error("Version handshake failed - invalid data length")
                return False

            client_major, client_minor, client_patch = struct.unpack("!BBB", data)
            logger.info(f"Client version: {client_major}.{client_minor}.{client_patch}")

            # Check compatibility (major version must match, minor can differ)
            compatible = client_major == const.APP_VERSION_MAJOR

            # Send server version and compatibility status
            socket_obj.sendall(
                struct.pack(
                    "!BBBB",
                    const.APP_VERSION_MAJOR,
                    const.APP_VERSION_MINOR,
                    const.APP_VERSION_PATCH,
                    (
                        const.VERSION_COMPATIBLE
                        if compatible
                        else const.VERSION_INCOMPATIBLE
                    ),
                )
            )
            return compatible
        except Exception as e:
            logger.error(f"Version handshake error: {e}")
        return False

    def _connect_to_destination(
        self, client_socket: socket.socket, dest_addr: str, dest_port: int
    ):
        """
        Connect to the destination and send the appropriate SOCKS5 reply.

        Args:
            client_socket: Client socket
            dest_addr: Destination address
            dest_port: Destination port

        Returns:
            Optional[socket.socket]: Remote socket if successful, None otherwise
        """
        remote_socket = None

        try:
            # Create socket
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_socket.settimeout(const.DEFAULT_SOCKET_TIMEOUT)
            remote_socket.connect((dest_addr, dest_port))

            # Get the bound address/port
            bind_addr, bind_port = utils.extract_address_port(remote_socket)

            # Send success response
            client_socket.sendall(
                utils.create_socks_reply_packet(
                    const.REPLY_SUCCESS, bind_addr, bind_port
                )
            )
            return remote_socket
        except socket.timeout:
            logger.error(f"Timeout connecting to {dest_addr}:{dest_port}")
            if client_socket:
                client_socket.sendall(
                    utils.create_socks_reply_packet(const.REPLY_HOST_UNREACHABLE)
                )
            if remote_socket:
                utils.close_socket(remote_socket)
            return None
        except socket.error as e:
            logger.error(f"Socket error connecting to {dest_addr}:{dest_port}: {e}")
            if client_socket:
                reply_code = const.REPLY_GENERAL_FAILURE

                if e.errno == 111:  # Connection refused
                    reply_code = const.REPLY_CONNECTION_REFUSED
                elif e.errno == 113:  # No route to host
                    reply_code = const.REPLY_HOST_UNREACHABLE
                elif e.errno == 101:  # Network unreachable
                    reply_code = const.REPLY_NETWORK_UNREACHABLE

                client_socket.sendall(utils.create_socks_reply_packet(reply_code))
            if remote_socket:
                utils.close_socket(remote_socket)
            return None
        except Exception as e:
            logger.error(f"Error connecting to {dest_addr}:{dest_port}: {e}")
            if client_socket:
                client_socket.sendall(
                    utils.create_socks_reply_packet(const.REPLY_GENERAL_FAILURE)
                )
            if remote_socket:
                utils.close_socket(remote_socket)
            return None
