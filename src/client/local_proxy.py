"""
Local client proxy that forwards traffic to a SOCKS5 server.
"""

import socket
import select
import struct
import threading
import logging
from typing import List

from ..common import constants as const
from ..common import utils
from .socks5_client import SOCKS5Client
from src.base import SOCKS5Base
from src.auth import NoAuthHandler, UsernamePasswordAuthHandler

logger = logging.getLogger(__name__)


class LocalClientProxy(SOCKS5Base):
    """
    Local client proxy that listens for connections and forwards them
    to a remote SOCKS5 server.
    """

    def __init__(
        self,
        local_host=const.LOCAL_HOST,
        local_port=const.DEFAULT_LOCAL_PORT,
        server_host=None,
        server_port=const.DEFAULT_SERVER_PORT,
        auth_handlers=None,
    ):
        """
        Initialize the local client proxy.

        Args:
            local_host: Local host to bind to
            local_port: Local port to bind to
            server_host: SOCKS5 server host
            server_port: SOCKS5 server port
            auth_handlers: List of authentication handlers
        """
        super().__init__(
            local_host,
            local_port,
            const.MODE_CLIENT,
            auth_handlers or [NoAuthHandler()],
        )
        self.server_host = server_host
        self.server_port = server_port

        if not server_host:
            raise ValueError("SOCKS5 server host must be specified")

        self.socks_client = SOCKS5Client(server_host, server_port)

    def _connect_to_destination(
        self, client_socket: socket.socket, dest_addr: str, dest_port: int
    ):
        """
        Connect to the destination via the SOCKS5 server.

        Args:
            client_socket: Client socket
            dest_addr: Destination address
            dest_port: Destination port

        Returns:
            Optional[socket.socket]: Remote socket if successful, None otherwise
        """
        try:
            # Use the SOCKS5 client to connect to the destination through the server
            remote_socket = self.socks_client.connect(dest_addr, dest_port)

            if not remote_socket:
                logger.error("Failed to connect to destination via SOCKS5 server")
                client_socket.sendall(
                    utils.create_socks_reply_packet(const.REPLY_HOST_UNREACHABLE)
                )
                return None

            # Send success response to local client
            bind_addr, bind_port = utils.extract_address_port(remote_socket)

            client_socket.sendall(
                utils.create_socks_reply_packet(
                    const.REPLY_SUCCESS, bind_addr, bind_port
                )
            )

            return remote_socket
        except Exception as e:
            logger.error(f"Error connecting via server: {e}")
            try:
                client_socket.sendall(
                    utils.create_socks_reply_packet(const.REPLY_GENERAL_FAILURE)
                )
            except:
                pass
            return None
    def _perform_version_handshake(self, socket_obj: socket.socket) -> bool:
        """
        Local client proxy doesn't need to perform version handshake on the
        listening socket as it acts as a server for local clients.
        For server mode version checking, this will be handled by the SOCKS5Client.
        
        Args:
            socket_obj: Socket connected to the peer
            
        Returns:
            bool: Always returns True
        """
        # Local client proxy doesn't need to verify version on the listening socket
        # as local applications don't use the version handshake
        return True