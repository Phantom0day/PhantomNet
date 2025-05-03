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

logger = logging.getLogger(__name__)


class LocalClientProxy:
    """
    Local client proxy that listens for connections and forwards them
    to a remote SOCKS5 server.
    """

    def __init__(
        self,
        local_host="127.0.0.1",
        local_port=const.DEFAULT_LOCAL_PORT,
        server_host=None,
        server_port=const.DEFAULT_SERVER_PORT,
    ):
        """
        Initialize the local client proxy.

        Args:
            local_host: Local host to bind to
            local_port: Local port to bind to
            server_host: SOCKS5 server host
            server_port: SOCKS5 server port
        """
        self.local_host = local_host
        self.local_port = local_port
        self.server_host = server_host
        self.server_port = server_port
        self.server_socket = None
        self.running = False
        self.shutting_down = False
        self.threads: List[threading.Thread] = []

        if not server_host:
            raise ValueError("SOCKS5 server host must be specified")

        self.socks_client = SOCKS5Client(server_host, server_port)

    def start(self):
        """
        Start the local client proxy.

        Returns:
            bool: True if started successfully, False otherwise
        """
        if self.running:
            logger.warning("Local proxy is already running")
            return False

        try:
            # Create server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.local_host, self.local_port))
            self.server_socket.listen(100)

            # Set a timeout so the socket doesn't block indefinitely
            self.server_socket.settimeout(const.DEFAULT_SOCKET_TIMEOUT)

            self.running = True
            logger.info(
                f"Local client proxy started on {self.local_host}:{self.local_port}"
            )
            logger.info(
                f"Forwarding to SOCKS5 server at {self.server_host}:{self.server_port}"
            )
            logger.info("Press Ctrl+C to stop the proxy")

            # Main server loop
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    logger.info(
                        f"New local connection from {client_address[0]}:{client_address[1]}"
                    )

                    # Start a new thread to handle the client
                    client_thread = threading.Thread(
                        target=self._handle_client, args=(client_socket,)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    self.threads.append(client_thread)

                    # Clean up finished threads
                    self._clean_finished_threads()

                except socket.timeout:
                    # This is normal, just continue the loop
                    continue
                except Exception as e:
                    if self.running:
                        logger.error(f"Local proxy error: {e}")

            return True
        except Exception as e:
            logger.error(f"Failed to start local proxy: {e}")
            self.stop()
            return False

    def stop(self):
        """
        Stop the local client proxy.

        Returns:
            bool: True if stopped successfully, False otherwise
        """
        if self.shutting_down:
            return True

        self.shutting_down = True
        self.running = False
        logger.info("Shutting down local client proxy...")

        if self.server_socket:
            utils.close_socket(self.server_socket)
            self.server_socket = None

        # Wait for all threads to finish (with timeout)
        self._join_all_threads()

        logger.info("Local client proxy stopped")
        self.shutting_down = False
        return True

    def _clean_finished_threads(self):
        """Remove finished threads from the threads list."""
        self.threads = [t for t in self.threads if t.is_alive()]

    def _join_all_threads(self):
        """Join all client threads with a timeout."""
        for t in self.threads:
            try:
                if t.is_alive():
                    t.join(const.DEFAULT_THREAD_JOIN_TIMEOUT)
            except Exception as e:
                logger.error(f"Error joining thread: {e}")

        # Clear the threads list
        self.threads = []

    def _handle_client(self, client_socket: socket.socket):
        """
        Handle a client connection.

        Args:
            client_socket: Client socket
        """
        remote_socket = None

        try:
            # SOCKS5 initialization
            if not self._socks5_initialization(client_socket):
                return

            # SOCKS5 request
            remote_socket = self._socks5_request(client_socket)
            if not remote_socket:
                return

            # Proxy data between client and remote
            self._proxy_data(client_socket, remote_socket)

        except Exception as e:
            logger.error(f"Error handling local client: {e}")
        finally:
            utils.close_socket(client_socket)
            if remote_socket:
                utils.close_socket(remote_socket)

    def _socks5_initialization(self, client_socket: socket.socket) -> bool:
        """
        Handle SOCKS5 initialization from the local client.

        Args:
            client_socket: Client socket

        Returns:
            bool: True if initialization successful, False otherwise
        """
        try:
            # Receive client authentication methods
            data = utils.recv_all(client_socket, 2)
            if len(data) < 2:
                logger.error("SOCKS5 initialization failed - invalid data length")
                return False

            version, nmethods = struct.unpack("!BB", data)
            if version != const.SOCKS_VERSION:
                logger.error(f"Unsuppported SOCKS version: {version}")
                return False

            # Receive authentication methods
            methods = utils.recv_all(client_socket, nmethods)
            if len(methods) < nmethods:
                logger.error("SOCKS5 initialization failed - invalid methods length")
                return False

            # We'll accept method 0 (no authentication required)
            client_socket.sendall(
                struct.pack("!BB", const.SOCKS_VERSION, const.AUTH_NO_AUTH)
            )
            return True

        except Exception as e:
            logger.error(f"SOCKS5 initialization error: {e}")
            return False

    def _socks5_request(self, client_socket: socket.socket) -> socket.socket:
        """
        Handle SOCKS5 request from the local client.

        Args:
            client_socket: Client socket

        Returns:
            Optional[socket.socket]: Remote socket if successful, None otherwise
        """
        try:
            # Receive client request
            data = utils.recv_all(client_socket, 4)
            if len(data) < 4:
                logger.error("SOCKS5 request failed - invalid data length")
                return None

            version, cmd, _, address_type = struct.unpack("!BBBB", data)
            if version != const.SOCKS_VERSION:
                logger.error(f"Unsupported SOCKS version: {version}")
                client_socket.sendall(
                    utils.create_socks_reply_packet(const.REPLY_GENERAL_FAILURE)
                )
                return None
            if cmd != const.CMD_CONNECT:
                logger.error(f"Unsupported SOCKS command: {cmd}")
                client_socket.sendall(
                    utils.create_socks_reply_packet(const.REPLY_COMMAND_NOT_SUPPORTED)
                )
                return None

            # Parse destination address
            dest_addr = utils.parse_address(client_socket, address_type)
            if not dest_addr:
                logger.error("Failed to parse destination address")
                client_socket.sendall(
                    utils.create_socks_reply_packet(
                        const.REPLY_ADDRESS_TYPE_NOT_SUPPORTED
                    )
                )
                return None

            # Get destination port
            port_data = utils.recv_all(client_socket, 2)
            if len(port_data) < 2:
                logger.error("SOCKS5 request failed - invalid port length")
                client_socket.sendall(
                    utils.create_socks_reply_packet(const.REPLY_GENERAL_FAILURE)
                )
                return None

            dest_port = struct.unpack("!H", port_data)[0]
            logger.info(
                f"Local client proxy request to connect to {dest_addr}:{dest_port}"
            )

            # Connect to destination via SOCKS5 server
            return self._connect_via_server(client_socket, dest_addr, dest_port)

        except Exception as e:
            logger.error(f"SOCKS5 request error: {e}")
            try:
                client_socket.sendall(
                    utils.create_socks_reply_packet(const.REPLY_GENERAL_FAILURE)
                )
            except:
                pass
            return None

    def _connect_via_server(
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

    def _proxy_data(self, client_socket: socket.socket, remote_socket: socket.socket):
        """
        Proxy data between local client and remote socket.

        Args:
            client_socket: Client socket
            remote_socket: Remote socket
        """
        client_socket.setblocking(False)
        remote_socket.setblocking(False)

        while self.running:
            try:
                # Wait until client or remote is available for read
                r, _, e = select.select(
                    [client_socket, remote_socket],
                    [],
                    [client_socket, remote_socket],
                    const.DEFAULT_SELECT_TIMEOUT,
                )

                if client_socket in e or remote_socket in e:
                    break

                for s in r:
                    try:
                        data = s.recv(const.DEFAULT_BUFFER_SIZE)
                        if not data:
                            return
                        if s is client_socket:
                            remote_socket.sendall(data)
                        else:
                            client_socket.sendall(data)
                    except ConnectionError:
                        return
            except (select.error, socket.error) as e:
                logger.error(f"Socket error in proxy_data: {e}")
                break
            except Exception as e:
                logger.error(f"Error in proxy_data: {e}")
                break
