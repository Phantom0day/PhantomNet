import logging
import select
import socket
import struct
import threading
from typing import List

from src.common import utils
from src.common import constants as const
from src.auth import NoAuthHandler, UsernamePasswordAuthHandler
from src.common import ConnectionPool


logger = logging.getLogger(__name__)


class SOCKS5Base:
    """Base class for SOCKS5 client & server implementations."""

    def __init__(self, host, port, mode, auth_handlers=None):
        """
        Initialize the SOCKS5 proxy.

        Args:
            host: Host address to bind to
            port: Port number to bind to
            mode: Proxy mode (server/client)
            auth_handlers: List of authentication handlers
        """
        self.host = host
        self.port = port
        self.mode: str = mode
        self.auth_handlers = auth_handlers or [NoAuthHandler()]
        self.auth_methods = {
            handler.get_method(): handler for handler in self.auth_handlers
        }
        self.is_server = mode == const.MODE_SERVER
        self.running = False
        self.shutting_down = False
        self.threads: List[threading.Thread] = []
        self.server_socket: socket.socket = None
        self.connection_pool = ConnectionPool()

    def start(self):
        f"""
        Start the SOCKS5 {self.mode}.

        Returns:
            bool: True if started successfully, False otherwise
        """
        if self.running:
            logger.warning(f"{self.mode.capitalize()} is already running")
            return False

        try:
            # Create socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(100)

            # Set a timeout so the socket doesn't block indefinitely
            self.server_socket.settimeout(const.DEFAULT_SOCKET_TIMEOUT)

            self.running = True
            logger.info(f"SOCKS5 {self.mode} started on {self.host}:{self.port}")
            if not self.is_server:
                logger.info(
                    f"Forwarding to SOCKS5 server at {self.server_host}:{self.server_port}"
                )
            logger.info("Press Ctrl+C to stop the server")

            # Main server loop
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    logger.info(
                        f"New connection from {client_address[0]}:{client_address[1]}"
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
                        logger.error(f"{self.mode.capitalize()} error: {e}")

            return True
        except Exception as e:
            logger.error(f"Failed to start {self.mode}: {e}")
            self.stop()
            return False

    def stop(self):
        """
        Stop the SOCKS5 server.

        Returns:
            bool: True if stopped successfully, False otherwise
        """
        if self.shutting_down:
            return True

        self.shutting_down = True
        self.running = False
        logger.info(f"Shutting down {self.mode}...")

        if self.server_socket:
            utils.close_socket(self.server_socket)
            self.server_socket = None

        # Wait for all threads to finish (with timeout)
        self._join_all_threads()

        logger.info(f"{self.mode.capitalize()} stopped")
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
            # Client version handshake for server mode
            if self.is_server and not self._perform_version_handshake(client_socket):
                logger.error("Version handshake falied - incompatible client")
                return

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
            logger.error(f"Error handling client: {e}")
        finally:
            utils.close_socket(client_socket)
            if remote_socket:
                peername = remote_socket.getpeername()
                dest_addr = peername[0]
                dest_port = peername[1]
                if self.is_server and dest_addr and dest_port:
                    # Return socket to pool if possible
                    self.connection_pool.return_connection(
                        dest_addr, dest_port, remote_socket
                    )
                else:
                    utils.close_socket(remote_socket)

    def _socks5_initialization(self, client_socket: socket.socket) -> bool:
        """
        Handle SOCKS5 initialization.

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
                logger.error(f"Unsupported SOCKS version: {version}")
                return False

            # Receive authentication methods
            methods = utils.recv_all(client_socket, nmethods)
            if len(methods) < nmethods:
                logger.error("SOCKS5 initialization failed - invalid methods length")
                return False

            supported_method = const.AUTH_NO_ACCEPTABLE_METHODS
            for method in methods:
                if method in self.auth_methods:
                    supported_method = method
                    break

            # Send selected authentication method
            client_socket.sendall(
                struct.pack("!BB", const.SOCKS_VERSION, supported_method)
            )

            if supported_method == const.AUTH_NO_ACCEPTABLE_METHODS:
                logger.error("No acceptable authentication methods")
                return False

            # Perform authentication if needed
            if supported_method != const.AUTH_NO_AUTH:
                auth_handler = self.auth_methods[supported_method]
                if not auth_handler.authenticate(client_socket):
                    logger.error("Authentication failed")
                    return False
            return True

        except Exception as e:
            logger.error(f"SOCKS5 initialization error: {e}")
            return False

    def _perform_version_handshake(self, socket_obj: socket.socket) -> bool:
        raise NotImplementedError()

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

            if cmd == const.CMD_CONNECT:
                # Handle CONNECT command (existing code)
                return self._connect_to_destination(client_socket, dest_addr, dest_port)
            elif cmd == const.CMD_UDP_ASSOCIATE:
                # Handle UDP ASSOCIATE command
                success, udp_socket = self._handle_udp_associate(
                    client_socket, dest_addr, dest_port
                )
                if success:
                    # Wait for the control connection to close
                    while self.running:
                        try:
                            data = client_socket.recv(1)
                            if not data:
                                break
                        except:
                            break

                    # Close UDP socket
                    if udp_socket:
                        utils.close_socket(udp_socket)

                        return None
                else:
                    return None
            else:
                logger.error(f"Unsupported SOCKS command: {cmd}")
                client_socket.sendall(
                    utils.create_socks_reply_packet(const.REPLY_COMMAND_NOT_SUPPORTED)
                )
                return None

        except Exception as e:
            logger.error(f"SOCKS5 request error: {e}")
            try:
                client_socket.sendall(
                    utils.create_socks_reply_packet(const.REPLY_GENERAL_FAILURE)
                )
            except:
                pass
            return None

    def _handle_udp_associate(self, client_socket: socket.socket, dest_addr, dest_port):
        """
        Handle UDP ASSOCIATE command.

        Args:
            client_socket: Client control socket
            dest_addr: Destination address (client's address usually)
            dest_port: Destination port (client's port usually)

        Returns:
            tuple: (bool success, UDP socket if created)
        """
        try:
            # Create UDP socket
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_socket.bind((self.host, 0))  # Bind to any available port

            # Get the bound address/port
            bind_addr, bind_port = utils.extract_address_port(udp_socket)

            # Send success response with the UDP server address/port
            client_socket.sendall(
                utils.create_socks_reply_packet(
                    const.REPLY_SUCCESS, bind_addr, bind_port
                )
            )

            # Start UDP relay thread
            udp_thread = threading.Thread(
                target=self._handle_udp_relay,
                args=(udp_socket, dest_addr, dest_port, client_socket),
            )
            udp_thread.daemon = True
            udp_thread.start()
            self.threads.append(udp_thread)

            return True, udp_socket
        except Exception as e:
            logger.error(f"UDP ASSOCIATE error: {e}")
            client_socket.sendall(
                utils.create_socks_reply_packet(const.REPLY_GENERAL_FAILURE)
            )
            return False, None

    def _handle_udp_relay(
        self,
        udp_socket: socket.socket,
        client_addr,
        client_port,
        control_socket: socket.socket,
    ):
        """
        Handle UDP relay between client and destinations.

        Args:
            udp_socket: UDP socket for relaying data
            client_addr: Client address
            client_port: Client port
            control_socket: TCP control connection
        """
        client_socket_fd = control_socket.fileno()
        remote_sockets = {}  # {(dest_addr, dest_port): socket}

        while self.running:
            try:
                # Check if control connection is still alive
                readable, _, _ = select.select([control_socket], [], [], 0.1)
                if control_socket in readable:
                    data = control_socket.recv(1)
                    if not data:  # Control connection closed
                        break

                # Check for UDP data
                readable, _, _ = select.select([udp_socket], [], [], 0.1)
                if not readable:
                    continue

                # Receive UDP data
                data, addr = udp_socket.recvfrom(const.UDP_DEFAULT_BUFFER_SIZE)

                if not data:
                    continue

                # Parse SOCKS5 UDP header
                if len(data) < 10:  # Minimum header size
                    continue

                frag, atyp = struct.unpack("!BB", data[:2])
                if frag != const.UDP_FRAG_NO:  # We don't support fragmentation
                    continue

                # Parse destination address and port from header
                header_size = 0
                dest_addr = None

                if atyp == const.ATYP_IPV4:
                    header_size = 10
                    dest_addr = socket.inet_ntoa(data[4:8])
                    dest_port = struct.unpack("!H", data[8:10])[0]
                elif atyp == const.ATYP_DOMAIN:
                    domain_len = data[2]
                    header_size = 7 + domain_len
                    dest_addr = data[3 : 3 + domain_len].decode()
                    dest_port = struct.unpack(
                        "!H", data[3 + domain_len : 5 + domain_len]
                    )[0]
                elif atyp == const.ATYP_IPV6:
                    header_size = 22
                    dest_addr = socket.inet_ntop(socket.AF_INET6, data[4:20])
                    dest_port = struct.unpack("!H", data[20:22])[0]
                else:
                    continue

                # Get payload
                payload = data[header_size:]

                # Get or create remote socket
                key = (dest_addr, dest_port)
                if key not in remote_sockets:
                    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    remote_sockets[key] = remote_socket
                else:
                    remote_socket = remote_sockets[key]

                # Send payload to destination
                remote_socket.sendto(payload, key)

                # Check for response from destination
                readable, _, _ = select.select([remote_socket], [], [], 0.1)
                if remote_socket in readable:
                    response, remote_addr = remote_socket.recvfrom(
                        const.UDP_DEFAULT_BUFFER_SIZE
                    )

                    # Create SOCKS5 UDP header for response
                    try:
                        # Try IPv4
                        socket.inet_aton(remote_addr[0])
                        header = struct.pack(
                            "!BBB", const.UDP_FRAG_NO, const.ATYP_IPV4, 0
                        )
                        header += socket.inet_aton(remote_addr[0])
                        header += struct.pack("!H", remote_addr[1])
                    except socket.error:
                        # Handle as domain
                        domain = remote_addr[0].encode()
                        header = struct.pack(
                            "!BBB", const.UDP_FRAG_NO, const.ATYP_DOMAIN, len(domain)
                        )
                        header += domain
                        header += struct.pack("!H", remote_addr[1])

                    # Send response to client
                    udp_socket.sendto(header + response, (client_addr, client_port))

            except Exception as e:
                logger.error(f"UDP relay error: {e}")
                break

        # Clean up UDP sockets
        utils.close_socket(udp_socket)
        for sock in remote_sockets.values():
            utils.close_socket(sock)

    def _connect_to_destination(
        self, client_socket: socket.socket, dest_addr: str, dest_port: int
    ):
        raise NotImplementedError()

    def _proxy_data(self, client_socket: socket.socket, remote_socket: socket.socket):
        """
        Proxy data between client and remote sockets.

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
                        # Determine the destination socket
                        dest_socket = (
                            remote_socket if s is client_socket else client_socket
                        )

                        # Use try-except to handle EWOULDBLOCK (10035) errors
                        try:
                            dest_socket.sendall(data)
                        except socket.error as e:
                            err = e.args[0]
                            # Handle would-block error
                            if err == 10035:  # WSAEWOULDBLOCK
                                # This is normal for non-blocking sockets
                                # Just continue and try again on the next loop iteration
                                continue
                            else:
                                # For other socket errors, raise the exception
                                raise

                    except ConnectionError:
                        return
            except (select.error, socket.error) as e:
                logger.error(f"Socket error in proxy_data: {e}")
                break
            except Exception as e:
                logger.error(f"Error in proxy_data: {e}")
                break
