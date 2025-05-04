import logging
import socket
import select
import struct
import threading
from typing import Optional, List
from src.core import *
from src.interceptors import *
from src.utils import *

logger = logging.getLogger(__name__)


class LocalClientProxy:
    """
    Local SOCKS5 proxy that runs on the client side.
    Accepts SOCKS5 connections from local applications and forwards them through
    the secure tunnel to the remote server.
    """

    def __init__(
        self, local_host, local_port, server_host, server_port, interceptors=None
    ):
        """
        Initialize the local client proxy.

        Args:
            local_host: Local host to bind to
            local_port: Local port to bind to
            server_host: Remote server host
            server_port: Remote server port
            interceptors: List of interceptors to use for the secure tunnel
        """
        self.local_host = local_host
        self.local_port = local_port
        self.server_host = server_host
        self.server_port = server_port
        self.interceptors = interceptors or []
        self.interceptor_wrappers = [
            lambda ctx, chain, i=i: i.intercept(ctx, chain) for i in self.interceptors
        ]
        self.running = False
        self.clients = set()  # Track active clients

    def start(self):
        """Start the local proxy server"""
        self.running = True
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server_socket.bind((self.local_host, self.local_port))
            server_socket.listen(5)
            logger.info(
                f"Local SOCKS5 proxy started on {self.local_host}:{self.local_port}"
            )
            logger.info(
                f"Forwarding to remote server at {self.server_host}:{self.server_port}"
            )

            while self.running:
                try:
                    # Accept new connections with a timeout
                    server_socket.settimeout(1.0)
                    try:
                        client_sock, addr = server_socket.accept()
                        logger.info(f"New local connection from {addr[0]}:{addr[1]}")
                        # Start a new thread to handle each client
                        client_thread = threading.Thread(
                            target=self._handle_client, args=(client_sock, addr)
                        )
                        client_thread.daemon = True
                        client_thread.start()
                    except socket.timeout:
                        continue
                    except Exception as e:
                        if self.running:
                            logger.error(f"Error accepting connection: {e}")
                except KeyboardInterrupt:
                    break

        except Exception as e:
            logger.error(f"Local proxy error: {e}")
        finally:
            self.running = False
            server_socket.close()
            # Close all client connections
            for client_sock in self.clients.copy():
                close_socket(client_sock)
            logger.info("Local proxy shutdown complete")

    def stop(self):
        """Stop the local proxy server"""
        logger.info("Stopping local proxy...")
        self.running = False

    def _handle_client(self, client_sock: socket.socket, addr):
        """Handle a client connection from a local application"""
        self.clients.add(client_sock)
        remote_sock = None

        try:
            # Process local client's SOCKS5 handshake
            if not self._handle_socks5_handshake(client_sock):
                logger.error(f"SOCKS5 handshake failed for {addr[0]}:{addr[1]}")
                return

            # Process local client's connection request
            dest_addr, dest_port = self._handle_socks5_connect(client_sock)
            if not dest_addr or not dest_port:
                logger.error(
                    f"SOCKS5 connection request failed for {addr[0]}:{addr[1]}"
                )
                return

            logger.info(f"Connecting to {dest_addr}:{dest_port} via remote server")

            # Connect to the remote server
            remote_sock = self._connect_to_remote_server(dest_addr, dest_port)
            if not remote_sock:
                logger.error(
                    f"Failed to connect to remote server for {addr[0]}:{addr[1]}"
                )
                # Send connection refused response to local client
                response = create_socks_reply(REPLY_HOST_UNREACHABLE)
                client_sock.sendall(response)
                return

            # Send successful connection response to local client
            bind_addr, bind_port = "0.0.0.0", 0  # Use placeholder values
            response = create_socks_reply(REPLY_SUCCESS, bind_addr, bind_port)
            client_sock.sendall(response)

            # Start proxying data
            self._proxy_data(client_sock, remote_sock)

        except Exception as e:
            logger.error(f"Error handling local client {addr[0]}:{addr[1]}: {e}")
        finally:
            # Clean up
            if client_sock in self.clients:
                self.clients.remove(client_sock)
            close_socket(client_sock)
            if remote_sock:
                close_socket(remote_sock)
            logger.info(f"Local connection from {addr[0]}:{addr[1]} closed")

    def _handle_socks5_handshake(self, client_sock: socket.socket) -> bool:
        """
        Handle the SOCKS5 handshake from a local client.

        Returns:
            bool: True if handshake successful, False otherwise
        """
        try:
            # Receive client greeting
            data = client_sock.recv(DEFAULT_BUFFER_SIZE)
            if not data or len(data) < 2:
                logger.error("Invalid SOCKS5 handshake data")
                return False

            version, nmethods = data[0], data[1]
            if version != SOCKS_VERSION:
                logger.error(f"Unsupported SOCKS version: {version}")
                return False

            # Extract authentication methods
            methods = data[2 : 2 + nmethods]

            # For now, only support no-auth
            if AUTH_NO_AUTH not in methods:
                logger.error("No supported authentication methods")
                # Send no acceptable methods response
                response = struct.pack("!BB", SOCKS_VERSION, AUTH_NO_ACCEPTABLE_METHODS)
                client_sock.sendall(response)
                return False

            # Send auth method choice (no auth)
            response = struct.pack("!BB", SOCKS_VERSION, AUTH_NO_AUTH)
            client_sock.sendall(response)
            return True

        except Exception as e:
            logger.error(f"Error in SOCKS5 handshake: {e}")
            return False

    def _handle_socks5_connect(self, client_sock: socket.socket):
        """
        Handle the SOCKS5 connect request from a local client.

        Returns:
            tuple: (dest_addr, dest_port) or (None, None) if failed
        """
        try:
            # Receive connect request
            data = client_sock.recv(DEFAULT_BUFFER_SIZE)
            if not data or len(data) < 4:
                logger.error("Invalid SOCKS5 connect request")
                return None, None

            version, cmd, _, address_type = struct.unpack("!BBBB", data[:4])

            if version != SOCKS_VERSION:
                logger.error(f"Unsupported SOCKS version: {version}")
                return None, None

            if cmd != CMD_CONNECT:
                logger.error(f"Unsupported command: {cmd}")
                response = create_socks_reply(REPLY_COMMAND_NOT_SUPPORTED)
                client_sock.sendall(response)
                return None, None

            # Parse destination address
            remaining_data = data[4:]
            from io import BytesIO

            request_data = BytesIO(remaining_data)
            dest_addr, dest_port = parse_address(request_data, address_type)

            if not dest_addr or not dest_port:
                logger.error("Failed to parse destination address")
                response = create_socks_reply(REPLY_ADDRESS_TYPE_NOT_SUPPORTED)
                client_sock.sendall(response)
                return None, None

            return dest_addr, dest_port

        except Exception as e:
            logger.error(f"Error handling SOCKS5 connect request: {e}")
            try:
                response = create_socks_reply(REPLY_GENERAL_FAILURE)
                client_sock.sendall(response)
            except:
                pass
            return None, None

    def _connect_to_remote_server(self, dest_addr, dest_port):
        """
        Connect to the remote server and establish a secure tunnel.

        Args:
            dest_addr: Destination address requested by local client
            dest_port: Destination port requested by local client

        Returns:
            socket.socket: Socket connected to remote server or None if connection fails
        """
        try:
            # Create socket and connect to the remote server
            remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_sock.settimeout(10)  # 10 second timeout
            remote_sock.connect((self.server_host, self.server_port))

            # Create initial context with connection information
            context = ProtocolContext(
                client_socket=remote_sock,
                dest_addr=dest_addr,
                dest_port=dest_port,
                protocol_stage="init",
            )

            # Prepare data to send to remote server
            # Format: [address_type(1) | address_len(1) | address(var) | port(2)]
            addr_type = 3  # Domain name type
            addr_bytes = dest_addr.encode("utf-8")
            port_bytes = struct.pack("!H", dest_port)
            initial_data = (
                struct.pack("!BB", addr_type, len(addr_bytes)) + addr_bytes + port_bytes
            )

            # Store request data in context
            context.request_data = initial_data

            # Process through interceptor chain
            chain = InterceptorChain(self.interceptor_wrappers)
            result_ctx = chain.proceed(context)

            if result_ctx.should_drop:
                logger.error("Remote connection drop requested by interceptor")
                close_socket(remote_sock)
                return None

            # Send processed data to remote server
            if result_ctx.processed_request:
                remote_sock.sendall(result_ctx.processed_request)
            else:
                remote_sock.sendall(initial_data)

            # Receive and process initial response from remote server
            response = remote_sock.recv(DEFAULT_BUFFER_SIZE)
            if not response:
                logger.error("No response from remote server")
                close_socket(remote_sock)
                return None

            # Process response through interceptor chain
            resp_context = ProtocolContext(
                client_socket=remote_sock, response_data=response, protocol_stage="init"
            )

            chain = InterceptorChain(self.interceptor_wrappers)
            resp_result = chain.proceed(resp_context)

            if resp_result.should_drop:
                logger.error("Connection drop requested by response interceptor")
                close_socket(remote_sock)
                return None

            # Check if remote connection was successful
            # The remote should send a simple acknowledgement
            processed_response = resp_result.processed_response or response
            if processed_response == b"\x00":  # Success code
                return remote_sock
            else:
                logger.error(
                    f"Remote server connection failed: {processed_response.hex()}"
                )
                close_socket(remote_sock)
                return None

        except Exception as e:
            logger.error(f"Error connecting to remote server: {e}")
            if "remote_sock" in locals() and remote_sock:
                close_socket(remote_sock)
            return None

    def _proxy_data(self, client_socket: socket.socket, remote_socket: socket.socket):
        """Proxy data between local client and remote server with interceptor processing"""
        client_socket.setblocking(False)
        remote_socket.setblocking(False)

        while self.running:
            try:
                # Wait until client or remote is available for read
                r, _, e = select.select(
                    [client_socket, remote_socket],
                    [],
                    [client_socket, remote_socket],
                    1.0,
                )

                if client_socket in e or remote_socket in e:
                    # Socket error
                    logger.debug("Socket error in proxy_data")
                    break

                for s in r:
                    try:
                        if s is client_socket:
                            # Client -> Remote
                            data = client_socket.recv(DEFAULT_BUFFER_SIZE)
                            if not data:
                                return

                            # Process through interceptor chain
                            context = ProtocolContext(
                                client_socket=client_socket,
                                remote_socket=remote_socket,
                                request_data=data,
                                protocol_stage="connected",
                            )

                            chain = InterceptorChain(self.interceptor_wrappers)
                            result = chain.proceed(context)

                            if result.should_drop:
                                return

                            # Send processed data to remote
                            if result.processed_request:
                                remote_socket.sendall(result.processed_request)
                            else:
                                remote_socket.sendall(data)

                        else:
                            # Remote -> Client
                            data = remote_socket.recv(DEFAULT_BUFFER_SIZE)
                            if not data:
                                return

                            # Process through interceptor chain
                            context = ProtocolContext(
                                client_socket=client_socket,
                                remote_socket=remote_socket,
                                response_data=data,
                                protocol_stage="connected",
                            )

                            chain = InterceptorChain(self.interceptor_wrappers)
                            result = chain.proceed(context)

                            if result.should_drop:
                                return

                            # Send processed data to client
                            if result.processed_response:
                                client_socket.sendall(result.processed_response)
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


class SecureSOCKS5Client:
    def __init__(self, server_host, server_port, interceptors=None):
        self.server_host = server_host
        self.server_port = server_port
        # Initialize with interceptors
        self.interceptors = interceptors or []

    def connect(self, dest_host, dest_port):
        """Connect to destination through secure SOCKS5 proxy"""
        sock = None
        try:
            # Create socket and connect to proxy server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)  # 10 second timeout
            sock.connect((self.server_host, self.server_port))

            # Create initial context
            context = ProtocolContext(
                client_socket=sock,
                dest_addr=dest_host,
                dest_port=dest_port,
                protocol_stage="init",
            )

            # Prepare SOCKS5 handshake
            greeting = struct.pack("!BBB", SOCKS_VERSION, 1, AUTH_NO_AUTH)
            context.request_data = greeting

            # Process through interceptor chain
            chain = InterceptorChain(
                [
                    lambda ctx, chain, i=i: i.intercept(ctx, chain)
                    for i in self.interceptors
                ]
            )

            # Process outbound request
            handshake_ctx = chain.proceed(context)

            if handshake_ctx.should_drop:
                logger.error("Handshake interceptor requested connection drop")
                return None

            # Send the possibly transformed handshake
            if handshake_ctx.processed_request:
                sock.sendall(handshake_ctx.processed_request)
            else:
                sock.sendall(greeting)

            # Receive handshake response
            response = sock.recv(2)
            if len(response) < 2:
                logger.error("Invalid handshake response")
                return None

            version, method = struct.unpack("!BB", response)
            if version != SOCKS_VERSION:
                logger.error(f"Invalid SOCKS version: {version}")
                return None

            # Create connection request
            connect_request = create_socks5_connect_request(dest_host, dest_port)

            # Create new context for connection request
            conn_context = ProtocolContext(
                client_socket=sock,
                dest_addr=dest_host,
                dest_port=dest_port,
                request_data=connect_request,
                protocol_stage="handshake_complete",
            )

            # Process connection request
            chain = InterceptorChain(
                [
                    lambda ctx, chain, i=i: i.intercept(ctx, chain)
                    for i in self.interceptors
                ]
            )

            conn_ctx = chain.proceed(conn_context)

            if conn_ctx.should_drop:
                logger.error("Connection interceptor requested connection drop")
                return None

            # Send connection request
            if conn_ctx.processed_request:
                sock.sendall(conn_ctx.processed_request)
            else:
                sock.sendall(connect_request)

            # Receive connection response
            response = sock.recv(10)  # Minimum size for IPv4 response
            if len(response) < 4:
                logger.error("Invalid connection response")
                return None

            version, status, _, atyp = struct.unpack("!BBBB", response[:4])

            if version != SOCKS_VERSION:
                logger.error(f"Invalid SOCKS version in response: {version}")
                return None

            if status != REPLY_SUCCESS:
                error_messages = {
                    REPLY_GENERAL_FAILURE: "General failure",
                    REPLY_CONNECTION_NOT_ALLOWED: "Connection not allowed",
                    REPLY_NETWORK_UNREACHABLE: "Network unreachable",
                    REPLY_HOST_UNREACHABLE: "Host unreachable",
                    REPLY_CONNECTION_REFUSED: "Connection refused",
                    REPLY_TTL_EXPIRED: "TTL expired",
                    REPLY_COMMAND_NOT_SUPPORTED: "Command not supported",
                    REPLY_ADDRESS_TYPE_NOT_SUPPORTED: "Address type not supported",
                }
                error_msg = error_messages.get(status, f"Unknown error: {status}")
                logger.error(f"Connection failed: {error_msg}")
                return None

            # Skip address and port in response based on address type
            if atyp == ATYP_IPV4:
                sock.recv(6)  # 4 bytes address + 2 bytes port
            elif atyp == ATYP_DOMAIN:
                domain_len = sock.recv(1)[0]
                sock.recv(domain_len + 2)  # domain + 2 bytes port
            elif atyp == ATYP_IPV6:
                sock.recv(18)  # 16 bytes address + 2 bytes port

            logger.info(f"Connected to {dest_host}:{dest_port} via secure SOCKS5 proxy")
            return sock

        except Exception as e:
            logger.error(f"Error connecting to {dest_host}:{dest_port}: {e}")
        finally:
            if sock:
                close_socket(sock)
            return None

    def send_receive(self, sock, data):
        """
        Send data through the socket and receive response with interceptor processing

        Args:
            sock: Connected socket
            data: Data to send

        Returns:
            bytes: Received data or None if error
        """
        try:
            # Create context for the data
            context = ProtocolContext(
                client_socket=sock, request_data=data, protocol_stage="connected"
            )

            # Process through interceptor chain
            chain = InterceptorChain(
                [
                    lambda ctx, chain, i=i: i.intercept(ctx, chain)
                    for i in self.interceptors
                ]
            )

            result_ctx = chain.proceed(context)

            if result_ctx.should_drop:
                logger.error("Interceptor requested connection drop")
                return None

            # Send processed data
            if result_ctx.processed_request:
                sock.sendall(result_ctx.processed_request)
            else:
                sock.sendall(data)

            # Receive response
            response = sock.recv(DEFAULT_BUFFER_SIZE)

            # Create context for response processing
            resp_context = ProtocolContext(
                client_socket=sock, response_data=response, protocol_stage="connected"
            )

            # Process response through interceptor chain
            chain = InterceptorChain(
                [
                    lambda ctx, chain, i=i: i.intercept(ctx, chain)
                    for i in self.interceptors
                ]
            )

            resp_ctx = chain.proceed(resp_context)

            if resp_ctx.should_drop:
                logger.error("Response interceptor requested connection drop")
                return None

            # Return processed response
            if resp_ctx.processed_response:
                return resp_ctx.processed_response
            else:
                return response

        except Exception as e:
            logger.error(f"Error in send_receive: {e}")
            return None
