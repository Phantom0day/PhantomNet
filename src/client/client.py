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


class LocalClientProxy(BaseProxy):
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
        super().__init__(interceptors)
        self.local_host = local_host
        self.local_port = local_port
        self.server_host = server_host
        self.server_port = server_port

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
