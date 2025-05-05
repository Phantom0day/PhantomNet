from io import BytesIO
import logging
import select
import socket
import threading
from typing import List
from src.core import *
from src.interceptors import *
from src.utils import *

logger = logging.getLogger(__name__)


class RemoteServer(BaseProxy):
    """
    Remote server that accepts connections from LocalClientProxy instances.
    Handles decoding the custom protocol and connecting to actual destinations.
    """

    def __init__(
        self, host: str, port: int, interceptors: List[BaseInterceptor] = None
    ):
        """
        Initialize the remote server.

        Args:
            host: Host address to bind to
            port: Port number to bind to
            interceptors: List of interceptors to use for processing
        """
        super().__init__(interceptors)
        self.host = host
        self.port = port

    def start(self):
        """Start the remote server"""
        self.running = True
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            logger.info(f"Remote server started on {self.host}:{self.port}")

            while self.running:
                try:
                    # Accept new connections with a timeout
                    server_socket.settimeout(1.0)
                    try:
                        client_sock, addr = server_socket.accept()
                        logger.info(
                            f"New connection from client proxy at {addr[0]}:{addr[1]}"
                        )
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
            logger.error(f"Remote server error: {e}")
        finally:
            self.running = False
            server_socket.close()
            # Close all client connections
            for client_sock in self.clients.copy():
                close_socket(client_sock)
            logger.info("Remote server shutdown complete")

    def stop(self):
        """Stop the remote server"""
        logger.info("Stopping remote server...")
        self.running = False

    def _handle_client(self, client_sock: socket.socket, addr):
        """Handle a connection from a client proxy"""
        self.clients.add(client_sock)
        dest_sock = None

        try:
            # Receive initial data from client proxy
            data = client_sock.recv(DEFAULT_BUFFER_SIZE)
            if not data:
                logger.error(
                    f"No data received from client proxy at {addr[0]}:{addr[1]}"
                )
                return

            # Create initial context
            context = ProtocolContext(
                client_socket=client_sock, request_data=data, protocol_stage="init"
            )

            # Process through interceptor chain
            chain = InterceptorChain(self.interceptor_wrappers)
            result_ctx = chain.proceed(context)

            if result_ctx.should_drop:
                logger.error(f"Connection drop requested for {addr[0]}:{addr[1]}")
                return

            # Use the processed request data if available
            processed_data = result_ctx.processed_request or data

            # Extract destination address and port from the processed data
            try:
                data_io = BytesIO(processed_data)
                addr_type = data_io.read(1)[0]

                if addr_type == ATYP_IPV4:
                    # IPv4 address (4 bytes) + port (2 bytes)
                    addr_data = data_io.read(4)
                    dest_addr = socket.inet_ntoa(addr_data)
                    port_data = data_io.read(2)
                    dest_port = struct.unpack("!H", port_data)[0]
                elif addr_type == ATYP_DOMAIN:
                    # Domain length (1 byte) + domain + port (2 bytes)
                    domain_len = data_io.read(1)[0]
                    addr_data = data_io.read(domain_len)
                    dest_addr = addr_data.decode("utf-8")
                    port_data = data_io.read(2)
                    dest_port = struct.unpack("!H", port_data)[0]
                elif addr_type == ATYP_IPV6:
                    # IPv6 address (16 bytes) + port (2 bytes)
                    addr_data = data_io.read(16)
                    dest_addr = socket.inet_ntop(socket.AF_INET6, addr_data)
                    port_data = data_io.read(2)
                    dest_port = struct.unpack("!H", port_data)[0]
                else:
                    logger.error(f"Unsupported address type: {addr_type}")
                    client_sock.sendall(b"\x01")  # Error code
                    return
            except Exception as e:
                logger.error(f"Error parsing destination address: {e}")
                client_sock.sendall(b"\x01")  # Error code
                return

            logger.info(f"Connecting to destination: {dest_addr}:{dest_port}")

            # Connect to destination
            try:
                dest_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                dest_sock.settimeout(10)  # 10 second timeout
                dest_sock.connect((dest_addr, dest_port))

                # Send success response to client proxy
                client_sock.sendall(b"\x00")  # Success code

                # Start proxying data
                self._proxy_data(client_sock, dest_sock, addr)

            except Exception as e:
                logger.error(
                    f"Error connecting to destination {dest_addr}:{dest_port}: {e}"
                )
                client_sock.sendall(b"\x01")  # Error code
                return

        except Exception as e:
            logger.error(f"Error handling client proxy {addr[0]}:{addr[1]}: {e}")
        finally:
            # Clean up
            if client_sock in self.clients:
                self.clients.remove(client_sock)
            close_socket(client_sock)
            if dest_sock:
                close_socket(dest_sock)
            logger.info(f"Connection from client proxy at {addr[0]}:{addr[1]} closed")
