from io import BytesIO
import logging
import select
import socket
import threading
from typing import List
from src.core import *
from src.interceptors import *
from src.utils import *

log = logging.getLogger(__name__)


class RemoteServer(BaseProxy):
    """Server that accepts connections from client proxies"""

    def __init__(
        self,
        host: str,
        port: int,
        interceptors: List[BaseInterceptor] = None,
    ):
        super().__init__(interceptors)
        self.host = host
        self.port = port

    def start(self):
        """Start the server"""
        self.running = True
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            sock.bind((self.host, self.port))
            sock.listen(5)
            log.info(f"Server started on {self.host}:{self.port}")

            while self.running:
                try:
                    sock.settimeout(1.0)
                    try:
                        client, addr = sock.accept()
                        log.info(f"New connection from {addr[0]}:{addr[1]}")
                        thread = threading.Thread(
                            target=self._handle_client,
                            args=(client, addr),
                            daemon=True,
                        )
                        thread.start()
                    except socket.timeout:
                        continue
                    except Exception as e:
                        if self.running:
                            log.error(f"Accept error: {e}")
                except KeyboardInterrupt:
                    break

        except Exception as e:
            log.error(f"Server error: {e}")
        finally:
            self.running = False
            sock.close()
            for client in self.clients.copy():
                close_socket(client)
            log.debug("Remote server shutdown complete")

    def stop(self):
        """Stop the remote server"""
        log.info("Stopping remote server...")
        self.running = False

    def _handle_client(self, client: socket.socket, addr: Tuple):
        """Handle client proxy connection"""
        self.clients.add(client)
        dest_sock = None

        try:
            # Receive initial data
            data = client.recv(DEFAULT_BUFFER_SIZE)
            if not data:
                log.debug(f"No data received from client proxy at {addr[0]}:{addr[1]}")
                return

            # Create initial context
            ctx = ProtocolContext(
                client=client,
                req_data=data,
                stage="init",
            )

            # Process through interceptor chain
            chain = InterceptorChain(self.interceptors)
            result = chain.proceed(ctx)

            if result.drop:
                log.debug(f"Connection drop requested for {addr[0]}:{addr[1]}")
                return

            # Use the processed request data if available
            proc_data = result.proc_req or data

            # Extract destination address and port from the processed data
            try:
                data_io = BytesIO(proc_data)
                addr_type = data_io.read(1)[0]

                if addr_type == ATYP_IPV4:
                    addr_data = data_io.read(4)
                    dest_addr = socket.inet_ntoa(addr_data)
                    port_data = data_io.read(2)
                    dest_port = struct.unpack("!H", port_data)[0]
                elif addr_type == ATYP_DOMAIN:
                    domain_len = data_io.read(1)[0]
                    addr_data = data_io.read(domain_len)
                    dest_addr = addr_data.decode("utf-8")
                    port_data = data_io.read(2)
                    dest_port = struct.unpack("!H", port_data)[0]
                elif addr_type == ATYP_IPV6:
                    addr_data = data_io.read(16)
                    dest_addr = socket.inet_ntop(socket.AF_INET6, addr_data)
                    port_data = data_io.read(2)
                    dest_port = struct.unpack("!H", port_data)[0]
                else:
                    log.debug(f"Unsupported address type: {addr_type}")
                    client.sendall(b"\x01")  # Error code
                    return
            except Exception as e:
                log.error(f"Address parse error: {e}")
                client.sendall(b"\x01")  # Error code
                return

            log.info(f"Connecting to {dest_addr}:{dest_port}")

            # Connect to destination
            try:
                dest_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                dest_sock.settimeout(10)
                dest_sock.connect((dest_addr, dest_port))

                # Send success response to client proxy
                client.sendall(b"\x00")  # Success code

                # Start proxying data
                self._proxy_data(client, dest_sock, addr)

            except Exception as e:
                log.error(f"Error on destination {dest_addr}:{dest_port}: {e}")
                client.sendall(b"\x01")  # Error code
                return

        except Exception as e:
            log.error(f"Client proxy error ({addr[0]}:{addr[1]}): {e}")
        finally:
            if client in self.clients:
                self.clients.remove(client)
            close_socket(client)
            if dest_sock:
                close_socket(dest_sock)
            log.debug(f"Connection from client proxy at {addr[0]}:{addr[1]} closed")
