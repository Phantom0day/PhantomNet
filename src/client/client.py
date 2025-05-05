from io import BytesIO
import logging
import socket
import select
import struct
import threading
from typing import Optional, List
from src.core import *
from src.interceptors import *
from src.utils import *

log = logging.getLogger(__name__)


class LocalClientProxy(BaseProxy):
    """SOCKS5 proxy that runs on the client side"""

    def __init__(
        self,
        local_host: str,
        local_port: int,
        server_host: str,
        server_port: int,
        interceptors: List[BaseInterceptor] = None,
    ):
        super().__init__(interceptors)
        self.local_host = local_host
        self.local_port = local_port
        self.server_host = server_host
        self.server_port = server_port

    def start(self):
        """Start the local proxy server"""
        self.running = True
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            sock.bind((self.local_host, self.local_port))
            sock.listen(5)
            log.info(f"Local proxy started on {self.local_host}:{self.local_port}")
            log.info(f"Forwarding to {self.server_host}:{self.server_port}")

            while self.running:
                try:
                    sock.settimeout(1.0)
                    try:
                        client, addr = sock.accept()
                        log.info(f"New connection from {addr[0]}:{addr[1]}")
                        thread = threading.Thread(
                            target=self._handle_client,
                            args=(client, addr),
                        )
                        thread.daemon = True
                        thread.start()
                    except socket.timeout:
                        continue
                    except Exception as e:
                        if self.running:
                            log.error(f"Accept error: {e}")
                except KeyboardInterrupt:
                    break

        except Exception as e:
            log.error(f"Local proxy error: {e}")
        finally:
            self.running = False
            sock.close()
            for client in self.clients.copy():
                close_socket(client)

    def stop(self):
        """Stop the local proxy server"""
        log.info("Stopping local proxy...")
        self.running = False

    def _handle_client(self, client: socket.socket, addr):
        """Handle a client connection"""
        self.clients.add(client)
        remote = None

        try:
            # Handle SOCKS5 handshake
            if not self._handle_socks5_handshake(client):
                log.error(f"SOCKS5 handshake failed for {addr[0]}:{addr[1]}")
                return

            # Handle connection request
            dest_addr, dest_port = self._handle_socks5_connect(client)
            if not dest_addr or not dest_port:
                log.error(f"SOCKS5 connect failed for {addr[0]}:{addr[1]}")
                return

            log.info(f"Connecting to {dest_addr}:{dest_port} via server")

            # Connect to the remote server
            remote = self._connect_to_server(dest_addr, dest_port)
            if not remote:
                log.error(f"Server connection failed for {addr[0]}:{addr[1]}")
                response = create_socks_reply(REPLY_HOST_UNREACHABLE)
                client.sendall(response)
                return

            # Send success response to client
            response = create_socks_reply(REPLY_SUCCESS, "0.0.0.0", 0)
            client.sendall(response)

            # Start proxying data
            self._proxy_data(client, remote)

        except Exception as e:
            log.error(f"Client error {addr[0]}:{addr[1]}: {e}")
        finally:
            if client in self.clients:
                self.clients.remove(client)
            close_socket(client)
            if remote:
                close_socket(remote)

    def _handle_socks5_handshake(self, client: socket.socket) -> bool:
        """Handle the SOCKS5 handshake"""
        try:
            data = client.recv(DEFAULT_BUFFER_SIZE)
            if not data or len(data) < 2:
                log.debug("Invalid SOCKS5 handshake data")
                return False

            ver, nmethods = data[0], data[1]
            if ver != SOCKS_VERSION:
                log.debug(f"Unsupported SOCKS version: {ver}")
                return False

            methods = data[2 : 2 + nmethods]

            if AUTH_NO_AUTH not in methods:
                log.debug("No supported authentication methods")
                response = struct.pack("!BB", SOCKS_VERSION, AUTH_NO_ACCEPTABLE_METHODS)
                client.sendall(response)
                return False

            response = struct.pack("!BB", SOCKS_VERSION, AUTH_NO_AUTH)
            client.sendall(response)
            return True

        except Exception as e:
            log.error(f"Handshake error: {e}")
            return False

    def _handle_socks5_connect(self, client: socket.socket):
        """Handle SOCKS5 connect request"""
        try:
            data = client.recv(DEFAULT_BUFFER_SIZE)
            if not data or len(data) < 4:
                log.debug("Invalid SOCKS5 connect request")
                return None, None

            ver, cmd, _, addr_type = struct.unpack("!BBBB", data[:4])

            if ver != SOCKS_VERSION:
                log.debug(f"Unsupported SOCKS version: {ver}")
                return None, None

            if cmd != CMD_CONNECT:
                log.debug(f"Unsupported command: {cmd}")
                response = create_socks_reply(REPLY_COMMAND_NOT_SUPPORTED)
                client.sendall(response)
                return None, None

            req_data = BytesIO(data[4:])
            dest_addr, dest_port = parse_address(req_data, addr_type)

            if not dest_addr or not dest_port:
                log.debug("Failed to parse destination address")
                response = create_socks_reply(REPLY_ADDRESS_TYPE_NOT_SUPPORTED)
                client.sendall(response)
                return None, None

            return dest_addr, dest_port

        except Exception as e:
            log.error(f"Connect error: {e}")
            response = create_socks_reply(REPLY_GENERAL_FAILURE)
            try:
                client.sendall(response)
            except:
                pass
            return None, None

    def _connect_to_server(self, dest_addr: str, dest_port: int):
        """Connect to the remote server"""
        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(10)  # 10 second timeout
            remote.connect((self.server_host, self.server_port))

            # Create context with connection info
            ctx = ProtocolContext(
                client=remote,
                dest_addr=dest_addr,
                dest_port=dest_port,
                stage="init",
            )

            # Prepare destination information
            addr_type = ATYP_DOMAIN
            addr_bytes = dest_addr.encode("utf-8")
            port_bytes = struct.pack("!H", dest_port)
            initial_data = (
                struct.pack("!BB", addr_type, len(addr_bytes)) + addr_bytes + port_bytes
            )

            # Store request data
            ctx.req_data = initial_data

            # Process through interceptor chain
            chain = InterceptorChain(self.interceptors)
            result = chain.proceed(ctx)

            if result.drop:
                log.debug("Remote connection drop requested by interceptor")
                close_socket(remote)
                return None

            # Send processed data to server
            if result.proc_req:
                remote.sendall(result.proc_req)
            else:
                remote.sendall(initial_data)

            # Receive response from server
            response = remote.recv(DEFAULT_BUFFER_SIZE)
            if not response:
                log.debug("No response from remote server")
                close_socket(remote)
                return None

            # Process response
            resp_ctx = ProtocolContext(
                client=remote,
                resp_data=response,
                stage="init",
            )

            chain = InterceptorChain(self.interceptors)
            resp_result = chain.proceed(resp_ctx)

            if resp_result.drop:
                log.debug("Connection drop requested by response interceptor")
                close_socket(remote)
                return None

            # Check if remote connection was successful
            proc_resp = resp_result.proc_resp or response
            if proc_resp == b"\x00":  # Success code
                return remote
            else:
                log.debug(f"Remote server connection failed: {proc_resp.hex()}")
                close_socket(remote)
                return None

        except Exception as e:
            log.error(f"Server connection error: {e}")
            if "remote" in locals() and remote:
                close_socket(remote)
            return None
