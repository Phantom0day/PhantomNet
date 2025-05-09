from io import BytesIO
import logging
import socket
import select
import struct
import threading
from typing import Dict, Optional, List
from src.core import *
from src.interceptors import *
from src.utils import *
from src.transport.udp import UdpRelayClient


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
        self.udp_relays: Dict[socket.socket, UdpRelayClient] = (
            {}
        )  # Maps TCP socket to UDP relay

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

            for relay in self.udp_relays.values():
                relay.stop()
            for client in self.clients.copy():
                close_socket(client)

    def stop(self):
        """Stop the local proxy server"""
        log.info("Stopping local proxy...")
        self.running = False

        # Stop all UDP relays
        for relay in self.udp_relays.values():
            relay.stop()

    def _handle_client(self, client: socket.socket, addr):
        """Handle a client connection"""
        self.clients.add(client)
        remote = None
        udp_relay = None

        try:
            # Handle SOCKS5 handshake
            if not self._handle_socks5_handshake(client):
                log.error(f"SOCKS5 handshake failed for {addr[0]}:{addr[1]}")
                return

            # Handle connection request
            cmd_type, dest_addr, dest_port = self._handle_socks5_request(client)
            if cmd_type is None or not dest_addr or not dest_port:
                log.error(f"SOCKS5 connect failed for {addr[0]}:{addr[1]}")
                return

            # Handle based on command type
            if cmd_type == CMD_CONNECT:
                # TCP CONNECT
                log.debug(f"TCP CONNECT to {dest_addr}:{dest_port}")
                remote = self._handle_tcp_connect(client, dest_addr, dest_port, addr)
                if not remote:
                    return

                # Start proxying data
                self._proxy_data(client, remote)

            elif cmd_type == CMD_UDP_ASSOCIATE:
                # UDP ASSOCIATE
                log.debug(f"UDP ASSOCIATE request from {addr[0]}:{addr[1]}")
                self._handle_udp_associate(client, addr)

            else:
                # Unsupported command
                log.error(f"Unsupported SOCKS5 command: {cmd_type}")
                response = create_socks_reply(REPLY_COMMAND_NOT_SUPPORTED)
                client.sendall(response)
                return

        except Exception as e:
            log.error(f"Client error {addr[0]}:{addr[1]}: {e}")
        finally:
            if client in self.clients:
                self.clients.remove(client)

            # Remove TCP->UDP mapping
            if client in self.udp_relays:
                udp_relay = self.udp_relays.pop(client)
                udp_relay.stop()

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

    def _handle_socks5_request(self, client: socket.socket):
        """Handle SOCKS5 connect request"""
        try:
            data = client.recv(DEFAULT_BUFFER_SIZE)
            if not data or len(data) < 4:
                log.debug("Invalid SOCKS5 connect request")
                return None, None, None

            ver, cmd, _, addr_type = struct.unpack("!BBBB", data[:4])

            if ver != SOCKS_VERSION:
                log.debug(f"Unsupported SOCKS version: {ver}")
                return None, None, None

            if cmd not in (CMD_CONNECT, CMD_UDP_ASSOCIATE):
                log.debug(f"Unsupported command: {cmd}")
                response = create_socks_reply(REPLY_COMMAND_NOT_SUPPORTED)
                client.sendall(response)
                return None, None, None

            req_data = BytesIO(data[4:])
            dest_addr, dest_port = parse_address(req_data, addr_type)

            if not dest_addr or not dest_port:
                log.debug("Failed to parse destination address")
                response = create_socks_reply(REPLY_ADDRESS_TYPE_NOT_SUPPORTED)
                client.sendall(response)
                return None, None, None

            return cmd, dest_addr, dest_port

        except Exception as e:
            log.error(f"Connect error: {e}")
            response = create_socks_reply(REPLY_GENERAL_FAILURE)
            try:
                client.sendall(response)
            except:
                pass
            return None, None, None

    def _handle_tcp_connect(self, client, dest_addr, dest_port, addr):
        """Handle TCP CONNECT command"""
        try:
            # Connect to the remote server
            remote = self._connect_to_server(dest_addr, dest_port)
            if not remote:
                log.error(f"Server connection failed for {addr[0]}:{addr[1]}")
                response = create_socks_reply(REPLY_HOST_UNREACHABLE)
                client.sendall(response)
                return None

            # Send success response to client
            response = create_socks_reply(REPLY_SUCCESS, "0.0.0.0", 0)
            client.sendall(response)

            return remote
        except Exception as e:
            log.error(f"TCP CONNECT error: {e}")
            return None

    def _handle_udp_associate(self, client, addr):
        """Handle UDP ASSOCIATE command"""
        try:
            # Create UDP relay
            udp_relay = UdpRelayClient(
                tcp_socket=None, client_addr=addr[0], client_port=None
            )

            # Set up the UDP socket
            if not udp_relay.setup():
                log.error("Failed to set up UDP relay")
                response = create_socks_reply(REPLY_GENERAL_FAILURE)
                client.sendall(response)
                return False

            # Connect to the remote server for UDP data tunnel
            remote = self._connect_to_server("0.0.0.0", 0, is_udp=True)
            if not remote:
                log.error(f"Server connection failed for UDP relay")
                response = create_socks_reply(REPLY_HOST_UNREACHABLE)
                client.sendall(response)
                return False

            # Set the TCP socket in UDP relay
            udp_relay.tcp_socket = remote

            # Send success response to client with the UDP socket address
            local_addr = udp_relay.local_addr
            local_port = udp_relay.local_port

            log.info(f"UDP relay ready on {local_addr}:{local_port}")

            response = create_socks_reply(REPLY_SUCCESS, local_addr, local_port)
            client.sendall(response)

            # Store the UDP relay in the map
            self.udp_relays[client] = udp_relay

            # Start the UDP relay
            udp_relay.start()

            # Keep the TCP connection open until the client closes it
            while self.running:
                try:
                    data = client.recv(DEFAULT_BUFFER_SIZE)
                    if not data:
                        log.info(f"Client closed TCP control channel for UDP relay")
                        break
                except Exception as e:
                    log.error(f"Error reading from TCP control channel: {e}")
                    break

            return True
        except Exception as e:
            log.error(f"UDP ASSOCIATE error: {e}")
            response = create_socks_reply(REPLY_GENERAL_FAILURE)
            try:
                client.sendall(response)
            except:
                pass
            return False

    def _connect_to_server(self, dest_addr: str, dest_port: int, is_udp: bool = False):
        """Connect to the remote server"""
        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(10)  # 10 second timeout
            remote.connect((self.server_host, self.server_port))

            # Create context with connection info
            ctx = ProtocolContext(
                dest_addr=dest_addr,
                dest_port=dest_port,
                stage="init",
                operation=Operation.PACK,
            )

            # Add UDP flag to metadata if this is for UDP relay
            if is_udp:
                ctx.meta["is_udp"] = True

            # Prepare destination information
            addr_type = ATYP_DOMAIN if not is_udp else 0  # Special marker for UDP
            addr_bytes = dest_addr.encode("utf-8")
            port_bytes = struct.pack("!H", dest_port)

            if is_udp:
                # For UDP, use a special marker packet
                # Type 2 = UDP setup, length 0
                req_data = b"\x02" + struct.pack("!H", 0)
            else:
                # For TCP, send the normal destination info
                req_data = (
                    struct.pack("!BB", addr_type, len(addr_bytes))
                    + addr_bytes
                    + port_bytes
                )

            # Send processed data to server
            packAndSend(remote, self.chain, ctx, req_data)

            resp_ctx = ProtocolContext(
                stage="init",
                operation=Operation.UNPACK,
            )
            # Receive response from server
            frame = recv_frame(remote, self.chain, resp_ctx)
            if not frame:
                log.debug("No response from remote server")
                close_socket(remote)
                return None

            if resp_ctx.drop:
                log.debug("Connection drop requested by response interceptor")
                close_socket(remote)
                return None

            # Check if remote connection was successful
            proc_resp = frame
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
