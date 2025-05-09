from io import BytesIO
import logging
import select
import socket
import threading
from typing import Dict, List
from src.core import *
from src.interceptors import *
from src.utils import *
from src.transport.udp import UdpRelayServer


class RemoteServer(BaseProxy):
    """Server that accepts connections from client proxies"""

    def __init__(
        self,
        host: str,
        port: int,
        interceptors: List[BaseInterceptor] = None,
    ):
        super().__init__(interceptors, True)
        self.host = host
        self.port = port
        # Maps TCP socket to UDP relay
        self.udp_relays: Dict[socket.socket, UdpRelayServer] = {}

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

            for relay in self.udp_relays.values():
                relay.stop()
            for client in self.clients.copy():
                close_socket(client)

            log.debug("Remote server shutdown complete")

    def stop(self):
        """Stop the remote server"""
        log.info("Stopping remote server...")
        self.running = False

        # Stop all UDP relays
        for relay in self.udp_relays.values():
            relay.stop()

    def _handle_client(self, client: socket.socket, addr: Tuple):
        """Handle client proxy connection"""
        self.clients.add(client)
        dest_sock = None
        udp_relay = None

        try:
            # Create initial context
            ctx = ProtocolContext(
                stage="init",
                operation=Operation.UNPACK,
            )
            # Receive initial data
            frame = recv_frame(client, self.chain, ctx)
            if not frame:
                log.debug(f"No data received from client proxy at {addr[0]}:{addr[1]}")
                return

            # Check for UDP relay setup packet
            if len(frame) >= 3 and frame[0] == 0x02:  # Type 2 = UDP setup
                # This is a UDP relay setup request
                log.info(f"UDP relay setup request from {addr[0]}:{addr[1]}")
                self._setup_udp_relay(client, ctx, addr)
                return

            if ctx.drop:
                log.debug(f"Connection drop requested for {addr[0]}:{addr[1]}")
                return

            # Extract destination address and port from the processed data
            try:
                data_io = BytesIO(frame)
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
                    packAndSend(client, self.chain, ctx, b"\x01")
                    return
            except Exception as e:
                log.error(f"Address parse error: {e}")
                packAndSend(client, self.chain, ctx, b"\x01")
                return

            log.info(f"Connecting to {dest_addr}:{dest_port}")

            # Connect to destination
            try:
                dest_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                dest_sock.settimeout(10)
                dest_sock.connect((dest_addr, dest_port))

                # Send success response to client proxy
                packAndSend(client, self.chain, ctx, b"\x00")

                # Start proxying data
                self._proxy_data(dest_sock, client, addr)

            except Exception as e:
                log.error(f"Error on destination {dest_addr}:{dest_port}: {e}")
                packAndSend(client, self.chain, ctx, b"\x01")
                return

        except Exception as e:
            log.error(f"Client proxy error ({addr[0]}:{addr[1]}): {e}")
        finally:
            if client in self.clients:
                self.clients.remove(client)
            if client in self.udp_relays:
                udp_relay = self.udp_relays.pop(client)
                udp_relay.stop()

            close_socket(client)
            if dest_sock:
                close_socket(dest_sock)
            log.debug(f"Connection from client proxy at {addr[0]}:{addr[1]} closed")

    def _setup_udp_relay(self, client, ctx, addr):
        """Set up UDP relay for client"""
        try:
            # Create and start UDP relay server
            udp_relay = UdpRelayServer(client)

            # Store the relay
            self.udp_relays[client] = udp_relay

            # Send success response
            packAndSend(client, self.chain, ctx, b"\x00")

            # Start the relay
            udp_relay.start()

            # The UDP relay thread will run until the TCP connection is closed
            # We can return now and the client socket will be cleaned up when
            # the connection is closed

            log.info(f"UDP relay set up for {addr[0]}:{addr[1]}")
        except Exception as e:
            log.error(f"Failed to set up UDP relay: {e}")
            try:
                packAndSend(client, self.chain, ctx, b"\x01")
            except:
                pass
