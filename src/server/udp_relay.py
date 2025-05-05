import logging
import socket
import struct
import threading
import time
from io import BytesIO
from src.utils.constants import *
from src.utils.utils import *

log = logging.getLogger(__name__)


class UdpRelayServer(threading.Thread):
    """UDP relay for server-side, handles UDP forwarding through TCP tunnel"""

    def __init__(self, tcp_socket):
        """
        Initialize the UDP relay server.

        Args:
            tcp_socket: TCP control channel socket (from client)
        """
        super().__init__(daemon=True)
        self.tcp_socket = tcp_socket
        self.running = False
        self.dest_sockets = {}  # Maps (dest_addr, dest_port) -> UDP socket
        self.lock = threading.Lock()

    def run(self):
        """Run the UDP relay server"""
        self.running = True
        buffer = b""

        # Set timeout on TCP socket to avoid blocking forever
        self.tcp_socket.settimeout(1)

        while self.running:
            try:
                # Read data from TCP socket
                data = self.tcp_socket.recv(DEFAULT_BUFFER_SIZE)

                if not data:
                    log.info("TCP control channel closed")
                    self.running = False
                    break

                # Add to buffer
                buffer += data

                # Process complete messages from buffer
                while len(buffer) >= 3:  # Minimum: 1-byte type + 2-byte length
                    # Check message type
                    if buffer[0] != 0x03:  # Not a UDP packet
                        # Skip this byte and continue
                        buffer = buffer[1:]
                        continue

                    # Extract length
                    if len(buffer) < 3:
                        break

                    length = struct.unpack("!H", buffer[1:3])[0]

                    # Check if we have the complete message
                    if len(buffer) < 3 + length:
                        break

                    # Extract the UDP packet
                    udp_packet = buffer[3 : 3 + length]
                    buffer = buffer[3 + length :]

                    # Process the UDP packet
                    self._process_udp_packet(udp_packet)

            except socket.timeout:
                # Just a timeout, continue the loop
                continue
            except Exception as e:
                log.error(f"Error in UDP relay server: {e}")
                if not self.running:
                    break
                time.sleep(1)  # Avoid busy loop in case of persistent errors

        # Clean up UDP sockets
        with self.lock:
            for sock in self.dest_sockets.values():
                sock.close()
            self.dest_sockets.clear()

    def stop(self):
        """Stop the UDP relay server"""
        self.running = False
        # Clean up UDP sockets
        with self.lock:
            for sock in self.dest_sockets.values():
                sock.close()
            self.dest_sockets.clear()

    def _process_udp_packet(self, udp_packet):
        """Process UDP packet from the client"""
        try:
            # Minimum UDP packet: RSV(2) + FRAG(1) + ATYP(1) + ADDR(min 1) + PORT(2) = 7 bytes
            if len(udp_packet) < 7:
                log.warning(f"UDP packet too small: {len(udp_packet)} bytes")
                return

            # Parse header
            reserved = struct.unpack("!H", udp_packet[:2])[0]
            frag = udp_packet[2]
            addr_type = udp_packet[3]

            if reserved != 0:
                log.warning(f"Invalid UDP packet: reserved field != 0 ({reserved})")
                return

            if frag != 0:
                log.warning(f"Fragmented UDP packets not supported (frag={frag})")
                return

            # Parse address
            addr_obj = BytesIO(udp_packet[3:])
            dest_addr, dest_port = parse_address(addr_obj, addr_type)

            if not dest_addr or not dest_port:
                log.warning("Failed to parse destination address in UDP packet")
                return

            # Calculate header size
            header_size = 0
            if addr_type == ATYP_IPV4:
                header_size = 10  # 2(RSV) + 1(FRAG) + 1(ATYP) + 4(IPv4) + 2(PORT)
            elif addr_type == ATYP_DOMAIN:
                domain_len = udp_packet[4]
                header_size = 7 + domain_len  # 2+1+1+1+domain_len+2
            elif addr_type == ATYP_IPV6:
                header_size = 22  # 2+1+1+16+2
            else:
                log.warning(f"Unsupported address type: {addr_type}")
                return

            # Extract the payload
            payload = udp_packet[header_size:]
            log.debug(f"UDP packet to {dest_addr}:{dest_port}, size={len(payload)}")

            # Get or create UDP socket for this destination
            sock = self._get_udp_socket(dest_addr, dest_port)
            if not sock:
                log.error(f"Failed to create UDP socket for {dest_addr}:{dest_port}")
                return

            # Send payload to destination
            try:
                sock.sendto(payload, (dest_addr, dest_port))
                log.debug(f"Sent UDP packet to {dest_addr}:{dest_port}")
            except Exception as e:
                log.error(f"Failed to send UDP packet to {dest_addr}:{dest_port}: {e}")

        except Exception as e:
            log.error(f"Error processing UDP packet: {e}")

    def _get_udp_socket(self, dest_addr, dest_port):
        """Get or create a UDP socket for the destination"""
        key = (dest_addr, dest_port)

        with self.lock:
            # Check if we already have a socket for this destination
            if key in self.dest_sockets:
                return self.dest_sockets[key]

            # Create a new UDP socket
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

                # Start a receiver thread for this socket
                thread = threading.Thread(
                    target=self._handle_udp_responses,
                    args=(sock, dest_addr, dest_port),
                    daemon=True,
                )
                thread.start()

                # Store the socket
                self.dest_sockets[key] = sock
                return sock

            except Exception as e:
                log.error(f"Failed to create UDP socket: {e}")
                return None

    def _handle_udp_responses(self, sock, dest_addr, dest_port):
        """Handle responses from the UDP destination"""
        sock.settimeout(1)

        while self.running:
            try:
                # Receive data from the UDP socket
                data, addr = sock.recvfrom(DEFAULT_BUFFER_SIZE)
                if not data:
                    continue

                # Only accept responses from the expected destination
                if addr[0] != dest_addr or addr[1] != dest_port:
                    log.warning(
                        f"Unexpected UDP response from {addr[0]}:{addr[1]}, "
                        f"expected from {dest_addr}:{dest_port}"
                    )
                    continue

                # Create a UDP packet with SOCKS5 header
                # Format: [RSV(2)][FRAG(1)][ATYP(1)][DST.ADDR(var)][DST.PORT(2)][DATA]

                # Determine address type and format the address
                addr_type = get_address_type(addr[0])
                if addr_type == ATYP_IPV4:
                    addr_bytes = socket.inet_aton(addr[0])
                    addr_data = struct.pack("!B", addr_type) + addr_bytes
                elif addr_type == ATYP_IPV6:
                    addr_bytes = socket.inet_pton(socket.AF_INET6, addr[0])
                    addr_data = struct.pack("!B", addr_type) + addr_bytes
                else:  # Domain name
                    addr_bytes = addr[0].encode()
                    addr_data = (
                        struct.pack("!BB", addr_type, len(addr_bytes)) + addr_bytes
                    )

                # Add port
                port_bytes = struct.pack("!H", addr[1])

                # Create the UDP packet
                udp_packet = struct.pack("!HB", 0, 0) + addr_data + port_bytes + data

                # Prefix with length and send to the TCP channel
                length_prefix = struct.pack("!H", len(udp_packet))
                try:
                    self.tcp_socket.sendall(b"\x03" + length_prefix + udp_packet)
                    log.debug(
                        f"Sent UDP response from {addr[0]}:{addr[1]} back to client"
                    )
                except Exception as e:
                    log.error(f"Failed to send UDP response to client: {e}")
                    return

            except socket.timeout:
                # Just a timeout, continue the loop
                continue
            except Exception as e:
                log.error(f"Error handling UDP responses: {e}")
                if not self.running:
                    break
                time.sleep(1)  # Avoid busy loop

        # Socket will be closed by the main thread
