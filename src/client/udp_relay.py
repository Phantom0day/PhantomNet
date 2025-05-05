from io import BytesIO
import logging
import socket
import struct
import threading
import time
from src.utils.constants import *
from src.utils.utils import *

log = logging.getLogger(__name__)


class UdpRelay(threading.Thread):
    """UDP relay for client-side, handles UDP ASSOCIATE command"""

    def __init__(self, tcp_socket, client_addr, client_port):
        super().__init__(daemon=True)
        self.tcp_socket = tcp_socket
        self.client_addr, self.client_port = client_addr, client_port
        self.running = False
        self.local_addr = None
        self.local_port = None
        self.udp_socket = None
        self.addr_map = {}  # Maps (dest_addr, dest_port) -> (client_addr, client_port)

    def setup(self):
        """Set up the UDP socket"""
        try:
            # Create UDP socket
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.bind(("0.0.0.0", 0))  # Bind to any available port

            # Get the actual bound address and port
            self.local_addr, self.local_port = self.udp_socket.getsockname()
            log.info(f"UDP relay bound to {self.local_addr}:{self.local_port}")

            return True
        except Exception as e:
            log.error(f"Failed to set up UDP relay: {e}")
            return False

    def run(self):
        """Run the UDP relay"""
        if not self.udp_socket:
            if not self.setup():
                return

        self.running = True

        # Start TCP listener thread
        tcp_thread = threading.Thread(target=self._handle_tcp_channel, daemon=True)
        tcp_thread.start()

        # Main UDP receiver loop
        self._handle_udp_traffic()

    def stop(self):
        """Stop the UDP relay"""
        self.running = False
        if self.udp_socket:
            self.udp_socket.close()
            self.udp_socket = None

    def _handle_udp_traffic(self):
        """Handle incoming UDP traffic from local client"""
        self.udp_socket.settimeout(1)

        while self.running:
            try:
                # Receive data from UDP socket
                data, addr = self.udp_socket.recvfrom(DEFAULT_BUFFER_SIZE)
                client_addr, client_port = addr

                # Only accept packets from the expected client address
                if (self.client_addr and self.client_port) and (
                    client_addr != self.client_addr or client_port != self.client_port
                ):
                    log.warning(
                        f"Rejected UDP packet from : {client_addr}:{client_port}, "
                        f"expected: {self.client_addr}:{self.client_port}"
                    )
                    continue

                # Extract SOCKS5 UDP header (if present)
                # UDP headers are expected to be in this format:
                # +----+------+------+----------+----------+----------+
                # |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
                # +----+------+------+----------+----------+----------+
                # | 2  |  1   |  1   | Variable |    2     | Variable |
                # +----+------+------+----------+----------+----------+
                if len(data) < 4:  # Minimum header size
                    log.warning(f"UDP packet too small: {len(data)} bytes")
                    continue

                # Parse header
                header = data[:4]
                reserved, frag, addr_type = struct.unpack("!HBB", header)

                if reserved != 0:
                    log.warning(f"Invalid UDP packet: reserved field != 0 ({reserved})")
                    continue
                if frag != 0:
                    log.warning(f"Fragmented UDP packets not supported (frag={frag})")
                    continue

                # Parse address
                dest_addr = None
                dest_port = None
                header_size = 0

                # Use BytesIO for easier parsing
                datagram = BytesIO(data)
                datagram.read(3)  # Skip (RSV + FRAG)

                # Parse address
                addr_obj = BytesIO(data[3:])
                dest_addr, dest_port = parse_address(addr_obj, addr_type)

                if not dest_addr or not dest_port:
                    log.warning("Failed to parse destination address in UDP packet")
                    continue

                # Calculate header size
                if addr_type == ATYP_IPV4:
                    header_size = 10  # 2(RSV) + 1(FRAG) + 1(ATYP) + 4(IPv4) + 2(PORT)
                elif addr_type == ATYP_DOMAIN:
                    domain_len = data[4]
                    header_size = 7 + domain_len  # 2+1+1+1+domain_len+2
                elif addr_type == ATYP_IPV6:
                    header_size = 22  # 2+1+1+16+2
                else:
                    log.warning(f"Unsupported address type: {addr_type}")
                    continue

                # Extract the payload
                payload = data[header_size:]
                log.debug(f"UDP packet to {dest_addr}:{dest_port}, size={len(payload)}")

                # Store the mapping for replies
                self.addr_map[(dest_addr, dest_port)] = addr

                # Forward to the server over TCP channel:
                # First, prepare the UDP datagram with SOCKS5 header
                socks_udp_packet = data  # Alread has SOCKS5 UDP header

                # Add length prefix (2 bytes) and send to TCP channel
                length_prefix = struct.pack("!H", len(socks_udp_packet))
                try:
                    self.tcp_socket.sendall(
                        b"\x03" + length_prefix + socks_udp_packet
                    )  # \x03 = UDP data marker
                except Exception as e:
                    log.error(f"Failed to forward UDP packet to server: {e}")
                    break

            except socket.timeout:
                continue
            except Exception as e:
                log.error(f"Error in UDP relay: {e}")
                if not self.running:
                    break
                time.sleep(1)  # Avoid busy loop in case of persistent errors

    def _handle_tcp_channel(self):
        """Handle incoming TCP data that contains UDP replies"""
        self.tcp_socket.settimeout(1)

        buffer = b""

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
                    self._process_udp_reply(udp_packet)

            except socket.timeout:
                continue
            except Exception as e:
                log.error(f"Error in TCP channel handler: {e}")
                if not self.running:
                    break
                time.sleep(1)  # Avoid busy loop

    def _process_udp_reply(self, udp_packet):
        """Process UDP reply from the server"""
        try:
            # Minimum UDP reply: RSV(2)+FRAG(1)+ATYP(1)+ADDR(min 1)+PORT(2) = 7 bytes
            if len(udp_packet) < 7:
                log.warning(f"UDP reply too small: {len(udp_packet)} bytes")
                return

            # Parse header
            reserved = struct.unpack("!H", udp_packet[:2])[0]
            frag = udp_packet[2]
            addr_type = udp_packet[3]

            if reserved != 0:
                log.warning(f"Invalid UDP reply: reserved field != 0 ({reserved})")
                return

            if frag != 0:
                log.warning(f"Fragmented UDP replies not supported (frag={frag})")
                return

            # Parse address
            addr_obj = BytesIO(udp_packet[3:])
            src_addr, src_port = parse_address(addr_obj, addr_type)

            if not src_addr or not src_port:
                log.warning("Failed to parse source address in UDP reply")
                return

            # Calculate header size
            header_size = 0
            if addr_type == ATYP_IPV4:
                header_size = 10  # 2(RSV)+1(FRAG)+1(ATYP)+4(IPv4)+2(PORT)
            elif addr_type == ATYP_DOMAIN:
                domain_len = udp_packet[4]
                header_size = 7 + domain_len  # 2+1+1+1+domain_len+2
            elif addr_type == ATYP_IPV6:
                header_size = 22  # 2+1+1+16+2
            else:
                log.warning(f"Unsupported address type in reply: {addr_type}")
                return

            # Extract payload
            payload = udp_packet[header_size:]

            # Find client address to send reply to
            client_addr = self.addr_map.get((src_addr, src_port))
            if not client_addr:
                # If we don't have a specific mapping, use the general client address
                if self.client_addr and self.client_port:
                    client_addr = (self.client_addr, self.client_port)
                else:
                    log.warning(f"No client mapping for {src_addr}:{src_port}")
                    return

            # Send the payload to client
            self.udp_socket.sendto(payload, client_addr)
            log.debug(
                f"Send UDP reply to {client_addr[0]}:{client_addr[1]}, size={len(payload)}"
            )

        except Exception as e:
            log.error(f"Error processing UDP reply: {e}")
