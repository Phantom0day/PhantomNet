import logging
import socket
import struct
import threading
import time
from io import BytesIO
from src.utils.constants import *
from src.utils.utils import *

log = logging.getLogger(__name__)


class BaseUdpRelay(threading.Thread):
    """Base class for UDP relay functionality"""

    def __init__(self, tcp_socket: socket.socket):
        super().__init__(daemon=True)
        self.tcp_socket = tcp_socket
        self.running = False
        self.lock = threading.Lock()

    def setup(self):
        raise NotImplementedError("Subclasses must implement this method")

    def run(self):
        if not self.setup():
            log.error("Failed to set up UDP relay")
            return
        self.running = True
        self._start_relay_threads()

        while self.running:
            try:
                # Keep the thread alive until stopped
                time.sleep(1)
            except Exception as e:
                log.error(f"Error in UDP relay main loop: {e}")
                if not self.running:
                    break

    def stop(self):
        self.running = False
        self._cleanup_resources()

    def _start_relay_threads(self):
        raise NotImplementedError("Subclasses must implement this method")

    def _cleanup_resources(self):
        raise NotImplementedError("Subclasses must implement this method")

    def _handle_tcp_channel(self):
        if not self.tcp_socket:
            log.error("No TCP socket available for relay")
            self.running = False
            return

        self.tcp_socket.settimeout(1)
        buf = b""

        while self.running:
            try:
                # Read data from TCP socket
                data = self.tcp_socket.recv(DEFAULT_BUFFER_SIZE)
                if not data:
                    log.info("TCP control channel closed")
                    self.running = False
                    break

                # Add to buffer
                buf += data

                # Process complete messages from buffer
                while len(buf) >= 3:  # Minimum: 1-byte type + 2-byte length
                    # Check message type
                    if buf[0] != 0x03:  # Not a UDP packet
                        # Skip this byte and continue
                        buf = buf[1:]
                        continue

                    # Extract length
                    if len(buf) < 3:
                        break

                    length = struct.unpack("!H", buf[1:3])[0]

                    # Check if we have the complete message
                    if len(buf) < 3 + length:
                        break

                    # Extract the UDP packet
                    udp_packet = buf[3 : 3 + length]
                    buf = buf[3 + length :]

                    # Process the UDP packet (implemented by subclasses)
                    self._process_udp_data(udp_packet)

            except socket.timeout:
                continue
            except Exception as e:
                log.error(f"Error in TCP channel handler: {e}")
                if not self.running:
                    break
                time.sleep(1)  # Avoid busy loop

    def _process_udp_data(self, data):
        raise NotImplementedError("Subclasses must implement this method")

    def _create_socks_udp_header(self, addr, port):
        """Create a SOCKS5 UDP header for the destination"""
        # Determine address type and format the address
        addr_type = get_address_type(addr)

        if addr_type == ATYP_IPV4:
            addr_bytes = socket.inet_aton(addr)
            addr_data = struct.pack("!B", addr_type) + addr_bytes
        elif addr_type == ATYP_IPV6:
            addr_bytes = socket.inet_pton(socket.AF_INET6, addr)
            addr_data = struct.pack("!B", addr_type) + addr_bytes
        else:  # Domain name
            addr_bytes = addr.encode()
            addr_data = struct.pack("!BB", addr_type, len(addr_bytes)) + addr_bytes

        # Add port and create the header
        port_bytes = struct.pack("!H", port)
        return struct.pack("!HB", 0, 0) + addr_data + port_bytes

    def _parse_socks_udp_header(self, data):
        """Parse a SOCKS5 UDP header to extract destination address and port"""
        if len(data) < 7:  # Minimum header size
            return None, None, 0

        try:
            # Parse header
            header = data[:4]
            reserved, frag, addr_type = struct.unpack("!HBB", header)

            if reserved != 0:
                log.warning(f"Invalid UDP packet: reserved field != 0 ({reserved})")
                return None, None, 0

            if frag != 0:
                log.warning(f"Fragmented UDP packets not supported (frag={frag})")
                return None, None, 0

            # Parse address
            addr_obj = BytesIO(data[3:])
            dest_addr, dest_port = parse_address(addr_obj, addr_type)

            # Calculate header size
            header_size = 0
            if addr_type == ATYP_IPV4:
                header_size = 10  # 2(RSV) + 1(FRAG) + 1(ATYP) + 4(IPv4) + 2(PORT)
            elif addr_type == ATYP_DOMAIN:
                domain_len = data[4]
                header_size = 7 + domain_len  # 2+1+1+1+domain_len+2
            elif addr_type == ATYP_IPV6:
                header_size = 22  # 2+1+1+16+2
            else:
                log.warning(f"Unsupported address type: {addr_type}")
                return None, None, 0

            return dest_addr, dest_port, header_size

        except Exception as e:
            log.error(f"Error parsing UDP header: {e}")
            return None, None, 0


class UdpRelayClient(BaseUdpRelay):
    """Client-side UDP relay implementation"""

    def __init__(self, tcp_socket, client_addr, client_port):
        super().__init__(tcp_socket)
        self.client_addr, self.client_port = client_addr, client_port
        self.local_addr, self.local_port = None, None
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

    def _start_relay_threads(self):
        """Start necessary relay threads"""
        # Start TCP listener thread
        tcp_thread = threading.Thread(target=self._handle_tcp_channel, daemon=True)
        tcp_thread.start()

        # Start UDP traffic handler thread
        udp_thread = threading.Thread(target=self._handle_udp_traffic, daemon=True)
        udp_thread.start()

    def _cleanup_resources(self):
        """Clean up UDP relay resources"""
        if self.udp_socket:
            close_socket(self.udp_socket)
            self.udp_socket = None

    def _handle_udp_traffic(self):
        """Handle incoming UDP traffic from local client"""
        if not self.udp_socket:
            log.error("UDP socket not initialized")
            self.running = False
            return

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

                # Parse the SOCKS5 UDP header
                dest_addr, dest_port, header_size = self._parse_socks_udp_header(data)

                if not dest_addr or not dest_port:
                    log.warning("Failed to parse destination address in UDP packet")
                    continue

                # Extract the payload
                payload = data[header_size:]
                log.debug(f"UDP packet to {dest_addr}:{dest_port}, size={len(payload)}")

                # Store the mapping for replies
                self.addr_map[(dest_addr, dest_port)] = addr

                # Forward to the server over TCP channel
                # The packet already has SOCKS5 UDP header
                length_prefix = struct.pack("!H", len(data))
                try:
                    self.tcp_socket.sendall(
                        b"\x03" + length_prefix + data
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

    def _process_udp_data(self, udp_packet):
        """Process UDP reply from the server"""
        try:
            # Parse address from the SOCKS UDP header
            src_addr, src_port, header_size = self._parse_socks_udp_header(udp_packet)

            if not src_addr or not src_port:
                log.warning("Failed to parse source address in UDP reply")
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


class UdpRelayServer(BaseUdpRelay):
    """Server-side UDP relay implementation"""

    def __init__(self, tcp_socket):
        super().__init__(tcp_socket)
        self.dest_sockets = {}  # Maps (dest_addr, dest_port) -> UDP socket

    def setup(self):
        """Set up the UDP relay server"""
        # No specific setup needed for server side
        return True

    def _start_relay_threads(self):
        """Start the TCP handler thread"""
        # Only need the TCP channel handler
        self._handle_tcp_channel()

    def _cleanup_resources(self):
        """Clean up UDP relay server resources"""
        with self.lock:
            for sock in self.dest_sockets.values():
                try:
                    sock.close()
                except Exception as e:
                    log.error(f"Error closing UDP socket: {e}")
            self.dest_sockets.clear()

    def _process_udp_data(self, udp_packet):
        """Process UDP packet from the client"""
        try:
            # Parse the SOCKS5 UDP header
            dest_addr, dest_port, header_size = self._parse_socks_udp_header(udp_packet)

            if not dest_addr or not dest_port:
                log.warning("Failed to parse destination address in UDP packet")
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
                udp_header = self._create_socks_udp_header(addr[0], addr[1])
                udp_packet = udp_header + data

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
