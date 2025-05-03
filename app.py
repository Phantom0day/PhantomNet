import socket
import select
import struct
import threading
import logging
import signal
import sys
from typing import List

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class SOCKS5Proxy:
    def __init__(self, host="0.0.0.0", port=1080):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = True
        self.threads: List[threading.Thread] = []

    def start(self):
        """Start the SOCKS5 proxy server"""
        try:
            # Create server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(100)

            # Set a timeout so the socket doesn't block indefinitely
            self.server_socket.settimeout(1)

            logger.info(f"SOCKS5 proxy server started on {self.host}:{self.port}")
            logger.info("Press Ctrl+C to stop the server")

            # Main server loop
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    logger.info(
                        f"New connection from {client_address[0]}:{client_address[1]}"
                    )

                    # Start a new thread to handle the client
                    client_thread = threading.Thread(
                        target=self.handle_client, args=(client_socket,)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    self.threads.append(client_thread)

                    # Clean up finished threads
                    self.threads = [t for t in self.threads if t.is_alive()]

                except socket.timeout:
                    # This is normal, just continue the Loop
                    continue
                except Exception as e:
                    if self.running:
                        logger.error(f"Server error: {e}")

        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            if self.running:
                self.stop()

    def stop(self):
        """Stop the proxy server"""
        self.running = False
        logger.info("Shutting down server...")

        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass

        # Wait for all threads to finish (with timeout)
        for t in self.threads:
            try:
                if t.is_alive():
                    t.join(0.5)
            except:
                pass

        logger.info("Server stopped")

    def handle_client(self, client_socket: socket.socket):
        """Handle SOCKS5 client connection"""
        try:
            # SOCKS5 initialization
            if not self.socks5_initialization(client_socket):
                return

            # SOCKS5 request
            if not self.socks5_request(client_socket):
                return

        except Exception as e:
            logger.error(f"Error handling client: {e}")
        finally:
            client_socket.close()

    def socks5_initialization(self, client_socket: socket.socket):
        """Handle SOCKS5 initialization"""
        # Receive client authentication methods
        data = client_socket.recv(2)
        if len(data) < 2:
            logger.error("SOCKS5 initialization failed - invalid data length")
            return False

        version, nmethods = struct.unpack("!BB", data)
        if version != 5:
            logger.error(f"Unsupported SOCKS version: {version}")
            return False

        # Receive authentication methods
        methods = client_socket.recv(nmethods)
        if len(methods) < nmethods:
            logger.error("SOCKS5 initialization failed - invalid methods length")
            return False

        # We'll accept method 0 (no authentication required)
        client_socket.sendall(struct.pack("!BB", 5, 0))
        return True

    def socks5_request(self, client_socket: socket.socket):
        """Handle SOCKS5 request"""
        # Receive client request
        data = client_socket.recv(4)
        if len(data) < 4:
            logger.error("SOCKS5 request failed - invalid data length")
            return False

        version, cmd, _, address_type = struct.unpack("!BBBB", data)
        if version != 5:
            logger.error(f"Unsupported SOCKS version: {version}")
            return False
        if cmd != 1:  # CONNECT command
            logger.error(f"Unsupported SOCKS command: {cmd}")
            client_socket.sendall(
                struct.pack("!BBBBIH", 5, 7, 0, 1, 0, 0)
            )  # Command not supported
            return False

        # Get destination address based on address type
        if address_type == 1:  # IPv4
            addr_data = client_socket.recv(4)
            if len(addr_data) < 4:
                logger.error("SOCKS5 request failed - invalid IPv4 address length")
                return False
            dest_addr = socket.inet_ntoa(addr_data)
        elif address_type == 3:  # Domain name
            addr_len = client_socket.recv(1)[0]
            addr_data = client_socket.recv(addr_len)
            if len(addr_data) < addr_len:
                logger.error("SOCKS5 request failed - invalid domain name length")
                return False
            dest_addr = addr_data.decode("utf-8")
        elif address_type == 4:  # IPv6
            addr_data = client_socket.recv(16)
            if len(addr_data) < 16:
                logger.error("SOCKS5 request failed - invalid IPv6 address length")
                return False
            dest_addr = socket.inet_ntop(socket.AF_INET6, addr_data)
        else:
            logger.error(f"Unsupported address type: {address_type}")
            # Address type not supported
            client_socket.sendall(struct.pack("!BBBBIH", 5, 8, 0, 1, 0, 0))
            return False

        # Get destination port
        port_data = client_socket.recv(2)
        if len(port_data) < 2:
            logger.error("SOCKS5 request failed - invalid port length")
            return False
        dest_port = struct.unpack("!H", port_data)[0]

        logger.info(f"SOCKS5 request to connect to {dest_addr}:{dest_port}")

        # Connect to destination
        try:
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_socket.connect((dest_addr, dest_port))

            # Send success response
            bind_addr, bind_port = remote_socket.getsockname()

            # Convert bind_addr to bytes based on its type
            data_flag = 1
            if ":" in bind_addr:  # IPv6
                addr_bytes = socket.inet_pton(socket.AF_INET6, bind_addr)
                data_flag = 4
            else:  # IPv4
                addr_bytes = socket.inet_aton(bind_addr)

            client_socket.sendall(
                struct.pack("!BBBB", 5, 0, 0, data_flag)
                + addr_bytes
                + struct.pack("!H", bind_port)
            )

            # Set up bidiractional proxy
            self.proxy_data(client_socket, remote_socket)

            return True
        except Exception as e:
            logger.error(f"Failed to connect to destination: {e}")
            # Send failure response
            client_socket.sendall(
                struct.pack("!BBBBIH", 5, 4, 0, 1, 0, 0)
            )  # Host unreachable
            return False

    def proxy_data(self, client_socket: socket.socket, remote_socket: socket.socket):
        """Proxy data between client and destination"""
        client_socket.setblocking(False)
        remote_socket.setblocking(False)

        while self.running:
            try:
                # Wait until client or remote is available for read
                r, _, e = select.select(
                    [client_socket, remote_socket],
                    [],
                    [client_socket, remote_socket],
                    1,
                )

                if client_socket in e or remote_socket in e:
                    break

                for s in r:
                    data = s.recv(4096)
                    if not data:
                        return
                    if s is client_socket:
                        remote_socket.sendall(data)
                    else:
                        client_socket.sendall(data)
            except Exception as e:
                logger.error(f"Error in proxy_data: {e}")
                break

        # Clean up
        remote_socket.close()


def signal_handler(sig, frame):
    """Handle keyboard interrupt"""
    logger.info("Received interrupt signal, shutting down...")
    if "proxy" in globals():
        proxy.running = False
        try:
            proxy.stop()
        except Exception as e:
            logger.error(f"Error stopping proxy: {e}")
    sys.exit(0)


def main(*args):
    host = "0.0.0.0"
    port = 1080
    if len(args) >= 2:
        host = args[0]
        port = int(args[1])

    global proxy
    proxy = SOCKS5Proxy(host, port)

    # Register the signal handler for keyboard interrupt (Ctrl + C)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    proxy.start()


if __name__ == "__main__":
    main(*sys.argv[1:])
