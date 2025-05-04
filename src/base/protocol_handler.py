import logging
import socket
import struct

from src.common import constants as const, utils
from src.auth import NoAuthHandler

logger = logging.getLogger(__name__)


class SOCKS5ProtocolHandler:
    """Handles SOCKS5 protocol operations."""

    def __init__(self, auth_handlers=None):
        """
        Initialize the protocol handler.

        Args:
            auth_handlers: List of authentication handlers
        """
        self.auth_handlers = auth_handlers or [NoAuthHandler()]
        self.auth_methods = {
            handler.get_method(): handler for handler in self.auth_handlers
        }

    def parse_address(self, socket_obj, address_type):
        """Parse an address from a socket based on the SOCKS5 address type."""
        return utils.parse_address(socket_obj, address_type)

    def create_socks_reply_packet(self, reply_code, bind_addr=None, bind_port=0):
        """Create a SOCKS5 reply packet."""
        return utils.create_socks_reply_packet(reply_code, bind_addr, bind_port)

    def parse_auth_methods(self, socket_obj):
        """Parse authentication methods from client."""
        data = utils.recv_all(socket_obj, 2)
        if len(data) < 2:
            return None, None

        version, nmethods = struct.unpack("!BB", data)
        methods = utils.recv_all(socket_obj, nmethods)

        return version, methods

    def send_auth_method_selection(self, socket_obj, method):
        """Send authentication method selection to client."""
        socket_obj.sendall(struct.pack("!BB", const.SOCKS_VERSION, method))

    def parse_socks_request(self, socket_obj):
        """Parse a SOCKS5 request from client."""
        # Parse header
        data = utils.recv_all(socket_obj, 4)
        if len(data) < 4:
            return None, None, None, None
        version, cmd, _, address_type = struct.unpack("!BBBB", data)

        # Parse address
        dest_addr = self.parse_address(socket_obj, address_type)

        # Parse port
        port_data = utils.recv_all(socket_obj, 2)
        if len(port_data) < 2:
            return version, cmd, dest_addr, None

        dest_port = struct.unpack("!H", port_data)[0]

        return version, cmd, dest_addr, dest_port

    def handle_client_auth_negotiation(self, socket_obj: socket.socket):
        """
        Handle client authentication method negotiation.

        Args:
            socket_obj: Client socket

        Returns:
            tuple: (success, selected_auth_method)
        """
        try:
            # Receive client authentication methods
            data = utils.recv_all(socket_obj, 2)
            if len(data) < 2:
                logger.error("SOCKS5 initialization failed - invalid data length")
                return False, None

            version, nmethods = struct.unpack("!BB", data)
            if version != const.SOCKS_VERSION:
                logger.error(f"Unsupported SOCKS version: {version}")
                return False, None

            # Receive authentication methods
            methods = utils.recv_all(socket_obj, nmethods)
            if len(methods) < nmethods:
                logger.error("SOCKS5 initialization failed - invalid methods length")
                return False, None

            # Find a supported authentication method
            supported_method = const.AUTH_NO_ACCEPTABLE_METHODS
            for method in methods:
                if method in self.auth_methods:
                    supported_method = method
                    break

            # Send selected authentication method
            socket_obj.sendall(
                struct.pack("!BB", const.SOCKS_VERSION, supported_method)
            )

            if supported_method == const.AUTH_NO_ACCEPTABLE_METHODS:
                logger.error("No acceptable authentication methods")
                return False, None

            return True, supported_method
        except Exception as e:
            logger.error(f"SOCKS5 initialization error: {e}")
            return False, None

    def perform_authentication(self, socket_obj: socket.socket, method):
        """
        Perform authentication

        Args:
            socket_obj: Client socket
            method: Selected authentication method

        Returns:
            bool: True if authentication successful
        """
        if method == const.AUTH_NO_AUTH:
            return True

        if method not in self.auth_methods:
            return False

        auth_handler = self.auth_methods[method]
        return auth_handler.authenticate(socket_obj)

    def parse_client_request(self, socket_obj: socket.socket):
        """
        Parse SOCKS5 client request.

        Args:
            socket_obj: Client socket

        Returns:
            tuple: (version, command, address_type, dest_addr, dest_port)
        """
        try:
            # Receive client request
            data = utils.recv_all(socket_obj, 4)
            if len(data) < 4:
                logger.error("SOCKS5 request failed - invalid data length")
                return None, None, None, None, None

            version, cmd, _, address_type = struct.unpack("!BBBB", data)

            # Parse destination address
            dest_addr = utils.parse_address(socket_obj, address_type)
            if not dest_addr:
                logger.error("Failed to parse destination address")
                return version, cmd, address_type, None, None

            # Get destination port
            port_data = utils.recv_all(socket_obj, 2)
            if len(port_data) < 2:
                logger.error("SOCKS5 request failed - invalid port length")
                return version, cmd, address_type, dest_addr, None

            dest_port = struct.unpack("!H", port_data)[0]
            return version, cmd, address_type, dest_addr, dest_port
        except Exception as e:
            logger.error(f"Error parsing client request: {e}")
            return None, None, None, None, None

    def send_reply(
        self, socket_obj: socket.socket, reply_code, bind_addr=None, bind_port=0
    ):
        """
        Send SOCKS5 reply.

        Args:
            socket_obj: Client socket
            reply_code: Reply code
            bind_addr: Bound address
            bind_port: Bound port

        Returns:
            bool: True if successful
        """
        try:
            reply = utils.create_socks_reply_packet(reply_code, bind_addr, bind_port)
            socket_obj.sendall(reply)
            return True
        except Exception as e:
            logger.error(f"Error sending reply: {e}")
            return False

    def perform_version_handshake(
        self, socket_obj: socket.socket, is_server=False
    ) -> bool:
        """
        Perform version handshake to ensure client and server are compatible.

        Args:
            socks_obj: Socket connected to the peer
            is_server: True if running in server mode

        Returns:
            bool: True if versions are compatible
        """
        try:
            if is_server:
                # Server: Receive client version and respond
                data = utils.recv_all(socket_obj, 3)
                if len(data) < 3:
                    logger.error("Version handshake failed - invalid data length")
                    return False

                client_major, client_minor, client_patch = struct.unpack("!BBB", data)
                logger.info(
                    f"Client version: {client_major}.{client_minor}.{client_patch}"
                )

                # Check compatibility (major version must match, minor can differ)
                compatible = client_major == const.APP_VERSION_MAJOR

                # Send server version and compatibility status
                socket_obj.sendall(
                    struct.pack(
                        "!BBBB",
                        const.APP_VERSION_MAJOR,
                        const.APP_VERSION_MINOR,
                        const.APP_VERSION_PATCH,
                        (
                            const.VERSION_COMPATIBLE
                            if compatible
                            else const.VERSION_INCOMPATIBLE
                        ),
                    )
                )
                return compatible
            else:
                # Client: Send version and receive response
                socket_obj.sendall(
                    struct.pack(
                        "!BBB",
                        const.APP_VERSION_MAJOR,
                        const.APP_VERSION_MINOR,
                        const.APP_VERSION_PATCH,
                    )
                )

                # Get server response
                response = utils.recv_all(socket_obj, 4)
                if len(response) < 4:
                    logger.error("Version handshake failed - invalid response length")
                    return False

                server_major, server_minor, server_patch, compatibility = struct.unpack(
                    "!BBBB", response
                )
                logger.info(
                    f"Server version: {server_major}.{server_minor}.{server_patch}"
                )
                if compatibility != const.VERSION_COMPATIBLE:
                    logger.error("Server reported version incompatibility")
                    return False
                return True
        except Exception as e:
            logger.error(f"Version handshake error: {e}")
        return False
