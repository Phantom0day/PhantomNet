import errno
import logging
import socket
import struct
from io import BytesIO
from src.core.context import ProtocolContext
from src.core.interceptor import BaseInterceptor
from src.utils.constants import *
from src.utils import parse_address, create_socks_reply, close_socket

logger = logging.getLogger(__name__)


class RoutingInterceptor(BaseInterceptor):
    """SOCKS5 connection routing interceptor"""

    def pre_process(self, context: ProtocolContext) -> ProtocolContext:
        # If we're not in handshake_complete stage, skip
        if context.protocol_stage != "handshake_complete":
            return context

        return self._handle_connect_request(context)

    def _handle_connect_request(self, context: ProtocolContext):
        try:
            # Parse the SOCKS5 request
            data = context.request_data

            if not data or len(data) < 4:
                logger.error("Invalid request data length")
                context.should_drop = True
                return context

            version, cmd, _, address_type = struct.unpack("!BBBB", data[:4])

            if version != SOCKS_VERSION:
                logger.error(f"Invalid SOCKS version: {version}")
                context.should_drop = True
                return context

            if cmd != CMD_CONNECT:
                logger.error(f"Unsupported command: {cmd}")
                context.processed_response = create_socks_reply(
                    REPLY_COMMAND_NOT_SUPPORTED
                )
                context.should_drop = True
                return context

            # Use BytesIO to read the remaining request data for parsing
            request_sock = BytesIO(data[4:])

            # Parse destination address
            dest_addr, dest_port = parse_address(request_sock, address_type)
            if not dest_addr or not dest_port:
                logger.error("Failed to parse destination address")
                context.processed_response = create_socks_reply(
                    REPLY_ADDRESS_TYPE_NOT_SUPPORTED
                )
                context.should_drop = True
                return context

            logger.debug(f"Connecting to {dest_addr}:{dest_port}")

            # Store destination in context
            context.dest_addr = dest_addr
            context.dest_port = dest_port

            # Create remote connection
            try:
                remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote_sock.settimeout(10)  # 10 second timeout
                remote_sock.connect((dest_addr, dest_port))
                context.remote_socket = remote_sock

                # Get the bound address/port
                bind_addr, bind_port = remote_sock.getsockname()

                # Create success response
                context.processed_response = create_socks_reply(
                    REPLY_SUCCESS, bind_addr, bind_port
                )

                # Update protocol stage
                context.protocol_stage = "connected"
                return context
            except socket.error as e:
                logger.error(f"Connection error: {e}")
                if e.errno == 111:  # Connection refused
                    context.processed_response = create_socks_reply(
                        REPLY_CONNECTION_REFUSED
                    )
                elif e.errno == 113:  # No route to host
                    context.processed_response = create_socks_reply(
                        REPLY_HOST_UNREACHABLE
                    )
                elif e.errno == 101:  # Network unreachable
                    context.processed_response = create_socks_reply(
                        REPLY_NETWORK_UNREACHABLE
                    )
                else:
                    context.processed_response = create_socks_reply(
                        REPLY_GENERAL_FAILURE
                    )
                context.should_drop = True
                return context

        except Exception as e:
            logger.error(f"Request handling error: {e}")
            context.processed_response = create_socks_reply(REPLY_GENERAL_FAILURE)
            context.should_drop = True
            return context

    def post_process(self, context: ProtocolContext) -> ProtocolContext:
        # Forward data from server to client
        if context.protocol_stage == "connected" and context.remote_socket:
            try:
                # If there's data to send to the remote
                if context.processed_request:
                    context.remote_socket.sendall(context.processed_request)
                # Receive data from remote if needed
                if not context.response_data and context.protocol_stage == "connected":
                    data = context.remote_socket.recv(DEFAULT_BUFFER_SIZE)
                    if not data:
                        # Connection closed by remote
                        context.should_drop = True
                    else:
                        context.response_data = data
                        context.processed_response = data
            except Exception as e:
                logger.error(f"Error receiving from remote: {e}")
                context.should_drop = True
        return context


class DataForwardingInterceptor(BaseInterceptor):
    """
    Handles data forwarding between client and remote sockets.
    This interceptor manages buffers and socket I/O operations.
    """

    def __init__(self, buffer_size=20 * 1024 * 1024):
        self.MAX_BUFFER_SIZE = buffer_size

    def pre_process(self, context: ProtocolContext) -> ProtocolContext:
        """
        Handle client->remote data flow and socket operations.
        This is called when data is received from the client.
        """
        # Only process in connected stage
        if context.protocol_stage != "connected":
            return context

        # Initialize buffers in metadata if not present
        if "client_buffer" not in context.metadata:
            context.metadata["client_buffer"] = b""
        if "remote_buffer" not in context.metadata:
            context.metadata["remote_buffer"] = b""

        # Process any new request data
        if context.request_data:
            # Add to the remote buffer to be sent
            context.metadata["remote_buffer"] += context.request_data

            # Try to send data to remote if socket is available
            if context.remote_socket and context.metadata["remote_buffer"]:
                try:
                    sent = context.remote_socket.send(context.metadata["remote_buffer"])
                    context.metadata["remote_buffer"] = context.metadata[
                        "remote_buffer"
                    ][sent:]
                except socket.error as e:
                    if e.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                        logger.error(f"Error sending to remote: {e}")
                        context.should_drop = True

            # Clear request data to indicate it's been processed
            context.processed_request = b""

        # Check buffer limits
        if len(context.metadata["remote_buffer"]) > self.MAX_BUFFER_SIZE:
            logger.error("Remote buffer overflow")
            context.should_drop = True

        return context

    def post_process(self, context: ProtocolContext) -> ProtocolContext:
        """
        Handle remote->client data flow and socket operations.
        This is called when data is received from the remote socket.
        """
        # Only process in connected stage
        if context.protocol_stage != "connected":
            return context

        # Initialize buffers if not present
        if "client_buffer" not in context.metadata:
            context.metadata["client_buffer"] = b""
        if "remote_buffer" not in context.metadata:
            context.metadata["remote_buffer"] = b""

        # Try to receive data from remote if needed
        if context.remote_socket and not context.response_data:
            try:
                data = context.remote_socket.recv(DEFAULT_BUFFER_SIZE)
                if data:
                    context.response_data = data
                elif data == b"":  # Connection closed
                    context.should_drop = True
                    return context
            except socket.error as e:
                if e.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                    logger.error(f"Error receiving from remote: {e}")
                    context.should_drop = True
                    return context

        # Process any new response data
        if context.response_data:
            # Add to client buffer to be sent
            context.metadata["client_buffer"] += context.response_data

            # Try to send to client if socket is available
            if context.client_socket and context.metadata["client_buffer"]:
                try:
                    sent = context.client_socket.send(context.metadata["client_buffer"])
                    context.metadata["client_buffer"] = context.metadata[
                        "client_buffer"
                    ][sent:]
                except socket.error as e:
                    if e.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                        logger.error(f"Error sending to client: {e}")
                        context.should_drop = True

            # Clear response data to indicate it's been processed
            context.processed_response = b""

        # Check buffer limits
        if len(context.metadata["client_buffer"]) > self.MAX_BUFFER_SIZE:
            logger.error("Client buffer overflow")
            context.should_drop = True

        return context
