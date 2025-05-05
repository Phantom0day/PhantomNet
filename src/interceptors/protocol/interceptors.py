import errno
import logging
import socket
import struct
from io import BytesIO
from src.core import BaseInterceptor, ProtocolContext
from src.utils.constants import *
from src.utils import *

log = logging.getLogger(__name__)


class HandshakeInterceptor(BaseInterceptor):
    """SOCKS5 handshake interceptor"""

    def pre_process(self, ctx):
        # Only process in init stage
        if ctx.stage != "init":
            return ctx

        data = ctx.req_data

        # Validate data
        if not data or len(data) < 2 or data[0] != SOCKS_VERSION:
            log.error(f"Invalid SOCKS version: {data[0] if data else 'no data'}")
            ctx.drop = True
            return ctx

        # Check auth methods
        nmethods = data[1]
        if len(data) < 2 + nmethods:
            log.error("Invalid handshake data length")
            ctx.drop = True
            return ctx

        methods = data[2 : 2 + nmethods]

        # Only support NO_AUTH for now
        if AUTH_NO_AUTH not in methods:
            log.error("No supported authentication methods")
            # Respond with no acceptable methods
            ctx.proc_resp = struct.pack(
                "!BB", SOCKS_VERSION, AUTH_NO_ACCEPTABLE_METHODS
            )
            ctx.drop = True
            return ctx

        # Accept NO_AUTH
        ctx.proc_resp = struct.pack("!BB", SOCKS_VERSION, AUTH_NO_AUTH)
        ctx.stage = "handshake_complete"
        log.debug("Handshake successful")

        return ctx


class RoutingInterceptor(BaseInterceptor):
    """SOCKS5 connection routing interceptor"""

    def pre_process(self, ctx):
        # Only process in handshake_complete stage
        if ctx.stage != "handshake_complete":
            return ctx

        data = ctx.req_data

        # Validate data
        if not data or len(data) < 4:
            log.error("Invalid request data length")
            ctx.drop = True
            return ctx

        version, cmd, _, addr_type = struct.unpack("!BBBB", data[:4])

        # Validate version
        if version != SOCKS_VERSION:
            log.error(f"Invalid SOCKS version: {version}")
            ctx.drop = True
            return ctx

        # Only support CONNECT command
        if cmd != CMD_CONNECT:
            log.error(f"Unsupported command: {cmd}")
            ctx.proc_resp = create_socks_reply(REPLY_COMMAND_NOT_SUPPORTED)
            ctx.drop = True
            return ctx

        # Parse destination address and port
        req_data = BytesIO(data[4:])
        dest_addr, dest_port = parse_address(req_data, addr_type)

        if not dest_addr or not dest_port:
            log.error("Failed to parse destination address")
            ctx.proc_resp = create_socks_reply(REPLY_ADDRESS_TYPE_NOT_SUPPORTED)
            ctx.drop = True
            return ctx

        log.debug(f"Connecting to {dest_addr}:{dest_port}")

        # Store destination in context
        ctx.dest_addr = dest_addr
        ctx.dest_port = dest_port

        # Try to establish the connection
        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(10)  # 10 second timeout
            remote.connect((dest_addr, dest_port))
            ctx.remote = remote

            # Get the bound address/port
            bind_addr, bind_port = remote.getsockname()

            # Create success response
            ctx.proc_resp = create_socks_reply(REPLY_SUCCESS, bind_addr, bind_port)

            # Update protocol stage
            ctx.stage = "connected"
            return ctx

        except socket.error as e:
            log.error(f"Connection error: {e}")

            # Send appropriate error response
            if e.errno == 111:  # Connection refused
                ctx.proc_resp = create_socks_reply(REPLY_CONNECTION_REFUSED)
            elif e.errno == 113:  # No route to host
                ctx.proc_resp = create_socks_reply(REPLY_HOST_UNREACHABLE)
            elif e.errno == 101:  # Network unreachable
                ctx.proc_resp = create_socks_reply(REPLY_NETWORK_UNREACHABLE)
            else:
                ctx.proc_resp = create_socks_reply(REPLY_GENERAL_FAILURE)

            ctx.drop = True
            return ctx

    def post_process(self, ctx):
        return ctx


class DataForwardingInterceptor(BaseInterceptor):
    """Handles data forwarding between client and remote sockets"""

    def __init__(self, buffer_size=10 * 1024 * 1024):
        self.MAX_BUFFER = buffer_size

    def pre_process(self, ctx):
        """Handle client->remote data flow"""
        if ctx.stage != "connected":
            return ctx

        # Initialize buffers if needed
        if "c_buf" not in ctx.meta:
            ctx.meta["c_buf"] = b""
        if "r_buf" not in ctx.meta:
            ctx.meta["r_buf"] = b""

        # Process any new request data
        if ctx.req_data:
            # Add to the remote buffer
            ctx.meta["r_buf"] += ctx.req_data

            # Try to send data to remote
            if ctx.remote and ctx.meta["r_buf"]:
                try:
                    sent = ctx.remote.send(ctx.meta["r_buf"])
                    ctx.meta["r_buf"] = ctx.meta["r_buf"][sent:]
                except socket.error as e:
                    if e.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                        log.error(f"Error sending to remote: {e}")
                        ctx.drop = True

            # Mark as processed
            ctx.proc_req = b""

        # Check buffer limits
        if len(ctx.meta["r_buf"]) > self.MAX_BUFFER:
            log.error("Remote buffer overflow")
            ctx.drop = True

        return ctx

    def post_process(self, ctx):
        """Handle remote->client data flow"""
        if ctx.stage != "connected":
            return ctx

        # Initialize buffers if needed
        if "c_buf" not in ctx.meta:
            ctx.meta["c_buf"] = b""
        if "r_buf" not in ctx.meta:
            ctx.meta["r_buf"] = b""

        # Try to receive from remote if needed
        if ctx.remote and not ctx.resp_data:
            try:
                data = ctx.remote.recv(DEFAULT_BUFFER_SIZE)
                if data:
                    ctx.resp_data = data
                elif data == b"":  # Connection closed
                    ctx.drop = True
                    return ctx
            except socket.error as e:
                if e.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                    log.error(f"Error receiving from remote: {e}")
                    ctx.drop = True
                    return ctx

        # Process any new response data
        if ctx.resp_data:
            # Add to client buffer
            ctx.meta["c_buf"] += ctx.resp_data

            # Try to send to client
            if ctx.client and ctx.meta["c_buf"]:
                try:
                    sent = ctx.client.send(ctx.meta["c_buf"])
                    ctx.meta["c_buf"] = ctx.meta["c_buf"][sent:]
                except socket.error as e:
                    if e.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                        log.error(f"Error sending to client: {e}")
                        ctx.drop = True

            # Mark as processed
            ctx.proc_resp = b""

        # Check buffer limits
        if len(ctx.meta["c_buf"]) > self.MAX_BUFFER:
            log.error("Client buffer overflow")
            ctx.drop = True

        return ctx


class UDPAssociateInterceptor(BaseInterceptor):
    """Handles UDP associate command (optional, for future use)"""

    def pre_process(self, ctx):
        # Only process in handshake_complete stage
        if ctx.stage != "handshake_complete":
            return ctx

        data = ctx.req_data

        # Check if this is a UDP ASSOCIATE command
        if not data or len(data) < 4:
            return ctx

        version, cmd, _, addr_type = struct.unpack("!BBBB", data[:4])

        if version != SOCKS_VERSION or cmd != CMD_UDP_ASSOCIATE:
            return ctx

        # Parse client's address and port
        req_data = BytesIO(data[4:])
        client_addr, client_port = parse_address(req_data, addr_type)

        log.debug(f"UDP ASSOCIATE request from {client_addr}:{client_port}")

        # Create a UDP socket
        try:
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.bind(("0.0.0.0", 0))

            # Get the bound address
            bind_addr, bind_port = udp_sock.getsockname()

            # Store UDP socket in context
            ctx.meta["udp_socket"] = udp_sock
            ctx.meta["udp_client"] = (client_addr, client_port)

            # Send success response with our UDP socket info
            ctx.proc_resp = create_socks_reply(REPLY_SUCCESS, bind_addr, bind_port)

            # Update stage for UDP association
            ctx.stage = "udp_associate"

            # Start a thread to handle UDP traffic
            # (Simplified - would need more implementation)

        except Exception as e:
            log.error(f"UDP ASSOCIATE error: {e}")
            ctx.proc_resp = create_socks_reply(REPLY_GENERAL_FAILURE)
            ctx.drop = True

        return ctx
