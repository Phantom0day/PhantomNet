import errno
import logging
import socket
import struct
from io import BytesIO
from src.core import ProtocolContext
from src.interceptors.core import BaseInterceptor
from src.utils.constants import *
from src.utils import *


class HandshakeInterceptor(BaseInterceptor):
    """SOCKS5 handshake interceptor"""

    def unpack(self, ctx):
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

    def pack(self, ctx):
        return ctx

    def unpack(self, ctx):
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


class UDPAssociateInterceptor(BaseInterceptor):
    """Handles UDP associate command (optional, for future use)"""

    def unpack(self, ctx):
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
