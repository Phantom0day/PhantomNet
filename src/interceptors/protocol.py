import errno
import logging
import logging.config
import socket
import struct
import time
from io import BytesIO
from src.core import ProtocolContext
from src.interceptors.core import BaseInterceptor
from src.utils.constants import *
from src.utils import *


class HandshakeInterceptor(BaseInterceptor):
    """SOCKS5 handshake interceptor"""

    def pack(self, ctx):
        # Only process in init stage
        if ctx.stage != "init":
            return ctx

        data = ctx.req_data

        timestamp = struct.pack("!I", time.time() / 10)
        ctx.stage = "handshake_complete"
        log.debug("Handshake successful")

        return ctx

    def unpack(self, ctx):
        # Only process in init stage
        if ctx.stage != "init":
            return ctx

        data = ctx.resp_data

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
            ctx.resp_data = struct.pack(
                "!BB", SOCKS_VERSION, AUTH_NO_ACCEPTABLE_METHODS
            )
            ctx.drop = True
            return ctx

        # Accept NO_AUTH
        ctx.resp_data = struct.pack("!BB", SOCKS_VERSION, AUTH_NO_AUTH)
        ctx.stage = "handshake_complete"
        log.debug("Handshake successful")

        return ctx


class UDPAssociateInterceptor(BaseInterceptor):
    """Handles UDP associate command (optional, for future use)"""

    def unpack(self, ctx):
        # Only process in handshake_complete stage
        if ctx.stage != "handshake_complete":
            return ctx

        data = ctx.resp_data

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
            ctx.resp_data = create_socks_reply(REPLY_SUCCESS, bind_addr, bind_port)

            # Update stage for UDP association
            ctx.stage = "udp_associate"

            # Start a thread to handle UDP traffic
            # (Simplified - would need more implementation)

        except Exception as e:
            log.error(f"UDP ASSOCIATE error: {e}")
            ctx.resp_data = create_socks_reply(REPLY_GENERAL_FAILURE)
            ctx.drop = True

        return ctx


class PacketLogger(BaseInterceptor):
    def __init__(self, log_level=logging.INFO, max_length=32):
        super().__init__()
        self.log_level = getattr(logging, log_level.upper(), logging.INFO)
        self.log_enable = log.level <= self.log_level
        self.max_length = getattr(logging, log_level.upper(), logging.INFO)

    def pack(self, ctx):
        if self.log_enable:
            data = ctx.req_data[:64].hex() if ctx.req_data else ""
            log.log(self.log_level, f"PACK>>{len(data)}")
            log.log(self.log_level, f"    REQ>>{data}")
        return ctx

    def unpack(self, ctx):
        if self.log_enable:
            data = ctx.resp_data[:64].hex() if ctx.resp_data else ""
            log.log(self.log_level, f"after UNPK<<{len(data)}")
            log.log(self.log_level, f"    RESP>>{data}")
        return ctx


class PacketLogger2(BaseInterceptor):
    def __init__(self, log_level=logging.INFO, max_length=32):
        super().__init__()
        self.log_level = getattr(logging, log_level.upper(), logging.INFO)
        self.log_enable = log.level <= self.log_level
        self.max_length = getattr(logging, log_level.upper(), logging.INFO)

    def pack(self, ctx):
        if self.log_enable:
            data = ctx.req_data[:64].hex() if ctx.req_data else ""
            log.log(self.log_level, f"after PACK>>{len(data)}")
            log.log(self.log_level, f"    REQ>>{data}")
        return ctx

    def unpack(self, ctx):
        if self.log_enable:
            data = ctx.resp_data[:64].hex() if ctx.resp_data else ""
            log.log(self.log_level, f"UNPK<<{len(data)}")
            log.log(self.log_level, f"    RESP>>{data}")
        return ctx
