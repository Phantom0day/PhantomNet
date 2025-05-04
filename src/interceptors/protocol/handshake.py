import hmac
import logging
import struct
import time
from src.core.context import ProtocolContext
from src.core.interceptor import BaseInterceptor
from src.utils.constants import *

logger = logging.getLogger(__name__)


class HandshakeInterceptor(BaseInterceptor):
    """SOCKS5 handshake interceptor"""

    def pre_process(self, context: ProtocolContext) -> ProtocolContext:
        try:
            # Check if we're in the initial protocol stage
            if context.protocol_stage != "init":
                return context
            # Request_data should already be set
            data = context.request_data

            # Check SOCKS version
            if not data or len(data) < 2 or data[0] != SOCKS_VERSION:
                logger.error(f"Invalid SOCKS version: {data[0] if data else 'no data'}")
                context.should_drop = True
                return context

            # Check auth method
            nmethods = data[1]
            if len(data) < 2 + nmethods:
                logger.error("Invalid handshake data length")
                context.should_drop = True
                return context

            # Extract auth methods
            methods = data[2 : 2 + nmethods]

            # For basic implementation, only support NO_AUTH
            if AUTH_NO_AUTH not in methods:
                logger.error("No supported authentication methods")
                # Respond with no acceptable methods
                response = struct.pack("!BB", SOCKS_VERSION, AUTH_NO_ACCEPTABLE_METHODS)
                context.processed_response = response
                context.should_drop = True
                return context

            # Send handshake response (accpet NO_AUTH)
            response = struct.pack("!BB", SOCKS_VERSION, AUTH_NO_AUTH)
            context.processed_response = response
            context.protocol_stage = "handshake_complete"

            logger.debug("Handshake successful, waiting for connection request")
            return context
        except Exception as e:
            logger.error(f"Handshake error: {e}")
            context.should_drop = True
            return context

    def post_process(self, context: ProtocolContext) -> ProtocolContext:
        # No special post-processing needed for handshake
        return context


class SecureHandshakeInterceptor(BaseInterceptor):
    """Implements secure authentication handshake"""

    def __init__(self, shared_secret, time_window=30):
        self.shared_secret = shared_secret
        self.time_window = time_window

    def pre_process(self, context):
        try:
            # Extract handshake data
            if len(context.request_data) < 8:
                context.should_drop = True
                return context

            # Verify timestamp to prevent replay attacks
            timestamp_bytes = context.request_data[:4]
            timestamp = struct.unpack("!I", timestamp_bytes)[0]
            current_time = int(time.time())

            if abs(current_time - timestamp) > self.time_window:
                # Timestamp too old or too far in future
                context.should_drop = True
                return context

            # Verify HMAC
            provided_hmac = context.request_data[4:8]
            expected_hmac = self._calculate_hmac(timestamp_bytes)

            if not hmac.compare_digest(provided_hmac, expected_hmac):
                context.should_drop = True
                return context

            # Extract the real SOCKS5 handshake after authentication data
            context.processed_request = context.request_data[8:]
        except Exception:
            context.should_drop = True
            return context
