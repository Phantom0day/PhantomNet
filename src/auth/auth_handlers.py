"""
Authentication handlers for SOCKS5 proxy.
"""

import logging
import socket
import struct
from typing import Dict, Optional, Tuple

from src.common import constants as const
from src.common import utils

logger = logging.getLogger(__name__)


class AuthHandler:
    """Base authentication handler interface."""

    def get_method(self) -> int:
        """Get the authentication method code."""
        raise NotImplementedError()

    def authenticate(self, socket_obj: socket.socket) -> bool:
        """Perform authentication on the given socket."""
        raise NotImplementedError()


class NoAuthHandler(AuthHandler):
    """No authentication required handler."""

    def get_method(self) -> int:
        return const.AUTH_NO_AUTH

    def authenticate(self, socket_obj) -> bool:
        # No authentication needed
        return True


class UsernamePasswordAuthHandler(AuthHandler):
    """Username/password authentication handler."""

    def __init__(self, credentials: Dict[str, str] = None):
        """
        Initialize with credentials dictionary.

        Args:
            credentials: Dictionary of username: password pairs
        """
        self.credentials = credentials or {}

    def get_method(self) -> int:
        return const.AUTH_USERNAME_PASSWORD

    def authenticate(self, socket_obj: socket.socket) -> bool:
        """
        Perform username/password authentication.

        Args:
            socket_obj: Socket to authenticate

        Returns:
            bool: True if authentication successful
        """
        try:
            # Receive auth version and username length
            data = utils.recv_all(socket_obj, 2)
            if len(data) < 2:
                logger.error("Username/password auth failed - invalid data length")
                return self._send_auth_response(socket_obj, False)

            ver, ulen = struct.unpack("!BB", data)
            if ver != const.AUTH_USERNAME_PASSWORD_VERSION:
                logger.error(f"Unsupported auth version: {ver}")
                return self._send_auth_response(socket_obj, False)

            # Receive username
            username_data = utils.recv_all(socket_obj, ulen)
            if len(username_data) < ulen:
                logger.error("Username/password auth failed - invalid username length")
                return self._send_auth_response(socket_obj, False)

            username = username_data.decode("utf-8")

            # Receive password length
            plen_data = utils.recv_all(socket_obj, 1)
            if not plen_data:
                logger.error("Username/password auth failed - missing password length")
                return self._send_auth_response(socket_obj, False)

            plen = plen_data[0]

            # Receive password
            password_data = utils.recv_all(socket_obj, plen)
            if len(password_data) < plen:
                logger.error("Username/password auth failed - invalid password length")
                return self._send_auth_response(socket_obj, False)

            password = password_data.decode("utf-8")

            # Verify credentials
            if username in self.credentials and self.credentials[username] == password:
                logger.info(f"User {username} authenticated successfully")
                return self._send_auth_response(socket_obj, True)
            else:
                logger.warning(f"Authentication failed for user {username}")
                return self._send_auth_response(socket_obj, False)

        except Exception as e:
            logger.error(f"Username/password authentication error: {e}")
            self._send_auth_response(socket_obj, False)
            return False

    def _send_auth_response(self, socket_obj: socket.socket, success: bool) -> bool:
        """
        Send authentication response.

        Args:
            socket_obj: Socket to send response to
            success: Whether authentication was successful

        Returns:
            bool: Success value
        """
        try:
            response = struct.pack(
                "!BB",
                const.AUTH_USERNAME_PASSWORD_VERSION,
                (
                    const.AUTH_USERNAME_PASSWORD_SUCCESS
                    if success
                    else const.AUTH_USERNAME_PASSWORD_FAILURE
                ),
            )
            socket_obj.sendall(response)
            return success
        except Exception as e:
            logger.error(f"Error sending auth response: {e}")
            return False
