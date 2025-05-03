import logging
import socket
import threading
from typing import Dict, List

from src.common import constants as const, utils


logger = logging.getLogger(__name__)


class ConnectionPool:
    """Pool of reusable connections."""

    def __init__(self, max_size=100):
        """Initialize the connection pool."""
        self.max_size = max_size
        self.pool: Dict[tuple, List] = {}  # {(host, port): [connections]}
        self.lock = threading.Lock()

    def get_connection(self, host, port):
        """Get a connection from the pool or create a new one."""
        key = (host, port)

        with self.lock:
            if key in self.pool and self.pool[key]:
                return self.pool[key].pop()

        # Create new connection
        sock = socket.socket(const.DEFAULT_SOCKET_TIMEOUT)
        try:
            sock.connect((host, port))
            return sock
        except Exception as e:
            logger.error(f"Error creating connection to {host}:{port}: {e}")
            utils.close_socket(sock)
            return None

    def return_connection(self, host, port, sock):
        """Return a connection to the pool."""
        key = (host, port)

        with self.lock:
            if key not in self.pool:
                self.pool[key] = []

            if len(self.pool[key]) < self.max_size:
                self.pool[key].append(sock)
            else:
                utils.close_socket(sock)
