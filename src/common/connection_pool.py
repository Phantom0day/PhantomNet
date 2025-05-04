import logging
import socket
import threading
from typing import Dict, List, Tuple

from src.common import constants as const, utils


logger = logging.getLogger(__name__)


class ConnectionPool:
    """Pool of reusable connections."""

    def __init__(self, max_size=100, dns_cache_ttl=300):
        """
        Initialize the connection pool.

        Args:
            max_size: Maximum connections per destination
            dns_cache_ttl: DNS cache time-to-live in seconds
        """
        self.max_size = max_size
        self.dns_cache_ttl = dns_cache_ttl
        self.pool: Dict[tuple, List] = {}  # {(host, port): [connections]}
        self.dns_cache: Dict[str, Tuple[str, float]] = {}  # {domain: (ip, timestamp)}
        self.lock = threading.Lock()
        self.dns_lock = threading.Lock()

    def _resolve_hostname(self, hostname: str) -> str:
        """
        Resolve hostname to IP address with caching.

        Args:
            hostname: Domain name to resolve

        Returns:
            str: Resolved IP address
        """
        # If it's already an IP address, return it
        try:
            socket.inet_aton(hostname)  # check if valid IPv4
            return hostname
        except socket.error:
            pass

        try:
            socket.inet_pton(socket.AF_INET6, hostname)  # check if valid IPv6
            return hostname
        except socket.error:
            pass

        # Check DNS cache
        with self.dns_lock:
            now = utils.get_current_time()
            if hostname in self.dns_cache:
                ip, timestamp = self.dns_cache[hostname]
                if now - timestamp < self.dns_cache_ttl:
                    return ip

            # Resolve domain
            try:
                ip = socket.gethostbyname(hostname)
                self.dns_cache[hostname] = (ip, now)
                return ip
            except socket.gaierror as e:
                logger.error(f"DNS resolution failed for {hostname}: {e}")
                return hostname  # Return original if resolution fails

    def get_connection(self, host, port):
        """
        Get a connection from the pool or create a new one.
        
        Args:
            host: Hostname or IP
            port: Port number
            
        Returns:
            socket.socket or None: Socket if successful connection
        
        """
        ip = self._resolve_hostname(host)
        key = (ip, port)

        with self.lock:
            if key in self.pool and self.pool[key]:
                logger.info("Reuse socket from pool")
                return self.pool[key].pop()

        # Create new connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(const.DEFAULT_SOCKET_TIMEOUT)
        try:
            sock.connect((ip, port))
            return sock
        except Exception as e:
            logger.error(f"Error creating connection to {host}({ip}):{port}: {e}")
            utils.close_socket(sock)
            return None

    def return_connection(self, host, port, sock):
        """
        Return a connection to the pool.
        
        Args:
            host: Hostname or IP
            port: Port number
            sock: Socket to return to the pool
        """
        ip = self._resolve_hostname(host)
        key = (ip, port)

        with self.lock:
            if key not in self.pool:
                self.pool[key] = []

            if len(self.pool[key]) < self.max_size:
                self.pool[key].append(sock)
            else:
                utils.close_socket(sock)
