import logging
import socket
import threading
import time
import dns.resolver
from typing import Dict, List, Tuple

from src.common import constants as const, utils
from src.config import config


logger = logging.getLogger(__name__)


class ConnectionPool:
    """Pool of reusable connections."""

    def __init__(
        self,
        max_size=config.get(const.KEY_POOL, const.KEY_MAX_SIZE, 100),
        dns_cache_ttl=config.get(const.KEY_POOL, const.KEY_DNS_CACHE_TTL, 300),
    ):
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

        if config.get(const.KEY_POOL, const.KEY_DISABLE_DNS_CACHE, False):
            # Skip cache check
            return hostname

        # Check DNS cache
        with self.dns_lock:
            now = utils.get_current_time()
            if hostname in self.dns_cache:
                ip, timestamp = self.dns_cache[hostname]
                if now - timestamp < self.dns_cache_ttl:
                    return ip

        # Try to resolve with default DNS (system default)
        ip = self._try_resolve_with_dns(hostname)
        if ip:
            with self.dns_lock:
                self.dns_cache[hostname] = (ip, now)
            return ip
        # If default DNS fails, try with alternative DNS servers
        alt_dns_servers = config.get(
            const.KEY_POOL,
            const.KEY_DNS_SERVERS,
            const.DEFAULT_DNS_SERVERS,
        )

        for dns_server in alt_dns_servers:
            ip = self._try_resolve_with_dns(hostname, dns_server)
            if ip:
                with self.dns_lock:
                    self.dns_cache[hostname] = (ip, now)
                return ip

        # If all DNS servers fail, log and return the original hostname
        logger.error(f"All DNS resolution attempts failed for {hostname}")
        return hostname

    def _try_resolve_with_dns(self, hostname, dns_server=None):
        """
        Try to resolve hostname using a specific DNS server with retries.

        Args:
            hostname: Domain name to resolve
            dns_server: DNS server to use (None for system default)

        Returns:
            str or None: Resovled IP address or None if resolution fails
        """
        resolver = dns.resolver.Resolver()
        if dns_server:
            resolver.nameservers = [dns_server]

        # Retry logic
        retries = config.get(const.KEY_POOL, const.KEY_DNS_RETRIES, 3)
        for attempt in range(retries):
            try:
                if attempt > 0:
                    logger.info(f"DNS resolution retry {attempt} for {hostname}")

                # Set a shorter timeout for retries
                resolver.timeout = (
                    config.get(const.KEY_POOL, const.KEY_DNS_TIMEOUT, 1.0)
                    + attempt * 0.5
                )  # Increase timeout with each retry

                answers = resolver.query(hostname, "A")
                for rdata in answers:
                    ip = rdata.address
                    logger.debug(
                        f"Resolved {hostname} to {ip} using {dns_server if dns_server else 'system DNS'}"
                    )
                    return ip
            except dns.resolver.NXDOMAIN:
                # Domain doesn't exist - don't retry
                logger.error(f"Domain {hostname} does not exist")
                break
            except dns.resolver.NoAnswer:
                # No A records - try AAAA
                try:
                    answers = resolver.query(hostname, "AAAA")
                    for rdata in answers:
                        ip = rdata.address
                        logger.debug(f"Resolved {hostname} to IPv6 {ip}")
                        return ip
                except Exception:
                    pass
                break
            except (dns.resolver.Timeout, dns.resolver.NoNameservers) as e:
                logger.warning(
                    f"DNS resolution attempt {attempt +1} failed for {hostname}: {e}"
                )
                time.sleep(0.1 * (attempt + 1))  # Short exponential backoff
            except Exception as e:
                logger.error(f"Unsupported DNS error: {e}")
                break

        return None

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
                sock = self.pool[key].pop()
                # Verify that the socket is still valid
                if self._is_socket_valid(sock):
                    logger.debug("Reuse socket from pool")
                    return sock
                else:
                    logger.debug("Discarding invalid socket from pool")
                    utils.close_socket(sock)

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

    def _is_socket_valid(self, sock: socket.socket):
        """
        Check if a socket is still valid and connected.

        Args:
            sock: Socket to check

        Returns:
            bool: True if socket is valid
        """
        try:
            # Set socket to non-blocking
            is_blocking = sock.getblocking()
            sock.setblocking(False)

            # Try to read data - if connected but no data, this will raise EWOULDBLOCK
            # If disconnected, it will return empty data or raise an error
            data = sock.recv(1, socket.MSG_PEEK)

            # Restore blocking state
            sock.setblocking(is_blocking)

            # Empty data means the connection is closed
            if len(data) == 0:
                return False

            # If we get here without an exception, the socket is likely invalid
            # Since we would expect either an exception or empty data for a valid idle socket
            return False
        except BlockingIOError:
            # This is expected for a valid connected socket with no pending data
            return True
        except (ConnectionError, socket.error):
            # Socket has an error
            return False
        finally:
            # Restore blocking state if an exception occurred
            try:
                sock.setblocking(is_blocking)
            except:
                pass

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
