import errno
import logging
import select
import socket
from typing import Optional, Tuple, List

from src.core import *
from src.utils import *

logger = logging.getLogger(__name__)


class BaseProxy:
    """Base class for proxy operations shared between client and server"""

    def __init__(self, interceptors=None):
        self.interceptors = interceptors or []
        self.interceptor_wrappers = [
            lambda ctx, chain, i=i: i.intercept(ctx, chain) for i in self.interceptors
        ]
        self.running = False
        self.clients = set()  # Track active clients

    def stop(self):
        """Stop the proxy server"""
        logger.info("Stopping proxy...")
        self.running = False
        # Close all client connections
        for client_sock in self.clients.copy():
            close_socket(client_sock)

    def _proxy_data(
        self,
        client_sock: socket.socket,
        remote_sock: socket.socket,
        addr: Optional[Tuple] = None,
    ):
        """Proxy data between two sockets with improved error handling"""
        client_sock.setblocking(False)
        remote_sock.setblocking(False)

        # Create initial context
        context = ProtocolContext(
            client_socket=client_sock,
            remote_socket=remote_sock,
            protocol_stage="connected",
        )

        # Initialize metadata for the interceptors
        context.metadata["client_buffer"] = b""
        context.metadata["remote_buffer"] = b""

        try:
            while self.running:
                # Determine which sockets to monitor
                rlist = [client_sock, remote_sock]
                wlist = []

                # Wait for socket activity
                try:
                    r, _, e = select.select(rlist, [], [client_sock, remote_sock], 1.0)
                except (select.error, socket.error) as e:
                    log_prefix = f"[{addr[0]}:{addr[1]}] " if addr else ""
                    logger.error(f"{log_prefix}Select error: {e}")
                    break

                # Handle errors
                if client_sock in e or remote_sock in e:
                    if addr:
                        logger.debug(f"Socket error for {addr[0]}:{addr[1]}")
                    else:
                        logger.debug("Socket error detected")
                    break

                # Handle readable sockets
                for s in r:
                    # Determine which direction data is flowing
                    if s is client_sock:
                        # Client -> Remote
                        try:
                            data = s.recv(DEFAULT_BUFFER_SIZE)
                            if not data:
                                # Connection closed
                                return

                            # Update context with new data
                            context.request_data = data
                            context.response_data = b""

                            # Process through interceptor chain
                            chain = InterceptorChain(self.interceptor_wrappers)
                            result = chain.proceed(context)

                            # Check if connection should be dropped
                            if result.should_drop:
                                return

                        except socket.error as e:
                            if e.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                                logger.error(f"Client socket error: {e}")
                                return
                    else:
                        # Remote -> Client
                        try:
                            data = s.recv(DEFAULT_BUFFER_SIZE)
                            if not data:
                                # Connection closed
                                return

                            # Update context with new data
                            context.request_data = b""
                            context.response_data = data

                            # Process through interceptor chain
                            chain = InterceptorChain(self.interceptor_wrappers)
                            result = chain.proceed(context)

                            # Check if connection should be dropped
                            if result.should_drop:
                                return

                        except socket.error as e:
                            if e.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                                logger.error(f"Remote socket error: {e}")
                                return

                # Run an idle cycle to let the DataForwardingInterceptor process any buffered data
                if not r:
                    context.request_data = b""
                    context.response_data = b""
                    chain = InterceptorChain(self.interceptor_wrappers)
                    result = chain.proceed(context)
                    if result.should_drop:
                        return

        except Exception as e:
            if addr:
                logger.error(f"Error in proxy_data for {addr[0]}:{addr[1]}: {e}")
            else:
                logger.error(f"Error in proxy_data: {e}")
        finally:
            # Don't close sockets here; let the caller do it
            pass
