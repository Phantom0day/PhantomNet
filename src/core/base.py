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
        self.MAX_BUFFER_SIZE = 20 * 1024 * 1024  # 20 MB max buffer

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

        # Buffers for data that couldn't be sent immediately
        client_buffer = b""
        remote_buffer = b""

        try:
            while self.running:
                # Determine which sockets to monitor
                rlist = [client_sock, remote_sock]
                wlist = []

                # Add sockets to write list if we have data buffered for them
                if client_buffer:
                    wlist.append(client_sock)
                if remote_buffer:
                    wlist.append(remote_sock)

                # Wait for socket activity with timeout
                try:
                    r, w, e = select.select(
                        rlist, wlist, [client_sock, remote_sock], 1.0
                    )
                except (select.error, socket.error) as e:
                    log_prefix = f"[{addr[0]}:{addr[1]}] " if addr else ""
                    logger.error(f"{log_prefix}Select error: {e}")
                    break

                # Error events
                if client_sock in e or remote_sock in e:
                    if addr:
                        logger.debug(
                            f"Socket error in proxy_data for {addr[0]}:{addr[1]}"
                        )
                    else:
                        logger.debug("Socket error detected")
                    break

                # Read events
                for s in r:
                    try:
                        data = s.recv(DEFAULT_BUFFER_SIZE)
                        if not data:
                            # Connection closed by one side
                            return

                        # Determine which direction the data is flowing
                        is_client_to_remote = s is client_sock

                        # Process through interceptor chain
                        context = ProtocolContext(
                            client_socket=client_sock,
                            remote_socket=remote_sock,
                            protocol_stage="connected",
                        )

                        if is_client_to_remote:
                            context.request_data = data
                        else:
                            context.response_data = data

                        chain = InterceptorChain(self.interceptor_wrappers)
                        result = chain.proceed(context)

                        if result.should_drop:
                            return

                        # Queue processed data for sending
                        if is_client_to_remote:
                            # Use processed request if available, otherwise original data
                            send_data = (
                                result.processed_request
                                if result.processed_request
                                else data
                            )
                            remote_buffer += send_data
                        else:
                            # Use processed response if available, otherwise original data
                            send_data = (
                                result.processed_response
                                if result.processed_response
                                else data
                            )
                            client_buffer += send_data

                        # Check buffer size limits
                        if (
                            len(client_buffer) > self.MAX_BUFFER_SIZE
                            or len(remote_buffer) > self.MAX_BUFFER_SIZE
                        ):
                            logger.error("Buffer overflow, closing connection")
                            return

                    except ConnectionError:
                        return
                    except socket.error as e:
                        # Only break the loop if it's not EAGAIN/EWOULDBLOCK
                        if e.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                            logger.error(f"Socket read error: {e}")
                            return

                # Write events - send buffered data
                for s in w:
                    try:
                        if s is client_sock and client_buffer:
                            # Send data to client
                            sent = s.send(client_buffer)
                            # Remove sent data from buffer
                            client_buffer = client_buffer[sent:]
                        elif s is remote_sock and remote_buffer:
                            # Send data to remote
                            sent = s.send(remote_buffer)
                            # Remove sent data from buffer
                            remote_buffer = remote_buffer[sent:]
                    except socket.error as e:
                        # Ignore EAGAIN/EWOULDBLOCK - will try again later
                        if e.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                            logger.error(f"Socket write error: {e}")
                            return

        except Exception as e:
            if addr:
                logger.error(f"Error in proxy_data for {addr[0]}:{addr[1]}: {e}")
            else:
                logger.error(f"Error in proxy_data: {e}")
        finally:
            # Don't close sockets here; let the caller do it
            pass
