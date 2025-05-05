import errno
import logging
import select
import socket
from typing import Optional, Tuple, List

from src.core import *
from src.utils import *

log = logging.getLogger(__name__)


class BaseProxy:
    """Base class for proxy operations"""

    def __init__(self, interceptors: Optional[List[BaseInterceptor]] = None):
        self.interceptors = interceptors or []
        self.running = False
        self.clients = set()  # Track active clients

    def stop(self):
        """Stop the proxy"""
        log.info("Stopping proxy...")
        self.running = False
        for sock in self.clients.copy():
            close_socket(sock)

    def _proxy_data(
        self,
        client: socket.socket,
        remote: socket.socket,
        addr: Optional[Tuple] = None,
    ):
        """Proxy data between client and remote"""
        client.setblocking(False)
        remote.setblocking(False)

        # Create initial context
        ctx = ProtocolContext(
            client=client,
            remote=remote,
            stage="connected",
        )

        # Initialize metadata for the interceptors
        ctx.meta["c_buf"] = b""
        ctx.meta["r_buf"] = b""

        chain = InterceptorChain(self.interceptors)
        try:
            while self.running:
                # Select sockets to monitor
                rlist = [client, remote]

                try:
                    r, _, e = select.select(rlist, [], [client, remote], 1.0)
                except (select.error, socket.error) as e:
                    log.error(f"Select error: {e}")
                    break

                # Handle errors
                if client in e or remote in e:
                    if addr:
                        log.debug(f"Socket error for {addr[0]}:{addr[1]}")
                    break

                # Handle readable sockets
                for s in r:
                    try:
                        data = s.recv(DEFAULT_BUFFER_SIZE)
                        if not data:
                            return

                        # Client -> Remote
                        if s is client:
                            ctx.req_data = data
                            ctx.resp_data = b""
                        # Remote -> Client
                        else:
                            ctx.req_data = b""
                            ctx.resp_data = data

                        # Process through interceptor chain
                        result = chain.proceed(ctx)

                        if result.drop:
                            return

                    except socket.error as e:
                        if e.errno == 10053:  # Connection aborted
                            log.debug(f"Connection closed by client: {e}")
                            return
                        if e.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                            log.error(
                                f"{'Client' if s is client else 'Remote'} socket error: {e}"
                            )
                            return

                # Process any buffered data when no new data
                if not r:
                    ctx.req_data = b""
                    ctx.resp_data = b""
                    result = chain.proceed(ctx)
                    if result.drop:
                        return

        except Exception as e:
            if addr:
                log.error(f"Error in proxy_data for {addr[0]}:{addr[1]}: {e}")
            else:
                log.error(f"Error in proxy_data: {e}")
        finally:
            pass
