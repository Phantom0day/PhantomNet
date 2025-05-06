import errno
import logging
import select
import socket
from typing import Optional, Tuple, List

from src.core import *
from src.interceptors import BaseInterceptor
from src.utils import *

log = logging.getLogger(__name__)


class BaseProxy:
    """Base class for proxy operations"""

    def __init__(
        self,
        interceptors: Optional[List[BaseInterceptor]] = None,
        is_server=False,
        buffer_size=10 * 1024 * 1024,
    ):
        self.interceptors = interceptors or []
        self.running = False
        self.clients = set()  # Track active clients
        self.is_server = is_server
        self.chain = InterceptorChain(self.interceptors, self.is_server)
        self.MAX_BUFFER = buffer_size

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

                        result = ctx
                        # Client -> Remote
                        if s is client:
                            ctx.req_data = data
                            ctx.resp_data = b""
                        # Remote -> Client
                        else:
                            ctx.req_data = b""
                            ctx.resp_data = data

                        self._forward_data(ctx)

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
                    result = self._forward_data(ctx)
                    if result.drop:
                        return

        except Exception as e:
            if addr:
                log.error(f"Error in proxy_data for {addr[0]}:{addr[1]}: {e}")
            else:
                log.error(f"Error in proxy_data: {e}")
        finally:
            pass

    def _forward_data(self, ctx):
        if ctx.stage != "connected":
            return ctx

        # Handle remote->client data flow
        # Initialize buffers if needed
        if "c_buf" not in ctx.meta:
            ctx.meta["c_buf"] = b""
        if "r_buf" not in ctx.meta:
            ctx.meta["r_buf"] = b""

        # Try to receive from remote if needed
        if ctx.remote and not ctx.resp_data:
            try:
                ctx.resp_data = ctx.remote.recv(DEFAULT_BUFFER_SIZE)
                if ctx.resp_data == b"":  # Connection closed
                    ctx.drop = True
                    return ctx
            except socket.error as e:
                if e.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                    log.error(f"Error receiving from remote: {e}")
                    ctx.drop = True
                    return ctx

        # Process any new response data
        if ctx.resp_data:
            # Add to client buffer
            ctx.meta["c_buf"] += ctx.resp_data

            # Try to send to client
            if ctx.client and ctx.meta["c_buf"]:
                try:
                    sent = ctx.client.send(ctx.meta["c_buf"])
                    ctx.meta["c_buf"] = ctx.meta["c_buf"][sent:]
                except socket.error as e:
                    if e.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                        log.error(f"Error sending to client: {e}")
                        ctx.drop = True

            # todo Mark as processed

        # Check buffer limits
        if len(ctx.meta["c_buf"]) > self.MAX_BUFFER:
            log.error("Client buffer overflow")
            ctx.drop = True

        # Handle client->remote data flow
        # Process any new request data
        if ctx.req_data:
            # Add to the remote buffer
            ctx.meta["r_buf"] += ctx.req_data

            # Try to send data to remote
            if ctx.remote and ctx.meta["r_buf"]:
                try:
                    sent = ctx.remote.send(ctx.meta["r_buf"])
                    ctx.meta["r_buf"] = ctx.meta["r_buf"][sent:]
                except socket.error as e:
                    if e.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                        log.error(f"Error sending to remote: {e}")
                        ctx.drop = True

            # todo Mark as processed

        # Check buffer limits
        if len(ctx.meta["r_buf"]) > self.MAX_BUFFER:
            log.error("Remote buffer overflow")
            ctx.drop = True

        return ctx
