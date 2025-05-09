import errno
import logging
import select
import socket
from typing import Optional, Tuple, List

from src.core.context import ProtocolContext
from src.core.chain import InterceptorChain, Operation
from src.utils import *


class BaseProxy:
    """Base class for proxy operations"""

    def __init__(
        self,
        interceptors: Optional[List] = None,
        is_server=False,
        buffer_size=10 * 1024 * 1024,
    ):
        self.interceptors = interceptors or []
        self.running = False
        self.clients = set()  # Track active clients
        self.is_server = is_server
        self.chain = InterceptorChain(self.interceptors)
        self.MAX_BUFFER = buffer_size

    def stop(self):
        """Stop the proxy"""
        log.info("Stopping proxy...")
        self.running = False
        for sock in self.clients.copy():
            close_socket(sock)

    def _proxy_data(
        self,
        in_sock: socket.socket,
        out_sock: socket.socket,
        addr: Optional[Tuple] = None,
    ):
        """Proxy data between client and remote"""
        in_sock.setblocking(False)
        out_sock.setblocking(False)

        # Create initial context
        ctx = ProtocolContext(
            client=in_sock,
            remote=out_sock,
            stage="connected",
        )

        # Initialize metadata for the interceptors
        ctx.meta["c_buf"] = b""
        ctx.meta["r_buf"] = b""

        try:
            while self.running:
                # Select sockets to monitor
                rlist = [in_sock, out_sock]

                try:
                    r, _, e = select.select(rlist, [], [in_sock, out_sock], 1.0)
                except (select.error, socket.error) as e:
                    log.error(f"Select error: {e}")
                    break

                # Handle errors
                if in_sock in e or out_sock in e:
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
                        if s is in_sock:
                            ctx.req_data, ctx.resp_data = data, b""
                            ctx.operation = Operation.PACK
                        # Remote -> Client
                        else:
                            ctx.req_data, ctx.resp_data = b"", data
                            ctx.operation = Operation.UNPACK

                        ctx = self.chain.run(ctx)
                        self._buffer_and_flush(ctx)

                        if ctx.drop:
                            return

                    except socket.error as e:
                        if e.errno == 10053:  # Connection aborted
                            log.debug(f"Connection closed by client: {e}")
                            return
                        if e.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                            log.error(
                                f"{'Client' if s is in_sock else 'Remote'} socket error: {e}"
                            )
                            return

                # Process any buffered data when no new data
                if not r:
                    ctx.req_data = b""
                    ctx.resp_data = b""
                    ctx = self._buffer_and_flush(ctx)
                    if ctx.drop:
                        return

        except Exception as e:
            if addr:
                log.error(f"Error in proxy_data for {addr[0]}:{addr[1]}: {e}")
            else:
                log.error(f"Error in proxy_data: {e}")
        finally:
            pass

    def _buffer_and_flush(self, ctx: ProtocolContext):
        if ctx.stage != "connected":
            return ctx

        # Initialize buffers if needed
        cb, rb = ctx.meta.setdefault("c_buf", b""), ctx.meta.setdefault("r_buf", b"")

        if ctx.req_data:
            ctx.meta["r_buf"] += ctx.req_data
            ctx.req_data = b""

        if ctx.resp_data:
            ctx.meta["c_buf"] += ctx.resp_data
            ctx.resp_data = b""

        if ctx.client and ctx.meta["c_buf"]:
            try:
                sent = ctx.client.send(ctx.meta["c_buf"])
                ctx.meta["c_buf"] = ctx.meta["c_buf"][sent:]
            except Exception:
                ctx.drop = True

        if ctx.remote and ctx.meta["r_buf"]:
            try:
                sent = ctx.remote.send(ctx.meta["r_buf"])
                ctx.meta["r_buf"] = ctx.meta["r_buf"][sent:]
            except Exception:
                ctx.drop = True

        if (
            len(ctx.meta["c_buf"]) > self.MAX_BUFFER
            or len(ctx.meta["r_buf"]) > self.MAX_BUFFER
        ):
            ctx.drop = True

        return ctx
