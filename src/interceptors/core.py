import errno
import socket
from src.core import BaseInterceptor, ProtocolContext
from src.utils.constants import *
from src.utils import *


class BaseInterceptor:
    """Base interceptor interface"""

    def intercept(self, ctx: ProtocolContext, next_fn) -> ProtocolContext:
        ctx = self.pre_process(ctx)
        if ctx.drop:
            return ctx

        ctx = next_fn(ctx)
        if ctx.drop:
            return ctx

        return self.post_process(ctx)

    def pre_process(self, ctx: ProtocolContext) -> ProtocolContext:
        """process inbound traffic"""
        return ctx

    def post_process(self, ctx: ProtocolContext) -> ProtocolContext:
        """process outbound traffic"""
        return ctx


class DataForwardingInterceptor(BaseInterceptor):
    """Handles data forwarding between client and remote sockets"""

    def __init__(self, buffer_size=10 * 1024 * 1024):
        self.MAX_BUFFER = buffer_size

    def pre_process(self, ctx):
        """Handle client->remote data flow"""
        if ctx.stage != "connected":
            return ctx

        # Initialize buffers if needed
        if "c_buf" not in ctx.meta:
            ctx.meta["c_buf"] = b""
        if "r_buf" not in ctx.meta:
            ctx.meta["r_buf"] = b""

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

            # Mark as processed
            ctx.proc_req = b""

        # Check buffer limits
        if len(ctx.meta["r_buf"]) > self.MAX_BUFFER:
            log.error("Remote buffer overflow")
            ctx.drop = True

        return ctx

    def post_process(self, ctx):
        """Handle remote->client data flow"""
        if ctx.stage != "connected":
            return ctx

        # Initialize buffers if needed
        if "c_buf" not in ctx.meta:
            ctx.meta["c_buf"] = b""
        if "r_buf" not in ctx.meta:
            ctx.meta["r_buf"] = b""

        # Try to receive from remote if needed
        if ctx.remote and not ctx.resp_data:
            try:
                data = ctx.remote.recv(DEFAULT_BUFFER_SIZE)
                if data:
                    ctx.resp_data = data
                elif data == b"":  # Connection closed
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

            # Mark as processed
            ctx.proc_resp = b""

        # Check buffer limits
        if len(ctx.meta["c_buf"]) > self.MAX_BUFFER:
            log.error("Client buffer overflow")
            ctx.drop = True

        return ctx
