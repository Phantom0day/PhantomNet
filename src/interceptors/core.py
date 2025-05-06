import errno
import socket
from src.core import ProtocolContext
from src.utils.constants import *
from src.utils import *


class BaseInterceptor:
    """Base interceptor interface"""

    def intercept(
        self,
        ctx: ProtocolContext,
        reverse: bool,
        next_fn,
    ) -> ProtocolContext:
        ctx = self.pack(ctx) if not reverse else self.unpack(ctx)
        if ctx.drop:
            return ctx

        ctx = next_fn(ctx)
        if ctx.drop:
            return ctx

        return self.unpack(ctx) if not reverse else self.pack(ctx)

    def pack(self, ctx: ProtocolContext) -> ProtocolContext:
        """process inbound traffic"""
        return ctx

    def unpack(self, ctx: ProtocolContext) -> ProtocolContext:
        """process outbound traffic"""
        return ctx
