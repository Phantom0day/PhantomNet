from abc import ABC
import errno
import socket
from src.core import *
from src.utils.constants import *
from src.utils import *


class BaseInterceptor(ABC):
    """Base interceptor interface"""

    def handle(
        self,
        ctx: ProtocolContext,
    ) -> ProtocolContext:
        return self.pack(ctx) if ctx.operation is Operation.PACK else self.unpack(ctx)

    def pack(self, ctx: ProtocolContext) -> ProtocolContext:
        """process C2S traffic"""
        return ctx

    def unpack(self, ctx: ProtocolContext) -> ProtocolContext:
        """process S2C traffic"""
        return ctx
