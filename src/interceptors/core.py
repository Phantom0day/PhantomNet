from abc import ABC
from src.core import *
from src.utils.constants import *
from src.utils import *


class BaseInterceptor(ABC):
    """Base interceptor interface"""

    async def handle(
        self,
        ctx: ProtocolContext,
    ) -> ProtocolContext:
        task = self.pack(ctx) if ctx.operation is Operation.PACK else self.unpack(ctx)
        return await task

    async def pack(self, ctx: ProtocolContext) -> ProtocolContext:
        """process C2S traffic"""
        return ctx

    async def unpack(self, ctx: ProtocolContext) -> ProtocolContext:
        """process S2C traffic"""
        return ctx
