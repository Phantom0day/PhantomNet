from typing import List
from .context import ProtocolContext, Operation


class InterceptorChain:
    def __init__(self, interceptors: List):
        self.interceptors = interceptors

    async def run(self, ctx: ProtocolContext) -> ProtocolContext:
        chain = (
            self.interceptors
            if ctx.operation is Operation.PACK
            else reversed(self.interceptors)
        )

        for it in chain:
            ctx = await it.handle(ctx)
            if ctx.drop:
                break
        return ctx
