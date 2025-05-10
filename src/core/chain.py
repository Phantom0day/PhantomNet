from typing import List
from src.core.context import ProtocolContext, Operation


class InterceptorChain:
    def __init__(self, interceptors: List):
        self.interceptors = interceptors

    def run(self, ctx: ProtocolContext) -> ProtocolContext:
        chain = (
            self.interceptors
            if ctx.operation is Operation.PACK
            else reversed(self.interceptors)
        )

        for it in chain:
            ctx = it.handle(ctx)
            if ctx.drop:
                break
        return ctx
