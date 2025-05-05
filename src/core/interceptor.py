from src.core.context import ProtocolContext
from src.core.chain import InterceptorChain


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
