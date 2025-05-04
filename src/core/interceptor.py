from src.core import ProtocolContext, InterceptorChain


class BaseInterceptor:
    """Base class for interceptors"""

    def intercept(
        self,
        context: ProtocolContext,
        chain: InterceptorChain,
    ) -> ProtocolContext:
        # Pre process
        context = self.pre_process(context)

        # pass to next interceptor
        next_context = chain.proceed(context)

        # post process
        return self.post_process(next_context)

    def pre_process(self, context: ProtocolContext) -> ProtocolContext:
        """process inbound traffic"""
        return context

    def post_process(self, context: ProtocolContext) -> ProtocolContext:
        """process outbound traffic"""
        return context
