from src.core import BaseInterceptor, ProtocolContext


class ZeroCopyInterceptor(BaseInterceptor):
    """Zero copy optimization"""

    def post_process(self, context: ProtocolContext) -> ProtocolContext:
        context.processed_response = memoryview(context.response_data)
        return context
