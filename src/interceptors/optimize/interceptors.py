from src.core import BaseInterceptor, ProtocolContext


class ConnectionPoolInterceptor(BaseInterceptor):
    """Connection reuse interceptor"""

    def __init__(self):
        self.pool = ConnectionPool(max_size=100)

    def pre_process(self, context: ProtocolContext) -> ProtocolContext:
        dest = (context.dest_addr, context.dest_port)
        context.remote = self.pool.acquire(dest)
        return context

    def post_process(self, context):
        self.pool.release(context.remote)
        return context


class ZeroCopyInterceptor(BaseInterceptor):
    """Zero copy optimization"""

    def post_process(self, context: ProtocolContext) -> ProtocolContext:
        context.proc_resp = memoryview(context.resp_data)
        return context
