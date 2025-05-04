from src.core.interceptor import BaseInterceptor
from src.core.context import ProtocolContext


class ConnectionPoolInterceptor(BaseInterceptor):
    """Connection reuse interceptor"""

    def __init__(self):
        self.pool = ConnectionPool(max_size=100)

    def pre_process(self, context: ProtocolContext) -> ProtocolContext:
        dest = (context.dest_addr, context.dest_port)
        context.remote_socket = self.pool.acquire(dest)
        return context

    def post_process(self, context):
        self.pool.release(context.remote_socket)
        return context
