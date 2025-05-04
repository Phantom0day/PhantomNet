from src.core import BaseInterceptor, ProtocolContext


class QuicCamouflageInterceptor(BaseInterceptor):
    """Quic protocol camouflage"""

    def pre_process(self, context: ProtocolContext) -> ProtocolContext:
        return super().pre_process(context)
