from src.core.context import ProtocolContext
from src.core.interceptor import BaseInterceptor


class AESEncryptionInterceptor(BaseInterceptor):
    """AES encryption interceptor"""

    def __init__(self, key: str):
        self.key = key

    def pre_process(self, context: ProtocolContext) -> ProtocolContext:
        if self._is_encrypted(context.request_data):
            context.processed_request = self._decrypt(context.request_data)
        return context

    def post_process(self, context: ProtocolContext) -> ProtocolContext:
        context.processed_response = self._encrypt(context.response_data)
        return context

    def _encrypt(self, data: bytes) -> bytes:
        pass

    def _decrypt(self, data: bytes) -> bytes:
        pass
