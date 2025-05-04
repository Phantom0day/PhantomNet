import random
from src.core.context import ProtocolContext
from src.core.interceptor import BaseInterceptor


class ObfuscationInterceptor(BaseInterceptor):
    """traffic obfuscator"""

    def pre_process(self, context: ProtocolContext) -> ProtocolContext:
        context.processed_request = self._deobfuscate(context.request_data)
        return context

    def post_process(self, context: ProtocolContext) -> ProtocolContext:
        context.processed_response = self._obfuscate(context.response_data)
        return context

    def _obfuscate(self, data: bytes) -> bytes:
        # example: add random fill
        return b"\x00\xff" + data + b"\xff\x00"

    def _deobfuscate(self, data: bytes) -> bytes:
        return data[2:-2]


class ProtocolObfuscationInterceptor(BaseInterceptor):
    """Obfuscates the SOCKS5 protocol to avoid detection"""

    def __init__(self, obfuscation_mode="random"):
        self.obfuscation_mode = obfuscation_mode
        self.obfuscation_methods = {
            "random_padding": self._add_random_padding,
            "http_header": self._add_http_header,
            "tls_mimicry": self._add_tls_mimicry,
        }

    def pre_process(self, context: ProtocolContext) -> ProtocolContext:
        # For incomming data, extract the real payload
        if self._is_obfuscated(context.request_data):
            context.processed_request = self._deobfuscate(context.request_data)
        return context

    def post_process(self, context: ProtocolContext) -> ProtocolContext:
        # For outgoing data, apply obfuscation
        method = self.obfuscation_mode
        if method == "random":
            # Choose a random method
            method = random.choice(list(self.obfuscation_methods.keys()))

        obfuscator = self.obfuscation_methods.get(method, self._add_random_padding)
        context.processed_response = obfuscator(context.response_data)
        return context

    def _is_obfuscated(self, data: bytes) -> bytes:
        pass

    def _deobfuscate(self, data: bytes) -> bytes:
        pass

    def _add_random_padding(self, data: bytes) -> bytes:
        pass
