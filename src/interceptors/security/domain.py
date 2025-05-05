from src.core.context import ProtocolContext
from src.core.interceptor import BaseInterceptor


class DomainFrontingInterceptor(BaseInterceptor):
    """Implements domain fronting technique"""

    def __init__(self, front_domain="cdn.example.com"):
        self.front_domain = front_domain

    def pre_process(self, context: ProtocolContext) -> ProtocolContext:
        if context.metadata.get("camouflage") == "http":
            # Modify the Host header while keeping the SNI intact
            context.processed_request = self._modify_host_header(
                context.request_data,
                self.front_domain,
            )
        return context
