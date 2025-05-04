from src.core import BaseInterceptor, ProtocolContext


class HTTPCamouflageInterceptor(BaseInterceptor):
    """HTTP protocol camouflage"""

    def pre_process(self, context: ProtocolContext) -> ProtocolContext:
        if context.request_data.startswith(b"GET"):
            # extract real payload
            payload = self._extract_http_payload(context.request_data)
            context.processed_request = payload
            context.metadata["camouflage"] = "http"
        return context

    def post_process(self, context):
        if context.metadata.get("camouflage") == "http":
            # wrap with http response
            context.processed_response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/octet-stream\r\n\r\n"
                + context.response_data,
            )
        return context

    def _extract_http_payload(self, data: bytes) -> bytes:
        pass
