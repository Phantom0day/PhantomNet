from src.core.interceptor import BaseInterceptor


class TLSCamouflageInterceptor(BaseInterceptor):
    """Makes traffic appear as legitimate TLS"""

    def pre_process(self, context):
        # If data appears to be a Client Hello, extract the real payload
        if self._looks_like_client_hello(context.request_data):
            real_payload = self._extract_from_fake_tls(context.request_data)
            context.processed_request = real_payload
        return context

    def post_process(self, context):
        # Wrap response in fake TLS records
        context.processed_response = self._wrap_in_tls_record(
            content_type=23,  # Application data
            version=0x0303,  # TLS 1.2
            payload=context.response_data,
        )
        return context
