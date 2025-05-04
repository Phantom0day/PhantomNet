import random
from src.core import BaseInterceptor, ProtocolContext


class BehaviorSimulatorInterceptor(BaseInterceptor):
    """simulate normal application behavior"""

    def post_process(self, context: ProtocolContext) -> ProtocolContext:
        # Add video stream headers
        if context.metadata.get("content_type") == "video":
            context.processed_response = self._add_video_headers(context.response_data)
        # simulate http downloading
        elif random.random() < 0.3:
            context.processed_response = self._simulate_http_chunked(
                context.response_data
            )
        return context
