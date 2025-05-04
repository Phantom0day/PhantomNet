import struct
from src.core import BaseInterceptor, ProtocolContext


class VideoCamouflageInterceptor(BaseInterceptor):
    """Video camouflage"""

    def post_process(self, context):
        # add video feature
        header = struct.pack("!I", len(context.response_data))
        context.processed_response = header + context.response_data
        context.metadata["content_type"] = "video/mp4"
        return context
