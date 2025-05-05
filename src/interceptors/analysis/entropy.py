import os
import random
from src.core import BaseInterceptor, ProtocolContext


class EntropyAdjustmentInterceptor(BaseInterceptor):
    """traffic entropy adjustment"""

    def post_process(self, context: ProtocolContext) -> ProtocolContext:
        original = context.response_data
        # Add random padding
        padded = original + os.urandom(random.randint(0, 256))
        # random packet size
        chunked = [
            padded[i : i + random.randint(128, 1024)]
            for i in range(0, len(padded), 1024)
        ]
        context.processed_response = b"".join(chunked)
        return context
