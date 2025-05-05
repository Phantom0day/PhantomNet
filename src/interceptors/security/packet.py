import os
from src.core.context import ProtocolContext
from src.core.interceptor import BaseInterceptor


class PacketSizeNormalizer(BaseInterceptor):
    """Normalizes packet sizes to avoid traffic fingerprinting"""

    def __init__(self, target_sizes=(64, 256, 512, 1024)):
        self.target_sizes = target_sizes

    def post_process(self, context):
        data = context.response_data
        data_len = len(data)

        # Find the smallest target size that fits the data
        target_size = next(
            (s for s in self.target_sizes if s >= data_len), self.target_sizes[-1]
        )

        # Pad to target size
        if data_len < target_size:
            padding = os.urandom(target_size - data_len)
            context.processed_response = data + padding
        else:
            # Split into multiple packets of target sizes
            chunks = []
            for i in range(0, data_len, self.target_sizes[-1]):
                chunk = data[i : i + self.target_sizes[-1]]
                if len(chunk) < self.target_sizes[-1]:
                    chunk += os.urandom(self.target_sizes[-1] - len(chunk))
                chunks.append(chunk)

            context.processed_response = b"".join(chunks)
        return context
