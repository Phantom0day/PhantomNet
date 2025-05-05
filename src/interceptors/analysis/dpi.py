import os
import random
from src.core import BaseInterceptor, ProtocolContext


class DPIEvasionInterceptor(BaseInterceptor):
    """Evades DPI by altering packet characteristics"""

    def __init__(self, target_entropy=7.2, tcp_split=True):
        self.target_entropy = target_entropy
        self.tcp_split = tcp_split

    def post_process(self, context: ProtocolContext) -> ProtocolContext:
        # Apply entropy adjustment
        modified_data = self._adjust_entropy(context.response_data)

        # If TCP segment splitting is enabled, mark for splitting
        if self.tcp_split:
            context.metadata["tcp_split"] = True
            context.metadata["tcp_split_size"] = random.randint(32, 128)

        context.processed_response = modified_data
        return context

    def _adjust_entropy(self, data: bytes) -> bytes:
        # Calculate current entropy
        current_entropy = self._calculate_entropy(data)

        # Adjust if needed
        if abs(current_entropy - self.target_entropy) > 0.5:
            # Add padding to reach target entropy
            return self._add_entropy_padding(data, self.target_entropy)
        return data
