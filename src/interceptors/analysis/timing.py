import random
import time
from src.core import BaseInterceptor, ProtocolContext


class TimingInterceptor(BaseInterceptor):
    """Adds timing variations to traffic"""

    def pre_process(self, context):
        # Random small delay before processing
        if random.random() < 0.3:
            time.sleep(random.uniform(0.01, 0.1))
        return context

    def post_process(self, context: ProtocolContext) -> ProtocolContext:
        size = len(context.response_data)
        # More likely to add delay for larger packets
        if size > 1000 and random.random() < 0.4:
            time.sleep(random.uniform(0.02, 0.15))
        return context
