from typing import Callable, List
from src.core import ProtocolContext


class InterceptorChain:
    def __init__(self, interceptors: List[Callable]):
        self.interceptors = interceptors
        self.position = 0

    def proceed(self, context: ProtocolContext) -> ProtocolContext:
        if self.position >= len(self.interceptors):
            return context

        interceptor = self.interceptors[self.position]
        self.position += 1

        try:
            return interceptor(context, self)
        except Exception as e:
            context.error = e
            context.should_drop = True
            return context
