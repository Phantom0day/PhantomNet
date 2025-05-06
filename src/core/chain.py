from typing import List
from src.core import ProtocolContext
from src.interceptors import BaseInterceptor


class InterceptorChain:
    def __init__(self, interceptors: List[BaseInterceptor], reverse=False):
        self.interceptors = interceptors
        self.reverse: bool = reverse

    def proceed(self, ctx: ProtocolContext) -> ProtocolContext:
        if not self.interceptors:
            return ctx

        def create_next(idx):
            if idx >= len(self.interceptors):
                return lambda c: c
            current: BaseInterceptor = self.interceptors[idx]
            next_fn = create_next(idx + 1)
            return lambda c: current.intercept(c, self.reverse, next_fn)

        return create_next(0)(ctx)
