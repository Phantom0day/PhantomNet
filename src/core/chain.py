from typing import List
from src.core import ProtocolContext


class InterceptorChain:
    def __init__(self, interceptors: List):
        self.interceptors = interceptors

    def proceed(self, ctx: ProtocolContext) -> ProtocolContext:
        if not self.interceptors:
            return ctx

        def create_next(idx):
            if idx >= len(self.interceptors):
                return lambda c: c
            current = self.interceptors[idx]
            next_fn = create_next(idx + 1)
            return lambda c: current.intercept(c, next_fn)

        return create_next(0)(ctx)
