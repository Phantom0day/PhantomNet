import logging
from src.utils import *

from src.interceptors.core import BaseInterceptor


class PacketLogger(BaseInterceptor):
    def __init__(self, log_level="info", max_length=32):
        super().__init__()
        self.log_level = getattr(logging, log_level.upper(), logging.INFO)
        self.log_enable = log.level <= self.log_level
        self.max_length = getattr(logging, log_level.upper(), logging.INFO)

    def pack(self, ctx):
        if self.log_enable:
            data = ctx.req_data[:64].hex() if ctx.req_data else ""
            log.log(self.log_level, f"PACK>>{len(data)}")
            log.log(self.log_level, f"    REQ>>{data}")
        return ctx

    def unpack(self, ctx):
        if self.log_enable:
            data = ctx.resp_data[:64].hex() if ctx.resp_data else ""
            log.log(self.log_level, f"after UNPK<<{len(data)}")
            log.log(self.log_level, f"    RESP>>{data}")
        return ctx


class PacketLogger2(BaseInterceptor):
    def __init__(self, log_level="info", max_length=32):
        super().__init__()
        self.log_level = getattr(logging, log_level.upper(), logging.INFO)
        self.log_enable = log.level <= self.log_level
        self.max_length = getattr(logging, log_level.upper(), logging.INFO)

    def pack(self, ctx):
        if self.log_enable:
            data = ctx.req_data[:64].hex() if ctx.req_data else ""
            log.log(self.log_level, f"after PACK>>{len(data)}")
            log.log(self.log_level, f"    REQ>>{data}")
        return ctx

    def unpack(self, ctx):
        if self.log_enable:
            data = ctx.resp_data[:64].hex() if ctx.resp_data else ""
            log.log(self.log_level, f"UNPK<<{len(data)}")
            log.log(self.log_level, f"    RESP>>{data}")
        return ctx
