import struct
from .core import BaseInterceptor


class LengthPrefixFramer(BaseInterceptor):
    def pack(self, ctx):
        if ctx.data:
            payload = ctx.data
            ctx.data = struct.pack("!H", len(payload)) + payload
        return ctx

    def unpack(self, ctx):
        cache = ctx.meta.get("lp_cache", b"") + ctx.data
        frame, length = b"", 0

        if len(cache) >= 2:
            length = struct.unpack("!H", cache[:2])[0]
            if len(cache) - 2 >= length:
                frame = cache[2 : 2 + length]
                ctx.meta["lp_cache"] = cache[length + 2 :]
            else:
                ctx.meta["lp_cache"] = cache
        ctx.data = frame
        return ctx
