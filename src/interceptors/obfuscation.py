from .core import BaseInterceptor
from Crypto.Util.strxor import strxor


class ObfuscationInterceptor(BaseInterceptor):
    """Simple traffic obfuscator"""

    def __init__(self, prefix=b"\x00\xff", suffix=b"\xff\x00"):
        self.prefix = prefix.encode() if isinstance(prefix, str) else prefix
        self.suffix = suffix.encode() if isinstance(suffix, str) else suffix
        self.salt = prefix + suffix
        if isinstance(self.salt, str):
            self.salt = self.salt.encode()

    async def pack(self, ctx):
        data = ctx.data
        if data and len(data) >= len(self.salt):
            ctx.data = (
                strxor(self.salt, data[: len(self.salt)]) + data[len(self.salt) :]
            )
        return ctx

    async def unpack(self, ctx):
        data = ctx.data
        if data and len(data) >= len(self.salt):
            ctx.data = (
                strxor(self.salt, data[: len(self.salt)]) + data[len(self.salt) :]
            )
        return ctx
