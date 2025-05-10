import struct
import random
import time
import os
from src.core import ProtocolContext
from src.interceptors.core import BaseInterceptor
from Crypto.Util.strxor import strxor


class ObfuscationInterceptor(BaseInterceptor):
    """Simple traffic obfuscator"""

    def __init__(self, prefix=b"\x00\xff", suffix=b"\xff\x00"):
        self.prefix = prefix.encode() if isinstance(prefix, str) else prefix
        self.suffix = suffix.encode() if isinstance(suffix, str) else suffix
        self.salt = prefix + suffix
        if isinstance(self.salt, str):
            self.salt = self.salt.encode()

    def pack(self, ctx):
        data = ctx.data
        if data and len(data) >= len(self.salt):
            ctx.data = (
                strxor(self.salt, data[: len(self.salt)]) + data[len(self.salt) :]
            )
        return ctx

    def unpack(self, ctx):
        data = ctx.data
        if data and len(data) >= len(self.salt):
            ctx.data = (
                strxor(self.salt, data[: len(self.salt)]) + data[len(self.salt) :]
            )
        return ctx