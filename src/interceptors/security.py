import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from .core import BaseInterceptor


class AESEncryptionInterceptor(BaseInterceptor):
    """AES encryption for traffic"""

    def __init__(self, key):
        if isinstance(key, str):
            self.key = key.encode()[:32].ljust(32, b"\0")  # Ensure 32 bytes for AES-256
        else:
            self.key = key[:32].ljust(32, b"\0")

    async def pack(self, ctx):
        data = ctx.data
        if data:
            ctx.data = self._encrypt(data)
        return ctx

    async def unpack(self, ctx):
        data = ctx.data
        if data and self._is_encrypted(data):
            try:
                ctx.data = self._decrypt(data)
            except Exception as e:
                # Log error but continue with original data
                pass
        return ctx

    def _is_encrypted(self, data):
        # Simple check for our format: [IV (16 bytes)][Encrypted Data]
        return len(data) > 16

    def _encrypt(self, data):
        iv = os.urandom(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(data, AES.block_size))
        return iv + encrypted

    def _decrypt(self, data):
        iv = data[:16]
        encrypted = data[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(encrypted), AES.block_size)


class PacketSizeNormalizer(BaseInterceptor):
    """Normalizes packet sizes to prevent traffic analysis"""

    def __init__(self, target_sizes=(64, 256, 512, 1024)):
        self.sizes = target_sizes

    async def pack(self, ctx):
        data = ctx.data
        if not data:
            return ctx

        data_len = len(data)

        # Find target size
        target = next((s for s in self.sizes if s >= data_len), self.sizes[-1])

        if data_len <= target:
            # Pad to target size
            padding = os.urandom(target - data_len)
            ctx.data = data + padding
        else:
            # Split into multiple chunks of target size
            chunks = []
            for i in range(0, data_len, self.sizes[-1]):
                chunk = data[i : i + self.sizes[-1]]
                if len(chunk) < self.sizes[-1]:
                    chunk += os.urandom(self.sizes[-1] - len(chunk))
                chunks.append(chunk)

            ctx.data = b"".join(chunks)

        return ctx
