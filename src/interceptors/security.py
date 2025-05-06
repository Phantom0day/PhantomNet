import os
import hmac
import time
import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from src.interceptors.core import BaseInterceptor


class AESEncryptionInterceptor(BaseInterceptor):
    """AES encryption for traffic"""

    def __init__(self, key):
        if isinstance(key, str):
            self.key = key.encode()[:32].ljust(32, b"\0")  # Ensure 32 bytes for AES-256
        else:
            self.key = key[:32].ljust(32, b"\0")

    def pack(self, ctx):
        if ctx.resp_data:
            ctx.proc_resp = self._encrypt(ctx.resp_data)
        return ctx

    def unpack(self, ctx):
        if ctx.req_data and self._is_encrypted(ctx.req_data):
            try:
                ctx.proc_req = self._decrypt(ctx.req_data)
            except Exception as e:
                # Log error but continue with original data
                ctx.proc_req = ctx.req_data
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


class SecureHandshakeInterceptor(BaseInterceptor):
    """Implements secure authentication handshake"""

    def __init__(self, shared_secret, time_window=30):
        self.secret = (
            shared_secret.encode() if isinstance(shared_secret, str) else shared_secret
        )
        self.window = time_window

    def unpack(self, ctx):
        try:
            # Validate minimum length
            if len(ctx.req_data) < 8:
                ctx.drop = True
                return ctx

            # Extract timestamp (first 4 bytes)
            ts_bytes = ctx.req_data[:4]
            timestamp = struct.unpack("!I", ts_bytes)[0]
            current = int(time.time())

            # Validate timestamp is within time window
            if abs(current - timestamp) > self.window:
                ctx.drop = True
                return ctx

            # Verify HMAC
            provided_hmac = ctx.req_data[4:8]
            expected_hmac = self._calculate_hmac(ts_bytes)

            if not hmac.compare_digest(provided_hmac, expected_hmac):
                ctx.drop = True
                return ctx

            # Extract real payload
            ctx.proc_req = ctx.req_data[8:]

        except Exception:
            ctx.drop = True

        return ctx

    def _calculate_hmac(self, data):
        h = hmac.new(self.secret, data, "sha256")
        return h.digest()[:4]  # Use first 4 bytes of HMAC


class PacketSizeNormalizer(BaseInterceptor):
    """Normalizes packet sizes to prevent traffic analysis"""

    def __init__(self, target_sizes=(64, 256, 512, 1024)):
        self.sizes = target_sizes

    def pack(self, ctx):
        if not ctx.resp_data:
            return ctx

        data_len = len(ctx.resp_data)

        # Find target size
        target = next((s for s in self.sizes if s >= data_len), self.sizes[-1])

        if data_len <= target:
            # Pad to target size
            padding = os.urandom(target - data_len)
            ctx.proc_resp = ctx.resp_data + padding
        else:
            # Split into multiple chunks of target size
            chunks = []
            for i in range(0, data_len, self.sizes[-1]):
                chunk = ctx.resp_data[i : i + self.sizes[-1]]
                if len(chunk) < self.sizes[-1]:
                    chunk += os.urandom(self.sizes[-1] - len(chunk))
                chunks.append(chunk)

            ctx.proc_resp = b"".join(chunks)

        return ctx
