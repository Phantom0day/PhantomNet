import os
import random
import hmac
import time
import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from src.core import BaseInterceptor, ProtocolContext


class ObfuscationInterceptor(BaseInterceptor):
    """Simple traffic obfuscator"""

    def __init__(self, prefix=b"\x00\xff", suffix=b"\xff\x00"):
        self.prefix = prefix
        self.suffix = suffix

    def pre_process(self, ctx):
        # Check if data has our markers
        if (
            ctx.req_data
            and len(ctx.req_data) > len(self.prefix) + len(self.suffix)
            and ctx.req_data.startswith(self.prefix)
            and ctx.req_data.endswith(self.suffix)
        ):
            ctx.proc_req = ctx.req_data[len(self.prefix) : -len(self.suffix)]
        return ctx

    def post_process(self, ctx):
        if ctx.resp_data:
            ctx.proc_resp = self.prefix + ctx.resp_data + self.suffix
        return ctx


class ProtocolObfuscationInterceptor(BaseInterceptor):
    """Advanced protocol obfuscation"""

    def __init__(self, obfuscation_mode="random"):
        self.mode = obfuscation_mode
        self.methods = {
            "random_padding": self._add_random_padding,
            "http_header": self._add_http_header,
            "tls_mimicry": self._add_tls_mimicry,
        }

    def pre_process(self, ctx):
        if ctx.req_data and self._is_obfuscated(ctx.req_data):
            ctx.proc_req = self._deobfuscate(ctx.req_data)
        return ctx

    def post_process(self, ctx):
        if not ctx.resp_data:
            return ctx

        # Select method
        method = self.mode
        if method == "random":
            method = random.choice(list(self.methods.keys()))

        obfuscator = self.methods.get(method, self._add_random_padding)
        ctx.proc_resp = obfuscator(ctx.resp_data)
        return ctx

    def _is_obfuscated(self, data):
        # Check for obfuscation markers (implementation depends on methods)
        if (
            data.startswith(b"HTTP/")
            or data.startswith(b"GET ")
            or data.startswith(b"POST ")
        ):
            return True
        # Add more detection logic as needed
        return False

    def _deobfuscate(self, data):
        # Extract real payload from obfuscated data
        if data.startswith(b"GET ") or data.startswith(b"POST "):
            pos = data.find(b"\r\n\r\n")
            if pos != -1:
                return data[pos + 4 :]
        # Add more extraction logic as needed
        return data

    def _add_random_padding(self, data):
        # Add random padding to the data
        pad_len = random.randint(4, 16)
        padding = os.urandom(pad_len)
        return struct.pack("!B", pad_len) + padding + data

    def _add_http_header(self, data):
        # Make data look like HTTP response
        return (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: nginx\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Length: " + str(len(data)).encode() + b"\r\n"
            b"\r\n" + data
        )

    def _add_tls_mimicry(self, data):
        # Make data look like TLS record
        record_type = 23  # Application data
        version = 0x0303  # TLS 1.2
        length = len(data)
        header = struct.pack("!BHH", record_type, version, length)
        return header + data


class AESEncryptionInterceptor(BaseInterceptor):
    """AES encryption for traffic"""

    def __init__(self, key):
        if isinstance(key, str):
            self.key = key.encode()[:32].ljust(32, b"\0")  # Ensure 32 bytes for AES-256
        else:
            self.key = key[:32].ljust(32, b"\0")

    def pre_process(self, ctx):
        if ctx.req_data and self._is_encrypted(ctx.req_data):
            try:
                ctx.proc_req = self._decrypt(ctx.req_data)
            except Exception as e:
                # Log error but continue with original data
                ctx.proc_req = ctx.req_data
        return ctx

    def post_process(self, ctx):
        if ctx.resp_data:
            ctx.proc_resp = self._encrypt(ctx.resp_data)
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

    def post_process(self, ctx):
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


class SecureHandshakeInterceptor(BaseInterceptor):
    """Implements secure authentication handshake"""

    def __init__(self, shared_secret, time_window=30):
        self.secret = (
            shared_secret.encode() if isinstance(shared_secret, str) else shared_secret
        )
        self.window = time_window

    def pre_process(self, ctx):
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
