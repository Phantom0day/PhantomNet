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
        data = ctx.req_data
        if data and len(data) >= len(self.salt):
            ctx.req_data = (
                strxor(self.salt, data[: len(self.salt)]) + data[len(self.salt) :]
            )
        return ctx

    def unpack(self, ctx):
        data = ctx.resp_data
        if data and len(data) >= len(self.salt):
            ctx.resp_data = (
                strxor(self.salt, data[: len(self.salt)]) + data[len(self.salt) :]
            )
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

    def pack(self, ctx):
        data = ctx.req_data
        if not data:
            return ctx

        # Select method
        method = self.mode
        if method == "random":
            method = random.choice(list(self.methods.keys()))

        obfuscator = self.methods.get(method, self._add_random_padding)
        ctx.req_data = obfuscator(data)
        return ctx

    def unpack(self, ctx):
        data = ctx.resp_data
        if data and self._is_obfuscated(data):
            ctx.resp_data = self._deobfuscate(data)
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


class HTTPCamouflageInterceptor(BaseInterceptor):
    """Makes traffic look like HTTP"""

    def __init__(self):
        self.user_agents = [
            b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            b"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
            b"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)",
        ]
        self.hosts = [
            b"api.example.com",
            b"cdn.cloudprovider.net",
            b"assets.website.org",
        ]

    def pack(self, ctx):
        data = ctx.req_data
        # Only modify if we're using HTTP protocol
        if ctx.meta.get("proto") != "http" or not data:
            return ctx

        # Create HTTP response
        ctx.req_data = self._build_http_request(data)
        return ctx

    def unpack(self, ctx):
        data = ctx.resp_data
        # Check if this is HTTP-camouflaged traffic
        if data and self._is_http(data):
            # Parse out the real payload
            real_data = self._extract_payload(data)
            if real_data:
                ctx.resp_data = real_data
                ctx.meta["proto"] = "http"

        # If we're at init stage, wrap outgoing data in HTTP request
        elif ctx.stage == "init" and ctx.req_data:
            ctx.resp_data = self._build_http_request(ctx.req_data)
            ctx.meta["proto"] = "http"

        return ctx

    def _is_http(self, data):
        """Check if data looks like HTTP"""
        if (
            data.startswith(b"GET ")
            or data.startswith(b"POST ")
            or data.startswith(b"HTTP/")
        ):
            return True
        return False

    def _extract_payload(self, data):
        """Extract payload from HTTP request/response"""
        # Find end of headers
        header_end = data.find(b"\r\n\r\n")
        if header_end != -1:
            return data[header_end + 4 :]
        return None

    def _build_http_request(self, data):
        """Wrap data in HTTP request"""
        agent = random.choice(self.user_agents)
        host = random.choice(self.hosts)
        path = b"/api/v" + str(random.randint(1, 3)).encode() + b"/data"

        request = (
            b"POST " + path + b" HTTP/1.1\r\n"
            b"Host: " + host + b"\r\n"
            b"User-Agent: " + agent + b"\r\n"
            b"Accept: */*\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Length: " + str(len(data)).encode() + b"\r\n"
            b"Connection: keep-alive\r\n\r\n"
        ) + data

        return request

    def _build_http_response(self, data):
        """Wrap data in HTTP response"""
        status = random.choice([b"200 OK", b"201 Created", b"202 Accepted"])
        server = random.choice([b"nginx", b"Apache", b"cloudflare"])
        content_type = b"application/octet-stream"

        response = (
            b"HTTP/1.1 " + status + b"\r\n"
            b"Server: " + server + b"\r\n"
            b"Date: "
            + time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()).encode()
            + b"\r\n"
            b"Content-Type: " + content_type + b"\r\n"
            b"Content-Length: " + str(len(data)).encode() + b"\r\n"
            b"Connection: keep-alive\r\n\r\n"
        ) + data

        return response


class TLSCamouflageInterceptor(BaseInterceptor):
    """Makes traffic appear as legitimate TLS"""

    def __init__(self):
        # TLS record types
        self.handshake = 22
        self.application_data = 23
        # TLS versions
        self.tls_1_2 = 0x0303

    def pack(self, ctx):
        data = ctx.req_data
        if ctx.meta.get("proto") != "tls" or not data:
            return ctx

        # Wrap response in TLS record
        if ctx.stage == "init":
            # Server hello for init response
            ctx.req_data = self._create_server_hello(data)
        else:
            # Application data for regular responses
            ctx.req_data = self._wrap_in_tls_record(
                self.application_data, self.tls_1_2, data
            )
        return ctx

    def unpack(self, ctx):
        data = ctx.resp_data
        # Extract real payload if it's TLS wrapped
        if data and self._looks_like_tls(data):
            payload = self._extract_from_tls(data)
            if payload:
                ctx.resp_data = payload
                ctx.meta["proto"] = "tls"
        # Wrap init data as client hello
        elif ctx.stage == "init" and data:
            ctx.resp_data = self._create_client_hello(data)
            ctx.meta["proto"] = "tls"
        return ctx

    def _looks_like_tls(self, data):
        """Check if data appears to be TLS"""
        if len(data) < 5:
            return False

        record_type = data[0]
        version_major, version_minor = data[1], data[2]

        # Check for valid TLS record types and versions
        return record_type in (self.handshake, self.application_data) and (
            version_major,
            version_minor,
        ) in [(3, 1), (3, 2), (3, 3)]

    def _extract_from_tls(self, data):
        """Extract payload from TLS record"""
        if len(data) < 5:
            return None

        # Get record length from bytes 3-4
        length = (data[3] << 8) | data[4]

        # Validate length
        if len(data) < length + 5:
            return None

        # Extract payload
        return data[5 : 5 + length]

    def _wrap_in_tls_record(self, record_type, version, payload):
        """Wrap data in TLS record"""
        length = len(payload)
        header = struct.pack("!BHH", record_type, version, length)
        return header + payload

    def _create_client_hello(self, data):
        """Create a fake Client Hello message with hidden data"""
        # Create random bytes (32 bytes) with the first 4 being the timestamp
        timestamp = int(time.time())
        random_bytes = struct.pack("!I", timestamp) + os.urandom(28)

        # Payload format:
        # 1 byte: handshake type (1 = client hello)
        # 3 bytes: length of client hello
        # 2 bytes: TLS version
        # 32 bytes: random
        # Rest: session ID, cipher suites, etc. (simplified)

        # Embed real data in "extension" area
        tls_hello = (
            b"\x01"  # Handshake type: client hello
            + struct.pack("!I", 32 + 74 + len(data))[1:]  # 3-byte length
            + struct.pack("!H", self.tls_1_2)  # TLS version
            + random_bytes  # Random bytes
            + b"\x20"
            + os.urandom(32)  # Session ID (32 bytes)
            + b"\x00\x2e"  # Cipher suites length
            + os.urandom(46)  # Cipher suites
            + b"\x01"  # Compression methods length
            + b"\x00"  # Compression method: none
            + struct.pack("!H", 4 + len(data))  # Extensions length
            + b"\xff\x01"  # Custom extension type
            + struct.pack("!H", len(data))  # Extension length
            + data  # Real data
        )

        # Wrap in TLS record
        return self._wrap_in_tls_record(self.handshake, self.tls_1_2, tls_hello)

    def _create_server_hello(self, data):
        """Create a fake Server Hello message with hidden data"""
        # Similar to client hello but with server hello type
        random_bytes = struct.pack("!I", int(time.time())) + os.urandom(28)

        tls_hello = (
            b"\x02"  # Handshake type: server hello
            + struct.pack("!I", 32 + 38 + len(data))[1:]  # 3-byte length
            + struct.pack("!H", self.tls_1_2)  # TLS version
            + random_bytes  # Random bytes
            + b"\x20"
            + os.urandom(32)  # Session ID (32 bytes)
            + b"\xc0\x2f"  # Cipher suite
            + b"\x00"  # Compression method: none
            + struct.pack("!H", 4 + len(data))  # Extensions length
            + b"\xff\x01"  # Custom extension type
            + struct.pack("!H", len(data))  # Extension length
            + data  # Real data
        )

        # Wrap in TLS record
        return self._wrap_in_tls_record(self.handshake, self.tls_1_2, tls_hello)


class VideoCamouflageInterceptor(BaseInterceptor):
    """Camouflages traffic as video streaming"""

    def __init__(self):
        self.video_magic = b"\x00\x00\x01\xba"  # MPEG-PS pack start code

    def pack(self, ctx):
        data = ctx.req_data
        if not data:
            return ctx

        # Mark as video protocol
        ctx.meta["proto"] = "video"

        # Create fake video header
        header = self.video_magic + struct.pack("!I", len(data))

        # Add some fake video metadata
        timestamp = int(time.time() * 90000)  # MPEG timestamp (90kHz)
        metadata = struct.pack("!IH", timestamp, random.randint(0, 0xFFFF))

        ctx.req_data = header + metadata + data
        return ctx

    def unpack(self, ctx):
        data = ctx.resp_data
        # Extract real data if it's video-camouflaged
        if data and len(data) > 8 and data.startswith(self.video_magic):
            # Data length is stored after the magic bytes
            data_len = struct.unpack("!I", data[4:8])[0]
            if len(data) >= 8 + data_len:
                ctx.resp_data = data[8 : 8 + data_len]
                ctx.meta["proto"] = "video"
        return ctx
