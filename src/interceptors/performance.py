import os
import random
import time
import math
from collections import Counter
from src.core import BaseInterceptor, ProtocolContext


class ConnectionPoolInterceptor(BaseInterceptor):
    """Connection reuse interceptor"""

    def __init__(self):
        self.pool = ConnectionPool(max_size=100)

    def pre_process(self, context: ProtocolContext) -> ProtocolContext:
        dest = (context.dest_addr, context.dest_port)
        context.remote = self.pool.acquire(dest)
        return context

    def post_process(self, context):
        self.pool.release(context.remote)
        return context


class ZeroCopyInterceptor(BaseInterceptor):
    """Zero copy optimization"""

    def post_process(self, context: ProtocolContext) -> ProtocolContext:
        context.proc_resp = memoryview(context.resp_data)
        return context


class EntropyAdjustmentInterceptor(BaseInterceptor):
    """Adjusts traffic entropy to avoid statistical analysis"""

    def __init__(self, target_entropy=7.0):
        self.target = target_entropy

    def post_process(self, ctx):
        if not ctx.resp_data:
            return ctx

        # Calculate current entropy
        current = self._calculate_entropy(ctx.resp_data)

        # Adjust if needed
        if abs(current - self.target) > 0.5:
            ctx.proc_resp = self._adjust_entropy(ctx.resp_data, current)
        else:
            ctx.proc_resp = ctx.resp_data

        return ctx

    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0

        # Count byte frequencies
        counter = Counter(data)

        # Calculate entropy
        length = len(data)
        entropy = 0

        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def _adjust_entropy(self, data, current):
        """Adjust entropy to target level"""
        if current > self.target:
            # Entropy too high, add repetitive data
            repeat_byte = random.randint(0, 255).to_bytes(1, byteorder="big")
            padding_size = int(len(data) * (current - self.target) / 2)
            padding = repeat_byte * padding_size
            return data + padding
        else:
            # Entropy too low, add random data
            padding_size = int(len(data) * (self.target - current) / 2)
            padding = os.urandom(padding_size)
            return data + padding


class TimingInterceptor(BaseInterceptor):
    """Adds timing variations to defeat traffic analysis"""

    def __init__(self, min_delay=0.01, max_delay=0.2, delay_prob=0.3):
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.delay_prob = delay_prob

    def pre_process(self, ctx):
        # Random delay on some requests
        if random.random() < self.delay_prob:
            time.sleep(random.uniform(self.min_delay, self.max_delay / 2))
        return ctx

    def post_process(self, ctx):
        # More likely to delay on larger responses
        if ctx.resp_data:
            size = len(ctx.resp_data)
            # Probability based on size
            prob = min(0.8, self.delay_prob + (size / 100000))

            if random.random() < prob:
                # Delay proportional to size
                factor = min(1.0, size / 10000)
                delay = random.uniform(self.min_delay, self.max_delay * factor)
                time.sleep(delay)

        return ctx


class DPIEvasionInterceptor(BaseInterceptor):
    """Deep Packet Inspection evasion techniques"""

    def __init__(self, tcp_split=True, pattern_avoid=True):
        self.tcp_split = tcp_split
        self.pattern_avoid = pattern_avoid

        # Common DPI signature patterns to avoid
        self.signatures = [
            b"HTTP/1.1",
            b"SSH-2.0",
            b"\x13\x03\x03",  # TLS 1.2 app data
            b"GET ",
            b"POST ",
        ]

    def pre_process(self, ctx):
        if not ctx.req_data:
            return ctx

        if self.pattern_avoid:
            # Check if request contains any known signatures
            for sig in self.signatures:
                if sig in ctx.req_data:
                    # Modify slightly to avoid exact match
                    ctx.proc_req = self._modify_pattern(ctx.req_data, sig)
                    break

        return ctx

    def post_process(self, ctx):
        if not ctx.resp_data:
            return ctx

        # Mark for TCP segment splitting if enabled
        if self.tcp_split:
            # Calculate ideal segment size (randomized)
            ctx.meta["tcp_split"] = True
            ctx.meta["tcp_split_size"] = random.randint(40, 200)

        if self.pattern_avoid:
            # Avoid patterns in response too
            for sig in self.signatures:
                if sig in ctx.resp_data:
                    ctx.proc_resp = self._modify_pattern(ctx.resp_data, sig)
                    break

        return ctx

    def _modify_pattern(self, data, pattern):
        """Subtly modify a pattern to avoid signature matching"""
        # Find the pattern
        pos = data.find(pattern)
        if pos == -1:
            return data

        # Modify it slightly (insert a zero-byte that many parsers ignore)
        modified = data[: pos + 1] + b"\x00" + data[pos + 1 :]
        return modified


class BehaviorSimulatorInterceptor(BaseInterceptor):
    """Simulates behavior of legitimate protocols"""

    def __init__(self, protocol="https", periodic_keepalive=True):
        self.protocol = protocol
        self.periodic_keepalive = periodic_keepalive
        self.last_activity = time.time()

    def pre_process(self, ctx):
        self.last_activity = time.time()

        # Add protocol-specific behavior
        if self.protocol == "https" and ctx.stage == "init":
            # Add TLS fingerprint
            ctx.meta["tls_fingerprint"] = {
                "version": "TLS 1.2",
                "ciphers": [
                    "ECDHE-RSA-AES128-GCM-SHA256",
                    "ECDHE-RSA-AES256-GCM-SHA384",
                ],
                "extensions": ["server_name", "ec_point_formats", "supported_groups"],
            }

        return ctx

    def post_process(self, ctx):
        self.last_activity = time.time()

        # Handle protocol-specific behaviors
        if self.protocol == "http" and ctx.resp_data:
            # Simulate HTTP chunked encoding for large responses
            if len(ctx.resp_data) > 1024:
                ctx.proc_resp = self._simulate_http_chunked(ctx.resp_data)

        # Add keepalive if needed
        if self.periodic_keepalive and time.time() - self.last_activity > 30:
            # Mark for sending keepalive
            ctx.meta["send_keepalive"] = True

        return ctx

    def _simulate_http_chunked(self, data):
        """Simulate HTTP chunked encoding"""
        result = b""

        # Split into random chunks
        pos = 0
        while pos < len(data):
            # Random chunk size between 200-1000 bytes
            chunk_size = min(random.randint(200, 1000), len(data) - pos)
            chunk = data[pos : pos + chunk_size]

            # Add chunk header and data
            result += hex(chunk_size)[2:].encode() + b"\r\n"
            result += chunk + b"\r\n"

            pos += chunk_size

        # Add final chunk
        result += b"0\r\n\r\n"
        return result
