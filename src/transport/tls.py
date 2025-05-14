import asyncio
import ssl, socket
import os
from .base import *


class TlsAdapter(TransportAdapter):
    def get_protocol_features(self):
        return {
            "encrypted": True,
            "encryption_type": "TLS",
            "max_packet_size": 16384,  # TLS record size
            "supports_udp": False,
            "mtu": 1400,  # Slightly lower due to TLS overhead
            "overhead": 25,  # ~25 bytes TLS record overhead
            "protocol_name": "tls",
            "latency_optimized": False,
            "congestion_control": True,
            "sni_enabled": True,
            "perfect_forward_secrecy": True,
        }


class TlsClientAdapter(TlsAdapter):
    def __init__(self, sni: str, verify=False, cert=None):
        self._sni = sni
        self._verify = verify
        cert = cert if os.path.isfile(cert) else None
        self._ssl_ctx = ssl.create_default_context(cafile=cert)
        self._ssl_ctx.check_hostname = verify
        if not verify:
            self._ssl_ctx.verify_mode = ssl.CERT_NONE

    async def create_outbound(self, address, timeout=None):
        r, w = await asyncio.open_connection(
            *address,
            ssl=self._ssl_ctx,
            server_hostname=self._sni,
            ssl_handshake_timeout=timeout,
        )

        return r, w

    async def wrap_inbound(self, reader, writer):
        return reader, writer


class TlsServerAdapter(TlsAdapter):
    def __init__(self, cert: str, key: str):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=cert, keyfile=key)
        self._ssl_ctx = ctx

    async def create_outbound(self, address, timeout=None):
        connect_task = asyncio.open_connection(*address)
        if timeout:
            try:
                reader, writer = await asyncio.wait_for(connect_task, timeout)
            except asyncio.TimeoutError:
                raise ConnectionError(
                    f"Connection to {address[0]}:{address[1]} timed out"
                )
        else:
            reader, writer = await connect_task
        return reader, writer

    async def wrap_inbound(self, r, w):
        # for asyncio streams we cannot retrofit SSL onto an existing reader/writer,
        # so we let Listener pass `ssl=self._ctx` directly – return originals.
        return r, w

    # async def wrap_inbound(self, sock):

    #     return self._ssl_ctx.wrap_socket(sock, server_side=True)
    @property
    def ssl_context(self):
        return self._ssl_ctx
