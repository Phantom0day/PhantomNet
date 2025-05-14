from abc import ABC, abstractmethod
from typing import Optional, Tuple, List

from src.config import *
from src.core.chain import InterceptorChain
from src.handshake import *
from src.interceptors import *
from src.listener import *
from src.session import *
from src.transport import *
from src.utils import *


class BaseProxy(ABC):
    """Base class for proxy operations"""

    def __init__(
        self,
        config: ConfigLoader,
        host: str,
        port: int,
        interceptors: Optional[List] = None,
    ):
        self.config = config
        self.addr = (host, port)
        self.interceptors = interceptors or []
        self.running = False
        self.clients = set()  # Track active clients
        self.chain = InterceptorChain(self.interceptors)
        self._listener = None
        self._server_task = None

    async def start(self):
        adapter = await self._get_adapter()
        handshaker = self._get_handshake_protocol()
        handler = self._get_handler(adapter, handshaker)

        listener = TcpListener(self.addr, handler, adapter)
        listener.chain = self.chain
        self._listener = listener

        self._server_task = asyncio.create_task(listener.start_server())

        try:
            await self._server_task
        except asyncio.CancelledError:
            log.info("Proxy server task cancelled")

    async def stop(self):
        """Stop the proxy"""
        if self._listener:
            await self._listener.stop()
        if self._server_task and not self._server_task.done():
            self._server_task.cancel()
            try:
                await self._server_task
            except asyncio.CancelledError:
                pass

    @abstractmethod
    def _get_handler(
        self, adapter: TransportAdapter, handshake: HandshakeProtocol
    ) -> Handler: ...

    @abstractmethod
    async def _get_adapter(self) -> TransportAdapter: ...

    @abstractmethod
    def _get_handshake_protocol(self) -> HandshakeProtocol: ...


class ClientProxy(BaseProxy):
    """SOCKS5 proxy that runs on the client side"""

    def __init__(
        self,
        config: ConfigLoader,
        local_host: str,
        local_port: int,
        server_host: str,
        server_port: int,
        interceptors: List[BaseInterceptor] = None,
    ):
        super().__init__(config, local_host, local_port, interceptors)
        self.server_addr = (server_host, server_port)

    def _get_handler(self, adapter, handshake):
        return Socks5ClientHandler(self.addr, self.server_addr, handshake, adapter)

    async def _get_adapter(self):
        c = self.config.get("transport", default={})
        t = c.get("type", "plain")
        if t == "tls":
            return TlsClientAdapter(
                c.get("sni", "google.com"),
                cert=c.get("cert", None),
            )
        return PlainTCPAdapter()

    def _get_handshake_protocol(self):
        handshake_type = self.config.get("handshake", "type", "socks5")
        if handshake_type != "socks5":
            log.debug(f"unsupported handshake protocol: {handshake_type}")
        handshake_protocol = Socks5ClientHandshakeProtocol()
        # if self.config.get('handshake', 'obfuscate', False):
        #     magic = self.config.get('handshake', 'magic', b'\xB0\xAE\x54')
        #     return ObfuscatedHandshakeProtocol(base_protocol, magic)
        return handshake_protocol


class ServerProxy(BaseProxy):
    """Server that accepts connections from client proxies"""

    def _get_handler(self, adapter, handshake):
        return Socks5ServerHandler(self.addr, handshake, adapter)

    async def _get_adapter(self):
        c = self.config.get("transport", default={})
        t = c.get("type", "plain")
        if t == "tls":
            return TlsServerAdapter(c["cert"], c["key"])
        return PlainTCPAdapter()

    def _get_handshake_protocol(self):
        handshake_type = self.config.get("handshake", "type", "socks5")
        if handshake_type != "socks5":
            log.debug(f"unsupported handshake protocol: {handshake_type}")
        handshake_protocol = Socks5ServerHandshakeProtocol()
        # if self.config.get('handshake', 'obfuscate', False):
        #     magic = self.config.get('handshake', 'magic', b'\xB0\xAE\x54')
        #     return ObfuscatedHandshakeProtocol(base_protocol, magic)
        return handshake_protocol
