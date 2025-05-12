from abc import ABC, abstractmethod
from typing import Optional, Tuple, List

from src.config import *
from src.core.chain import InterceptorChain
from src.handler import *
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

    def start(self):
        transport_adapter = self._get_adapter()
        handshake_protocol = self._get_handshake_protocol()
        handler = self._get_handler(transport_adapter, handshake_protocol)

        listener = TcpListener(
            self.addr,
            handler=lambda c, p: Session(
                *handler.handle(c, p),
                self.chain,
            ).loop(),
            adapter=transport_adapter,
        )
        self._listener = listener
        listener.serve_forever()

    @abstractmethod
    def _get_handler(
        self, adapter: TransportAdapter, handshake: HandshakeProtocol
    ) -> Handler:
        raise NotImplementedError("Subclasses must implement this method")

    @abstractmethod
    def _get_adapter(self) -> TransportAdapter:
        raise NotImplementedError("Subclasses must implement this method")

    def _get_handshake_protocol(self) -> HandshakeProtocol:
        handshake_type = self.config.get("handshake", "type", "socks5")
        base_protocol = Socks5HandshakeProtocol()
        # if self.config.get('handshake', 'obfuscate', False):
        #     magic = self.config.get('handshake', 'magic', b'\xB0\xAE\x54')
        #     return ObfuscatedHandshakeProtocol(base_protocol, magic)
        return base_protocol

    def stop(self):
        """Stop the proxy"""
        log.info("Stopping proxy...")
        self.running = False
        for sock in self.clients.copy():
            close_socket(sock)


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
        return Socks5ClientHandler(self.addr, self.server_addr, adapter, handshake)

    def _get_adapter(self):
        c = self.config.get("transport", default={})
        t = c.get("type", "plain")
        if t == "tls":
            return TlsClientAdapter(
                c.get("sni", "google.com"),
                cert=c.get("cert", None),
            )
        return PlainTCPAdapter()


class ServerProxy(BaseProxy):
    """Server that accepts connections from client proxies"""

    def _get_handler(self, adapter, handshake):
        return Socks5ServerHandler(self.addr, adapter, handshake)

    def _get_adapter(self):
        c = self.config.get("transport", default={})
        t = c.get("type", "plain")
        if t == "tls":
            return TlsServerAdapter(c["cert"], c["key"])
        return PlainTCPAdapter()
