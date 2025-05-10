from abc import ABC, abstractmethod
from typing import Optional, Tuple, List

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
        host: str,
        port: int,
        interceptors: Optional[List] = None,
    ):
        self.addr = (host, port)
        self.interceptors = interceptors or []
        self.running = False
        self.clients = set()  # Track active clients
        self.chain = InterceptorChain(self.interceptors)

    def start(self):
        handler = self.getHandler()
        listener = TcpListener(
            self.addr,
            handler=lambda c, p: Session(
                *handler.handle(c, p),
                self.chain,
                PlainTCPAdapter(),
            ).loop(),
        )
        self._listener = listener
        listener.serve_forever()

    @abstractmethod
    def getHandler(self) -> Handler:
        raise NotImplementedError("Subclasses must implement this method")

    def stop(self):
        """Stop the proxy"""
        log.info("Stopping proxy...")
        self.running = False
        for sock in self.clients.copy():
            close_socket(sock)


class ServerProxy(BaseProxy):
    """Server that accepts connections from client proxies"""

    def getHandler(self):
        return Socks5ServerHandler(self.addr)


class ClientProxy(BaseProxy):
    """SOCKS5 proxy that runs on the client side"""

    def __init__(
        self,
        local_host: str,
        local_port: int,
        server_host: str,
        server_port: int,
        interceptors: List[BaseInterceptor] = None,
    ):
        super().__init__(local_host, local_port, interceptors)
        self.server_addr = (server_host, server_port)

    def getHandler(self):
        return Socks5ClientHandler(self.addr, self.server_addr)
