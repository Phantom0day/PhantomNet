from abc import ABC, abstractmethod
import errno
import logging
import select
import socket
from typing import Optional, Tuple, List

from src.core.context import ProtocolContext
from src.core.chain import InterceptorChain, Operation
from src.listener import *
from src.utils import *


class BaseProxy(ABC):
    """Base class for proxy operations"""

    def __init__(
        self,
        host: str,
        port: int,
        interceptors: Optional[List] = None,
    ):
        self.host = host
        self.port = port
        self.interceptors = interceptors or []
        self.running = False
        self.clients = set()  # Track active clients
        self.chain = InterceptorChain(self.interceptors)

    def start(self):
        self.running = True
        listener = TcpListener(
            (self.host, self.port),
            handler=self._handle_client,
        )
        self._listener = listener
        listener.serve_forever()

    def stop(self):
        """Stop the proxy"""
        log.info("Stopping proxy...")
        self.running = False
        for sock in self.clients.copy():
            close_socket(sock)

    @abstractmethod
    def _handle_client(self, client: socket.socket, addr: Tuple):
        raise NotImplementedError("Subclasses must implement this method")
