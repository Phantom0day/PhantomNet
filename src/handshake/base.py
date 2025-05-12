import socket
from abc import ABC, abstractmethod
from typing import Tuple, Dict, Any, Optional


class HandshakeProtocol(ABC):
    @abstractmethod
    def client_handshake(self, conn: socket.socket) -> Tuple[bool, Dict[str, Any]]: ...
    @abstractmethod
    def server_handshake(self, conn: socket.socket) -> Tuple[bool, Dict[str, Any]]: ...
