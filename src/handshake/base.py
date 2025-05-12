import socket
from abc import ABC, abstractmethod
from typing import Tuple, Dict, Any, Optional


class HandshakeProtocol(ABC):
    def __init__(self, timeout=5):
        self.timeout = timeout

    @abstractmethod
    def client_handshake(self, conn: socket.socket) -> Tuple[str, int]: ...
    @abstractmethod
    def server_handshake(self, remote: socket.socket, dest_addr) -> bool: ...
