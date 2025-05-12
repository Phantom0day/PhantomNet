import socket
from abc import ABC, abstractmethod
from typing import Tuple


class TransportAdapter(ABC):
    @abstractmethod
    def create_connection(
        self,
        address: Tuple[str, int],
        timeout: float = None,
    ) -> socket.socket: ...

    @abstractmethod
    def wrap_inbound(self, sock: socket.socket) -> socket.socket: ...

    @abstractmethod
    def get_protocol_features(self) -> dict: ...
