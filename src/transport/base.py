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
    def wrap_accepted_socket(self, sock: socket.socket) -> socket.socket: ...
