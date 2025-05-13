import asyncio
from abc import ABC, abstractmethod
from typing import Tuple, Dict, Any, Optional


class HandshakeProtocol(ABC):
    def __init__(self, timeout=5):
        self.timeout = timeout

    @abstractmethod
    async def client_handshake(
        self,
        client: Tuple[asyncio.StreamReader, asyncio.StreamWriter],
    ) -> Tuple[str, int]: ...
    @abstractmethod
    async def server_handshake(
        self,
        remote: Tuple[asyncio.StreamReader, asyncio.StreamWriter],
        dest_addr,
    ) -> bool: ...
