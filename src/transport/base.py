from abc import ABC, abstractmethod
from asyncio import Transport, StreamReader, StreamWriter
from typing import Tuple


class TransportAdapter(ABC):
    @abstractmethod
    async def create_outbound(
        self,
        address: Tuple[str, int],
        timeout: float = None,
    ) -> Tuple[StreamReader, StreamWriter]: ...

    @abstractmethod
    async def wrap_inbound(
        self, reader: StreamReader, writer: StreamWriter
    ) -> Tuple[StreamReader, StreamWriter]: ...

    @abstractmethod
    def get_protocol_features(self) -> dict: ...
