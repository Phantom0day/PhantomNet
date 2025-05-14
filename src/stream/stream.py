import asyncio

from asyncio import StreamReader, StreamWriter
from typing import Any, Optional, List, Dict
from src.utils import *
from .framing import *


class FramedReader:
    def __init__(self, reader: StreamReader, framer: Framer = Framer()):
        self._reader = reader
        self._framer = framer
        self._queue: List[Dict[str, Any]] = []

    async def read(self, n: int = -1) -> bytes:
        while not self._queue:
            chunk = await self._reader.read(DEFAULT_BUFFER_SIZE)
            if not chunk:
                return b""
            self._queue.extend(self._framer.feed(chunk))

        frame = self._queue.pop(0)
        return frame["data"]


class FramedWriter:
    def __init__(self, writer: StreamWriter, framer: Framer = Framer()):
        self._writer = writer
        self._framer = framer

    def write(
        self,
        payload: bytes,
        frame_type: int = FrameType.SOCKS,
        channel_id: int = 0,
    ):
        framed = self._framer.pack(payload, frame_type, channel_id)
        self._writer.write(framed)

    def is_closing(self):
        return self._writer.is_closing()

    def close(self):
        self._writer.close()

    async def wait_closed(self):
        await self._writer.wait_closed()

    async def drain(self):
        await self._writer.drain()
