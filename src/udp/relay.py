import asyncio, struct
from typing import Tuple, Dict
from asyncio import DatagramTransport

from src.stream import *
from src.utils import *


class UDPRelay(asyncio.DatagramProtocol):
    def __init__(
        self,
        frame_writer: FramedWriter,
        channel_id: int,
        loop=None,
    ):
        self.writer = frame_writer
        self.ch = channel_id
        self.loop = loop or asyncio.get_event_loop()
        self.transport: DatagramTransport | None = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        dest_host, dest_port = addr
        atyp = get_address_type(dest_host)
        addr_hdr = pack_address(addr, atyp)
        payload = addr_hdr + data
        # use channel_id = 0 for now; todo: support multiplexing
        self.writer.write(payload, FrameType.UDP, self.ch)

    async def start(self, bind_host="127.0.0.1", port=None) -> Tuple[str, int]:
        local = (bind_host, port or 0)
        _, _ = await self.loop.create_datagram_endpoint(
            lambda: self,
            local_addr=local,
            reuse_address=True,
            reuse_port=True,
        )
        return self.transport.get_extra_info("sockname")

    def write_back(self, payload: bytes):
        if len(payload) < 4:
            return
        view = memoryview(payload)
        atyp = view[0]
        if atyp == ATYP_IPV4:
            offset = 1 + 4 + 2
        elif atyp == ATYP_DOMAIN:
            dom_len = view[1]
            offset = 1 + 1 + dom_len + 2
        elif atyp == ATYP_IPV6:
            offset = 1 + 16 + 2
        else:
            return
        data = view[offset:].tobytes()
        if self.transport:
            self.transport.sendto(data)
