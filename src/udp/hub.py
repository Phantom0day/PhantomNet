import asyncio, struct, socket
from typing import Tuple, Dict

from src.stream import *
from src.utils import *


class UDPHub:
    def __init__(
        self,
        framed_writer: FramedWriter,
        channel_id: int,
        loop=None,
    ):
        self.writer = framed_writer
        self.ch = channel_id
        self.loop = loop or asyncio.get_event_loop()
        self._udp_cache: Dict[Tuple[str, int], asyncio.DatagramTransport] = {}

    async def forward(self, payload: bytes):
        # payload = addr_hdr + data
        dst, header_len = self._parse_addr_hdr(payload)
        if dst is None:
            return
        data = payload[header_len:]
        transport = await self._get_or_create_socket(dst)
        transport.sendto(data, dst)

    async def _get_or_create_socket(
        self, dst: Tuple[str, int]
    ) -> asyncio.DatagramTransport:
        if dst in self._udp_cache:
            return self._udp_cache[dst]

        transport, _ = await self.loop.create_datagram_endpoint(
            lambda: self._build_proto(),
            local_addr=None,
        )
        self._udp_cache[dst] = transport
        return transport

    def _build_proto(self, key):
        hub = self

        class _Proto(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                atyp = get_address_type(addr[0])
                addr_hdr = pack_address(addr, atyp)
                hub.writer.write(addr_hdr + data, FrameType.UDP, hub.ch)

        return _Proto()

    # helpers
    def _parse_addr_hdr(self, payload: bytes):
        if not payload:
            return None, 0
        atyp = payload[0]
        view = memoryview(payload)
        if atyp == ATYP_IPV4:
            addr = socket.inet_ntoa(view[1:5])
            port = struct.unpack("!H", view[5:7])[0]
            return (addr, port), 7
        elif atyp == ATYP_DOMAIN:
            dom_len = view[1]
            addr = view[2 : 2 + dom_len].tobytes().decode()
            port = struct.unpack("!H", view[2 + dom_len : 4 + dom_len])[0]
            return (addr, port), 4 + dom_len
        elif atyp == ATYP_IPV6:
            addr = socket.inet_ntop(socket.AF_INET6, view[1:17])
            port = struct.unpack("!H", view[17:19])[0]
            return (addr, port), 19
        return None, 0
