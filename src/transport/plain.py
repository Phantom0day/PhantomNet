import asyncio
from .base import *


class PlainTCPAdapter(TransportAdapter):
    async def create_outbound(self, address, timeout=None):
        connect_task = asyncio.open_connection(address[0], address[1])
        if timeout:
            try:
                reader, writer = await asyncio.wait_for(connect_task, timeout)
                return reader, writer
            except asyncio.TimeoutError:
                raise ConnectionError(
                    f"Connection to {address[0]}:{address[1]} timed out"
                )
        else:
            reader, writer = await connect_task
        return reader, writer

    async def wrap_inbound(self, reader, writer):
        return reader, writer

    def get_protocol_features(self):
        return {
            "encrypted": False,
            "max_packet_size": 65535,  # TCP theoretical max
            "supports_udp": False,
            "mtu": 1460,  # Typical TCP MSS
            "overhead": 0,  # No additional overhead
            "protocol_name": "plain_tcp",
            "latency_optimized": False,
            "congestion_control": True,
        }
