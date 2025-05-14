import asyncio
from asyncio import StreamReader, StreamWriter
from src.core import *
from src.udp import *
from src.utils import *


class Session:
    def __init__(
        self,
        inbound: Tuple[StreamReader, StreamWriter],
        outbound: Tuple[StreamReader, StreamWriter],
        chain: InterceptorChain,
        udp_relay=None,
        udp_hub=None,
    ):
        self.inbound = inbound
        self.outbound = outbound
        self.chain = chain
        self.running = True

        self.udp_relay: UDPRelay = (
            udp_relay
            or getattr(outbound[1], "udp_relay", None)
            or getattr(inbound[1], "udp_relay", None)
        )
        self.udp_hub: UDPHub = (
            udp_hub
            or getattr(inbound[1], "udp_hub", None)
            or getattr(outbound[1], "udp_hub", None)
        )

    async def start(self):
        try:
            t1 = asyncio.create_task(
                self._pipe(
                    self.inbound,
                    self.outbound,
                    Operation.UNPACK,
                )
            )
            t2 = asyncio.create_task(
                self._pipe(
                    self.outbound,
                    self.inbound,
                    Operation.PACK,
                )
            )
            await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
        except Exception as e:
            log.error(f"Session error: {e}")
        finally:
            self.running = False
            await self._close(self.inbound[1])
            await self._close(self.outbound[1])

    async def _pipe(
        self,
        src: Tuple[StreamReader, StreamWriter],
        dst: Tuple[StreamReader, StreamWriter],
        op: Operation,
    ):
        reader, writer = src
        dst_writer = dst[1]
        while self.running:
            try:
                if isinstance(reader, FramedReader):
                    frame = await reader.read_frame()
                    data = frame["data"]
                    frame_type = frame["type"]
                    channel_id = frame["channel_id"]
                else:
                    data = await src[0].read(DEFAULT_BUFFER_SIZE)
                    frame_type = FrameType.SOCKS
                    channel_id = 0

                if not data:
                    break
                if frame_type == FrameType.UDP:
                    if op is Operation.UNPACK:
                        if self.udp_hub is None and isinstance(
                            self.inbound[1], FramedWriter
                        ):
                            self.udp_hub = UDPHub(self.inbound[1], channel_id)
                        if self.udp_hub:
                            await self.udp_hub.forward(data)
                    else:
                        if self.udp_relay:
                            self.udp_relay.write_back(data)
                    continue

                ctx = ProtocolContext(
                    data=data,
                    frame_type=frame_type,
                    channel_id=channel_id,
                    operation=op,
                )
                ctx = await self.chain.run(ctx)
                if ctx.drop or not ctx.data:
                    break

                if isinstance(dst_writer, FramedWriter):
                    dst_writer.write(ctx.data, ctx.frame_type, ctx.channel_id)
                    await dst_writer.drain()
                else:
                    await write_data(dst_writer, ctx.data)
            except (ConnectionResetError, BrokenPipeError):
                log.info(
                    "Peer closed connection (channel %s -> %s)",
                    src[1].get_extra_info("peername"),
                    dst[1].get_extra_info("peername"),
                )
                break
            except Exception:
                log.exception("Unhandled pipe error")
                break

    @staticmethod
    async def _close(writer: StreamWriter):
        if not writer.is_closing():
            writer.close()
            await writer.wait_closed()

    def register_udp_relay(self, relay):
        self.udp_relay = relay

    def register_udp_hub(self, hub):
        self.udp_hub = hub
