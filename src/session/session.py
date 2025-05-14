import asyncio
from asyncio import StreamReader, StreamWriter
from src.core.context import *
from src.utils import *


class Session:
    def __init__(
        self,
        inbound: Tuple[StreamReader, StreamWriter],
        outbound: Tuple[StreamReader, StreamWriter],
        chain: InterceptorChain,
    ):
        self.inbound = inbound
        self.outbound = outbound
        self.chain = chain
        self.running = True

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
        while self.running:
            data = await src[0].read(DEFAULT_BUFFER_SIZE)
            if not data:
                break
            ctx = ProtocolContext(data=data, operation=op)
            ctx = await self.chain.run(ctx)
            if ctx.drop or not ctx.data:
                break
            await write_data(dst[1], ctx.data)

    @staticmethod
    async def _close(writer: StreamWriter):
        if not writer.is_closing():
            writer.close()
            await writer.wait_closed()
