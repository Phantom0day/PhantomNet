import asyncio
import select
import ssl
from asyncio import Transport, StreamReader, StreamWriter
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
            inbound_task = asyncio.create_task(self._handle_inbound())
            outbound_task = asyncio.create_task(self._handle_outbound())

            done, pending = await asyncio.wait(
                [inbound_task, outbound_task],
                return_when=asyncio.FIRST_COMPLETED,
            )

            # cancel unfinished tasks
            for task in pending:
                task.cancel()

            # try to retrieve result
            for task in done:
                try:
                    await task
                except Exception as e:
                    log.error(f"Session task error: {e}")
        except Exception as e:
            log.error(f"Session error: {e}")
        finally:
            self.running = False
            if not self.inbound[1].is_closing():
                self.inbound[1].close()
                await self.inbound[1].wait_closed()
            if not self.outbound[1].is_closing():
                self.outbound[1].close()
                await self.outbound[1].wait_closed()

    async def _handle_inbound(self):
        while self.running:
            try:
                # read data from packed stream
                data = await self.inbound[0].read(DEFAULT_BUFFER_SIZE)
                if not data:  # connection closed
                    break

                # process data through interceptor chain
                ctx = ProtocolContext(data, operation=Operation.UNPACK)
                ctx = await self.chain.run(ctx)

                if ctx.drop:
                    self.running = False
                    break
                if ctx.data:
                    await write_data(self.outbound[1], ctx.data)
            except Exception as e:
                log.error(f"Error handling inbound data")
                log.exception(e)
                break

    async def _handle_outbound(self):
        while self.running:
            try:
                # read data from unpacked stream
                data = await self.outbound[0].read(DEFAULT_BUFFER_SIZE)
                if not data:  # connection closed
                    break

                ctx = ProtocolContext(data, operation=Operation.PACK)
                ctx = await self.chain.run(ctx)

                if ctx.drop:
                    self.running = False
                    break
                if ctx.data:
                    await write_data(self.inbound[1], ctx.data)
            except Exception as e:
                log.error(f"Error handling outbound data: {e}")
                break
