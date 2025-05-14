import socket, threading, logging, select
from src.utils import *
from src.handshake import *
from src.handshake.handler import Handler
from src.transport import *
from src.session import *


class TcpListener:
    def __init__(
        self,
        bind: tuple[str, int],
        handler: Handler,
        adapter: TransportAdapter = None,
    ):
        self.bind = bind
        self.handler = handler
        self.adapter = adapter or PlainTCPAdapter()
        self.server = None
        self.chain = None
        self._running = False

    async def start_server(self):
        self.running = True
        server = await asyncio.start_server(
            self._handle_client,
            *self.bind,
            # add SSL context for TLS adapter
            ssl=getattr(self.adapter, "ssl_context", None),
            reuse_address=True,
        )

        self.server = server
        log.info(f"Listening on {self.bind[0]}:{self.bind[1]}")

        try:
            async with server:
                await server.serve_forever()
        except asyncio.CancelledError:
            log.info("Server task was cancelled")
        finally:
            self._running = False

    async def _handle_client(
        self, *conn: Tuple[asyncio.StreamReader, asyncio.StreamWriter]
    ):
        peer = conn[1].get_extra_info("peername")
        log.info(f"New connection from {peer}")

        try:
            wrapped_conn = await self.adapter.wrap_inbound(conn[0], conn[1])

            _in, _out = await self.handler.handle(wrapped_conn, peer)
            if _in[0] and _in[1] and _out[0] and _out[1]:
                session = Session(_in, _out, self.chain)
                await session.start()
            else:
                log.warning(f"Failed to establish proxied connection for {peer}")
                if not conn[1].is_closing():
                    conn[1].close()
                    await conn[1].wait_closed()
        except Exception as e:
            log.error(f"Error handling client {peer}: {e}")
            if not conn[1].is_closing():
                conn[1].close()
                await conn[1].wait_closed()

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self._running = False
            log.info("Server stopped")
