from abc import ABC, abstractmethod
from typing import Tuple
from src.core.errors import *
from src.handshake import HandshakeProtocol
from src.handshake import *
from src.utils import *
from src.transport import *


class Handler(ABC):
    def __init__(
        self,
        addr: Tuple[str, int],
        handshaker: HandshakeProtocol,
        transporter: TransportAdapter = None,
        timeout=5,
    ):
        self.addr = addr
        self.handshaker = handshaker
        self.transporter = transporter or PlainTCPAdapter()
        self.timeout = timeout

    @abstractmethod
    async def handle(
        self,
        conn: Tuple[asyncio.StreamReader, asyncio.StreamWriter],
        peer,
    ) -> Tuple[
        Tuple[asyncio.StreamReader, asyncio.StreamWriter],
        Tuple[asyncio.StreamReader, asyncio.StreamWriter],
    ]: ...


class Socks5ClientHandler(Handler):
    def __init__(self, addr, server_addr, handshake, transport, timeout=5):
        super().__init__(addr, handshake, transport, timeout)
        self.server_addr = server_addr

    async def handle(
        self,
        client: Tuple[asyncio.StreamReader, asyncio.StreamWriter],
        peer,
    ):
        try:
            dest_addr = await self.handshaker.client_handshake(client)
            if not dest_addr:
                return None, None

            remote = await self.transporter.create_outbound(
                self.server_addr, self.timeout
            )
            result = await self.handshaker.server_handshake(remote, dest_addr)
            if not result:
                log.error(f"Server connection failed for {peer[0]}:{peer[1]}")
                await write_data(client[1], create_socks_reply(REPLY_HOST_UNREACHABLE))
                return None, None
            await write_data(client[1], b"\x05\x00\x00\x01" + b"\x00" * 6)
            return client, remote
        except Exception as e:
            log.error(f"Client error {peer[0]}:{peer[1]}")
            log.exception(e)
            return None, None


class Socks5ServerHandler(Handler):

    async def handle(
        self,
        conn: Tuple[asyncio.StreamReader, asyncio.StreamWriter],
        peer,
    ):
        try:
            address = await self.handshaker.client_handshake(conn)
            if not address:
                log.error("No target address received")
                return None, None

            log.info(f"Connecting to {address[0]}:{address[1]}")
            remote = await self.transporter.create_outbound(address, self.timeout)
            result = await self.handshaker.server_handshake(remote, address)
            if not result:
                log.error(f"Server connection failed for {peer[0]}:{peer[1]}")
                await write_data(conn[1], b"\x01")
                return None, None
            await write_data(conn[1], b"\x00")
            return conn, remote
        except Exception as e:
            log.error(f"Server error {peer[0]}:{peer[1]}: {e}")
            await write_data(conn[1], b"\x01")
            return None, None
