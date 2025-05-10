import select
from src.core import *
from src.utils import *


class Session:
    def __init__(
        self,
        inbound: socket.socket,
        outbound: socket.socket,
        chain: InterceptorChain,
        max_buf=MAX_BUFFER_SIZE,
    ):
        self.in_sock, self.out_sock = inbound, outbound
        self.chain = chain
        self.max_buf = max_buf
        self.buf_cli, self.buf_rem = b"", b""
        self.running = True

    def loop(self):
        try:
            self.in_sock.setblocking(False)
            self.out_sock.setblocking(False)
            rlist = [self.in_sock, self.out_sock]
            stage = "transport"
            while self.running:
                try:
                    r, _, e = select.select(rlist, [], rlist, 1.0)
                except (select.error, socket.error) as e:
                    log.error(f"Select error: {e}")
                    break
                if self.in_sock in e or self.out_sock in e:
                    log.debug(f"Socket error: {e}")
                    break

                for s in r:
                    if s is self.out_sock:  # outbound → inbound
                        self._pump(
                            self.out_sock,
                            self.in_sock,
                            ProtocolContext(stage=stage, operation=Operation.PACK),
                        )
                    else:
                        self._pump(
                            self.in_sock,
                            self.out_sock,
                            ProtocolContext(stage=stage, operation=Operation.UNPACK),
                        )
        finally:
            close_socket(self.in_sock)
            close_socket(self.out_sock)

    def _pump(self, src: socket.socket, dst: socket.socket, ctx: ProtocolContext):
        ctx.data = src.recv(DEFAULT_BUFFER_SIZE)
        if not ctx.data:
            self.running = False
            return
        self.chain.run(ctx)
        # self._buffer_and_flush(ctx)
        if ctx.drop:
            self.running = False
            return
        payload = ctx.data
        if payload:
            dst.sendall(payload)

    def _buffer_and_flush(self, ctx: ProtocolContext):
        # Initialize buffers if needed
        ctx.meta.setdefault("packed_buf", b"")
        ctx.meta.setdefault("unpacked_buf", b"")

        if ctx.operation is Operation.PACK:
            ctx.meta["packed_buf"] += ctx.data
        else:
            ctx.meta["unpacked_buf"] += ctx.data
        ctx.data = b""

        if ctx.meta["unpacked_buf"]:
            try:
                sent = self.out_sock.send(ctx.meta["unpacked_buf"])
                ctx.meta["unpacked_buf"] = ctx.meta["unpacked_buf"][sent:]
            except Exception:
                ctx.drop = True

        if ctx.meta["packed_buf"]:
            try:
                sent = self.in_sock.send(ctx.meta["packed_buf"])
                ctx.meta["packed_buf"] = ctx.meta["packed_buf"][sent:]
            except Exception:
                ctx.drop = True

        if (
            len(ctx.meta["unpacked_buf"]) > MAX_BUFFER_SIZE
            or len(ctx.meta["packed_buf"]) > MAX_BUFFER_SIZE
        ):
            ctx.drop = True

        return ctx
