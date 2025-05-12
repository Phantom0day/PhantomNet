import select
import ssl
from src.core.context import *
from src.utils import *


class Session:
    def __init__(
        self,
        inbound: socket.socket,
        outbound: socket.socket,
        chain: InterceptorChain,
        max_buf=MAX_BUFFER_SIZE,
    ):
        if inbound is None or outbound is None:
            log.error("Session initialized with None socket")
            self.running = False
            return
        self.in_sock = inbound
        self.out_sock = outbound
        self.chain = chain
        self.max_buf = max_buf
        self.buf_cli, self.buf_rem = b"", b""
        self.running = True

    def loop(self):
        try:
            if not isinstance(self.in_sock, ssl.SSLSocket):
                self.in_sock.setblocking(False)
            if not isinstance(self.out_sock, ssl.SSLSocket):
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
        except Exception as e:
            log.error(f"Session error: {e}")
        finally:
            close_socket(self.in_sock)
            close_socket(self.out_sock)

    def _pump(self, src: socket.socket, dst: socket.socket, ctx: ProtocolContext):
        try:
            ctx.data = src.recv(DEFAULT_BUFFER_SIZE)
            if not ctx.data:
                self.running = False
                return
            ctx = self.chain.run(ctx)
            if ctx.drop:
                self.running = False
                return
            payload = ctx.data
            if payload:
                dst.sendall(payload)
        except socket.error:
            self.running = False
