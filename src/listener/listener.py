import socket, threading, logging, select
from src.utils import *
from src.handler import *
from src.transport import *


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
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._running = False

    def serve_forever(self):
        self._sock.bind(self.bind)
        self._sock.listen(5)
        self._running = True
        self._sock.settimeout(1)
        log.info(f"Listening on {self.bind[0]}:{self.bind[1]}")
        while self._running:
            try:
                conn, peer = self._sock.accept()
                wrapped_conn = self.adapter.wrap_accepted_socket(conn)
                if wrapped_conn is None:
                    log.error(f"Failed to establish secure connection with {peer}")
                    close_socket(conn)
                    continue
                t = threading.Thread(
                    target=self._handle_connection,
                    args=(wrapped_conn, peer),
                    daemon=True,
                )
                t.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_connection(self, conn, peer):
        try:
            self.handler(conn, peer)
        except Exception as e:
            log.error(f"Connection handler error: {e}")
        finally:
            close_socket(conn)

    def close(self):
        self._running = False
        close_socket(self._sock)
