class TransportAdapter:
    def wrap_inbound(self, sock):
        return sock

    def wrap_outbound(self, sock):
        return sock
