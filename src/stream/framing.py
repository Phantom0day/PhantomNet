import struct


class FrameType:
    SOCKS = 0x01
    UDP = 0x03
    CONTROL = 0x02
    PING = 0xFF


class Framer:
    def __init__(self):
        self._cache = b""

    def pack(
        self,
        payload: bytes,
        frame_type: int = FrameType.SOCKS,
        channel_id: int = 0,
    ) -> bytes:
        total_length = 1 + 2 + len(payload)
        header = struct.pack("!HBH", total_length, frame_type, channel_id)
        return header + payload

    def feed(self, data: bytes):
        self._cache += data
        frames = []

        while True:
            if len(self._cache) < 5:
                break
            total_length = struct.unpack("!H", self._cache[:2])[0]
            if len(self._cache) < 2 + total_length:
                break

            frame_type = self._cache[2]
            channel_id = struct.unpack("!H", self._cache[3:5])[0]
            payload = self._cache[5 : 2 + total_length]

            frames.append(
                {
                    "type": frame_type,
                    "channel_id": channel_id,
                    "data": payload,
                }
            )
            self._cache = self._cache[2 + total_length :]
        return frames
