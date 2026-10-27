"""Wire format: frame = [u32 comp_len][u32 uncomp_len][body]; body = 33-byte header + payload.

Implemented from the observed behavior of the stock server and client, for interoperability only.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

HEADER_LEN = 33
MAX_MESSAGE = 0x3200000                 # protocol maximum
SERVER_MAX_MESSAGE = 8 * 1024 * 1024    # what this server accepts from a client (largest real message is ~1 MiB)

# Header layout (offsets inside the 33-byte header, byte 0 is the message type)
_OFF_TIMEOUT = 1       # u32, request timeout in ms (URB requests), 0 in replies
_OFF_SEQ = 5           # u32, request sequence number echoed in the reply
_OFF_COOKIE = 17       # u64, opaque client pointer echoed in the reply
_OFF_DEVICE = 25       # u32, device id
_OFF_SIZE = 29         # u32, payload length


try:  # the C implementation is much faster; the pure Python fallback below is always correct
    import lz4.block as _lz4_block
except ImportError:  # pragma: no cover - depends on the environment
    _lz4_block = None


def _read_length(src: bytes, i: int, base: int) -> tuple[int, int]:
    """Read an LZ4 length extension (runs of 255) starting at src[i]; returns (length, next index)."""
    if base != 15:
        return base, i
    total = base
    while True:
        if i >= len(src):
            raise ValueError("truncated lz4 stream")
        b = src[i]
        i += 1
        total += b
        if b != 255:
            return total, i


def _lz4_python(src: bytes, uncompressed_size: int) -> bytes:
    out = bytearray()
    i, n = 0, len(src)
    while i < n:
        token = src[i]
        i += 1
        literal_len, i = _read_length(src, i, token >> 4)
        if i + literal_len > n or len(out) + literal_len > uncompressed_size:
            raise ValueError("lz4 literal run out of bounds")
        out += src[i:i + literal_len]
        i += literal_len
        if i >= n:
            break
        if i + 2 > n:
            raise ValueError("truncated lz4 stream")
        offset = src[i] | (src[i + 1] << 8)
        i += 2
        match_len, i = _read_length(src, i, token & 15)
        match_len += 4
        if offset == 0 or offset > len(out) or len(out) + match_len > uncompressed_size:
            raise ValueError("corrupt lz4 stream")
        start = len(out) - offset
        if offset >= match_len:
            out += out[start:start + match_len]
        else:  # overlapping copy repeats the last `offset` bytes
            out += (out[start:] * (match_len // offset + 1))[:match_len]
    if len(out) != uncompressed_size:
        raise ValueError(f"lz4 size mismatch {len(out)} != {uncompressed_size}")
    return bytes(out)


def lz4_block_decompress(src: bytes, uncompressed_size: int) -> bytes:
    """LZ4 block decompressor; never produces more than `uncompressed_size` bytes."""
    if uncompressed_size > MAX_MESSAGE:
        raise ValueError("declared size too large")
    if _lz4_block is not None:
        try:
            out = _lz4_block.decompress(src, uncompressed_size=uncompressed_size)
        except Exception as exc:  # noqa: BLE001 - library raises its own error types
            raise ValueError(f"corrupt lz4 stream: {exc}") from exc
        # The C decoder can stop short of `uncompressed_size` on a malformed stream without raising (it
        # only allocates that much buffer, it does not guarantee filling it) -- the pure Python fallback
        # below already enforces an exact match, so the fast path must too, or a short result silently
        # desyncs the caller's framing instead of being rejected.
        if len(out) != uncompressed_size:
            raise ValueError(f"lz4 size mismatch {len(out)} != {uncompressed_size}")
        return out
    return _lz4_python(src, uncompressed_size)


@dataclass(frozen=True)
class Message:
    mtype: int
    payload: bytes = b""
    timeout: int = 0
    seq: int = 0
    cookie: int = 0
    device: int = 0

    def encode(self) -> bytes:
        """Serialize as an uncompressed frame (always accepted by the peer)."""
        header = bytearray(HEADER_LEN)
        header[0] = self.mtype
        struct.pack_into("<I", header, _OFF_TIMEOUT, self.timeout)
        struct.pack_into("<I", header, _OFF_SEQ, self.seq)
        struct.pack_into("<Q", header, _OFF_COOKIE, self.cookie)
        struct.pack_into("<I", header, _OFF_DEVICE, self.device)
        struct.pack_into("<I", header, _OFF_SIZE, len(self.payload))
        body = bytes(header) + self.payload
        return struct.pack("<II", 0, len(body)) + body

    def reply(self, mtype: int, payload: bytes = b"") -> "Message":
        """Reply that echoes seq/cookie/device of this request."""
        return Message(mtype, payload, 0, self.seq, self.cookie, self.device)


def decode_body(body: bytes) -> Message:
    if len(body) < HEADER_LEN:
        raise ValueError("short message")
    size = struct.unpack_from("<I", body, _OFF_SIZE)[0]
    payload = body[HEADER_LEN:]
    if size != len(payload):
        raise ValueError(f"payload size mismatch hdr={size} real={len(payload)}")
    return Message(
        body[0],
        payload,
        struct.unpack_from("<I", body, _OFF_TIMEOUT)[0],
        struct.unpack_from("<I", body, _OFF_SEQ)[0],
        struct.unpack_from("<Q", body, _OFF_COOKIE)[0],
        struct.unpack_from("<I", body, _OFF_DEVICE)[0],
    )


class FrameDecoder:
    """Incremental decoder for a TCP byte stream."""

    def __init__(self, max_message: int = SERVER_MAX_MESSAGE) -> None:
        self._buf = bytearray()
        self._max = min(max_message, MAX_MESSAGE)

    def pending(self) -> bool:
        """True while a frame has been started (header or body bytes buffered) but not yet completed."""
        return bool(self._buf)

    def feed(self, data: bytes) -> list[Message]:
        self._buf += data
        out: list[Message] = []
        while len(self._buf) >= 8:
            comp, unc = struct.unpack_from("<II", self._buf, 0)
            body_len = comp if comp else unc
            if body_len > self._max or unc < HEADER_LEN or unc > self._max:
                raise ValueError("invalid frame sizes")
            if len(self._buf) < 8 + body_len:
                break
            chunk = bytes(self._buf[8:8 + body_len])
            del self._buf[:8 + body_len]
            out.append(decode_body(lz4_block_decompress(chunk, unc) if comp else chunk))
        return out
