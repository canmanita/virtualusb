"""Payload layouts of the wire protocol (message types, builders, parsers).

Offsets are payload offsets (message offset minus the 33-byte header).
"""
from __future__ import annotations

import struct
import time
from dataclasses import dataclass

# --- client -> server -------------------------------------------------------------------------------------------
C_HELLO = 0
C_KEEPALIVE = 2
C_LIST_DEVICES = 9
C_PING = 10
C_PONG = 15
C_CONTROL = 13
C_BULK = 18
C_BULK_STREAMS = 74
C_QUERY_STATUS = 20
C_RESET_DEVICE = 22
C_BIND = 25
C_UNBIND = 35
C_SET_NICKNAME = 42
C_SET_PASSWORD = 66

# --- server -> client -------------------------------------------------------------------------------------------
S_SERVER_INFO = 1
S_UNBIND_DONE = 7
S_PONG = 11
S_PING = 12
S_CONTROL_DONE = 14
S_DEVICE_RECORD = 16
S_KEEPALIVE_ACK = 17
S_BULK_DONE = 19
S_QUERY_STATUS_DONE = 21
S_RESET_DONE = 23
S_TEXT = 24
S_BIND_DONE = 39
S_PASSWORD_ACK = 67

# generic "status" replies: request type -> reply type, payload is a single s32 status
STATUS_REPLY_TYPES = {22: 23, 26: 27, 28: 29, 30: 31, 50: 32, 51: 23}
# endpoint operations of the 26/28/30 family (clear halt / reset pipe / abort); their payload starts with the endpoint
CLEAR_HALT_TYPES = frozenset({26, 28, 30})
MAX_TRANSFER = 4 * 1024 * 1024  # largest bulk transfer accepted from a client

SERVER_VERSION = (4, 8, 8)
INFO_LEN = 724
DEVICE_RECORD_LEN = 539
BIND_REPLY_LEN = 65878
DESCRIPTOR_BLOB_LEN = 0x10011

# bind status codes (s32)
BIND_OK = 1
BIND_ERROR = -1
BIND_MAX_DEVICES = -2
BIND_UNAUTHORIZED = -3
BIND_MAX_CLIENTS = -5
BIND_PASSWORD_REQUIRED = -8

STATE_GONE = 0
STATE_FREE = 1
STATE_IN_USE = 3

ENODEV = -19
EPIPE = -32
ETIMEDOUT = -110
EIO = -5


def _put_str(buf: bytearray, off: int, text: str, size: int) -> None:
    raw = text.encode("utf-8", "replace")[: size - 1]
    buf[off:off + len(raw)] = raw


def _get_str(data: bytes, off: int, size: int) -> str:
    raw = data[off:off + size].split(b"\0", 1)[0]
    return raw.decode("utf-8", "replace")


@dataclass(frozen=True)
class ClientHello:
    name: str
    host: str
    version: tuple[int, int, int]


def parse_hello(payload: bytes) -> ClientHello:
    version = tuple(payload[128:131]) if len(payload) >= 131 else (0, 0, 0)
    return ClientHello(_get_str(payload, 0, 64), _get_str(payload, 64, 64), version)  # type: ignore[arg-type]


def build_server_info(name: str, serial: str, hostname: str, iface: str, conn_guid: bytes,
                      max_devices: int = 0) -> bytes:
    buf = bytearray(INFO_LEN)
    buf[0] = 8
    _put_str(buf, 1, name, 127)
    _put_str(buf, 129, serial, 37)
    struct.pack_into("<H", buf, 166, max_devices)
    buf[168:184] = conn_guid
    buf[184:187] = bytes(SERVER_VERSION)
    _put_str(buf, 188, hostname, 255)
    _put_str(buf, 444, iface, 255)
    buf[723] = 1
    return bytes(buf)


@dataclass(frozen=True)
class DeviceRecord:
    """What the server announces for one device (message type 16)."""
    device_id: int
    vid: int
    pid: int
    vendor: str
    product: str
    serial: str
    state: int = STATE_FREE
    nickname: str = ""
    num_configs: int = 1
    num_interfaces: int = 1
    intf_class: int = 0
    intf_subclass: int = 0
    intf_protocol: int = 0
    port: int = 0
    hub_ports: int = 0
    user_guid: bytes = bytes(16)
    user_ipv4: bytes = bytes(4)
    user_name: str = ""
    user_host: str = ""


def build_device_record(rec: DeviceRecord, with_timestamp: bool = False) -> bytes:
    buf = bytearray(DEVICE_RECORD_LEN + (32 if with_timestamp else 0))
    struct.pack_into("<HH", buf, 0, rec.vid, rec.pid)
    _put_str(buf, 4, rec.vendor, 64)
    _put_str(buf, 68, rec.product, 64)
    struct.pack_into("<I", buf, 132, rec.device_id)
    buf[136] = rec.state
    buf[137:153] = rec.user_guid
    buf[153:157] = rec.user_ipv4
    _put_str(buf, 157, rec.nickname, 64)
    buf[221] = rec.num_configs
    buf[222] = rec.num_interfaces
    buf[223:226] = bytes((rec.intf_class, rec.intf_subclass, rec.intf_protocol))
    _put_str(buf, 226, rec.user_name, 64)
    _put_str(buf, 306, rec.serial, 64)
    _put_str(buf, 434, rec.user_host, 64)
    buf[499] = rec.port
    buf[538] = rec.hub_ports
    if with_timestamp:
        _put_str(buf, DEVICE_RECORD_LEN, time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()), 32)
    return bytes(buf)


def build_bind_reply(status: int, speed: int, descriptors: bytes, product: str, serial: str,
                     server_serial: str) -> bytes:
    buf = bytearray(BIND_REPLY_LEN)
    struct.pack_into("<i", buf, 0, status)
    buf[4] = speed
    blob = descriptors[:DESCRIPTOR_BLOB_LEN]
    buf[5:5 + len(blob)] = blob
    _put_str(buf, 5 + DESCRIPTOR_BLOB_LEN, product, 122)
    _put_str(buf, 0x10096, serial, 128)
    _put_str(buf, 0x10116, server_serial, 128)
    return bytes(buf)


# --- URB requests / replies -------------------------------------------------------------------------------------
@dataclass(frozen=True)
class ControlRequest:
    setup: bytes
    data: bytes

    @property
    def is_in(self) -> bool:
        return bool(self.setup[0] & 0x80)

    @property
    def length(self) -> int:
        return struct.unpack_from("<H", self.setup, 6)[0]


def parse_control(payload: bytes) -> ControlRequest:
    if len(payload) < 16:
        raise ValueError("control request too short")
    setup = payload[8:16]
    length = struct.unpack_from("<H", setup, 6)[0]
    if setup[0] & 0x80:
        return ControlRequest(setup, b"")
    if len(payload) < 16 + length:
        raise ValueError("control request data truncated")
    return ControlRequest(setup, payload[16:16 + length])


def build_control_reply(req: ControlRequest, status: int, data: bytes) -> bytes:
    """status >= 0 is the number of bytes transferred, negative is an errno-style error."""
    body = data[: req.length] if req.is_in else b""
    pad = bytes(req.length - len(body)) if req.is_in else b""
    return req.setup + struct.pack("<iI", status if status < 0 else 0, max(status, 0)) + body + pad


@dataclass(frozen=True)
class BulkRequest:
    endpoint: int
    flags: int
    kind: int
    length: int
    data: bytes

    @property
    def is_in(self) -> bool:
        return bool(self.endpoint & 0x80)


def parse_bulk(payload: bytes) -> BulkRequest:
    if len(payload) < 13:
        raise ValueError("bulk request too short")
    endpoint = payload[0]
    flags = payload[4]
    kind = struct.unpack_from("<I", payload, 5)[0]
    length = struct.unpack_from("<I", payload, 9)[0]
    if length > MAX_TRANSFER:
        raise ValueError(f"transfer length {length} exceeds the limit")
    if endpoint & 0x80:
        return BulkRequest(endpoint, flags, kind, length, b"")
    if len(payload) < 13 + length:
        raise ValueError("bulk request data truncated")
    return BulkRequest(endpoint, flags, kind, length, payload[13:13 + length])


def build_bulk_reply(req: BulkRequest, status: int, data: bytes) -> bytes:
    """status >= 0 is the number of bytes transferred, negative is an errno-style error."""
    head = struct.pack("<i", status)
    if req.is_in:
        return head + data[: req.length] + bytes(max(0, req.length - len(data)))
    return head


def build_status_reply(status: int) -> bytes:
    return struct.pack("<i", status)


# --- device passwords and nicknames -----------------------------------------------------------------------------
MAX_PASSWORD_BYTES = 127
NICKNAME_FIELD = 64
INSUFFICIENT_PERMISSIONS = b"INSUFFICIENT_PERMISSIONS_MSG\0"


def parse_password(payload: bytes) -> str | None:
    """The password of message 66 (header device id selects the device); None when it is too long to be valid."""
    if len(payload) > MAX_PASSWORD_BYTES:
        return None
    return payload.split(b"\0", 1)[0].decode("utf-8", "replace")


def describe_password_payload(payload: bytes) -> str:
    """Length and character class of the value a client sent, for diagnostics (the value itself is never logged)."""
    if len(payload) == 32 and all(c in b'0123456789abcdef' for c in payload):
        kind = '32 hex digits, lower case'
    elif len(payload) == 32 and all(c in b'0123456789ABCDEF' for c in payload):
        kind = '32 hex digits, upper case'
    elif len(payload) == 32 and all(c in b'0123456789abcdefABCDEF' for c in payload):
        kind = '32 hex digits, mixed case'
    else:
        kind = 'other'
    return f'{len(payload)} bytes ({kind})'


@dataclass(frozen=True)
class NicknameRequest:
    vid: int
    pid: int
    device_id: int
    nickname: str
    serial: str


def parse_set_nickname(payload: bytes) -> NicknameRequest:
    """Message 42: vid u16, pid u16, device id u32, nickname[64], then (newer clients) the device serial string."""
    if len(payload) < 8 + 1:
        raise ValueError("nickname request too short")
    vid, pid, device_id = struct.unpack_from("<HHI", payload, 0)
    nickname = _get_str(payload.ljust(8 + NICKNAME_FIELD, b"\0"), 8, NICKNAME_FIELD)
    serial = _get_str(payload, 8 + NICKNAME_FIELD, 128) if len(payload) > 8 + NICKNAME_FIELD else ""
    return NicknameRequest(vid, pid, device_id, nickname, serial)
