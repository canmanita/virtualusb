"""End-to-end test: a minimal protocol client drives the server with the emulated RAM disk."""
import asyncio
import struct

from vhserver import protocol as proto
from vhserver.fakedisk import FakeDiskBackend
from vhserver.server import VhServer
from vhserver.wire import FrameDecoder, Message


class MiniClient:
    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer
        self.decoder = FrameDecoder()
        self.backlog: list[Message] = []
        self.seq = 0

    @classmethod
    async def connect(cls, port: int) -> "MiniClient":
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        return cls(reader, writer)

    async def send(self, msg: Message) -> None:
        self.writer.write(msg.encode())
        await self.writer.drain()

    async def expect(self, mtype: int, timeout: float = 5.0) -> Message:
        async def pull() -> Message:
            while True:
                for i, m in enumerate(self.backlog):
                    if m.mtype == mtype:
                        return self.backlog.pop(i)
                data = await self.reader.read(65536)
                assert data, "server closed connection"
                self.backlog.extend(self.decoder.feed(data))

        return await asyncio.wait_for(pull(), timeout)

    async def control(self, device: int, setup: bytes, data: bytes = b"") -> tuple[int, bytes]:
        self.seq += 1
        await self.send(Message(proto.C_CONTROL, bytes(8) + setup + data, timeout=5000, seq=self.seq, device=device))
        rep = await self.expect(proto.S_CONTROL_DONE)
        status, actual = struct.unpack_from("<iI", rep.payload, 8)
        return status, rep.payload[16:16 + actual]

    async def bulk(self, device: int, ep: int, length: int, data: bytes = b"") -> tuple[int, bytes]:
        self.seq += 1
        head = bytes([ep, 0, 0, 0, 2 if not ep & 0x80 else 0, 3, 0, 0, 0]) + struct.pack("<I", length)
        await self.send(Message(proto.C_BULK, head + data, seq=self.seq, device=device))
        rep = await self.expect(proto.S_BULK_DONE)
        status = struct.unpack_from("<i", rep.payload, 0)[0]
        return status, rep.payload[4:4 + max(status, 0)]


def cbw(tag: int, data_len: int, direction_in: bool, cb: bytes) -> bytes:
    return b"USBC" + struct.pack("<IIBBB", tag, data_len, 0x80 if direction_in else 0, 0, len(cb)) + cb.ljust(16, b"\0")


async def _run_session() -> dict:
    server = VhServer(FakeDiskBackend(device_id=7, megabytes=1), name="Test Hub")
    tcp = await asyncio.start_server(server._on_client, "127.0.0.1", 0)
    server._loop = asyncio.get_running_loop()
    server.backend.start(server._on_plug_threadsafe)
    await asyncio.sleep(0.05)
    port = tcp.sockets[0].getsockname()[1]
    result: dict = {}
    client = await MiniClient.connect(port)
    hello = b" (tester)".ljust(64, b"\0") + b"TESTPC".ljust(64, b"\0") + bytes([6, 0, 3, 0])
    await client.send(Message(proto.C_HELLO, hello))
    info = await client.expect(proto.S_SERVER_INFO)
    result["server_name"] = info.payload[1:8]
    await client.send(Message(proto.C_LIST_DEVICES))
    record = await client.expect(proto.S_DEVICE_RECORD)
    result["listed_id"] = struct.unpack_from("<I", record.payload, 132)[0]
    result["listed_state"] = record.payload[136]

    await client.send(Message(proto.C_BIND, device=7))
    bind = await client.expect(proto.S_BIND_DONE)
    result["bind_status"] = struct.unpack_from("<i", bind.payload, 0)[0]
    in_use = await client.expect(proto.S_DEVICE_RECORD)
    result["in_use_state"] = in_use.payload[136]
    result["in_use_name"] = in_use.payload[226:233]

    status, data = await client.control(7, bytes([0x80, 6, 0, 1, 0, 0, 0x40, 0]))
    result["dev_desc"] = (status, data[:2], data[8:12])
    status, _ = await client.control(7, bytes([0x80, 6, 0xEE, 3, 0, 0, 0x12, 0]))
    result["stall"] = status

    status, _ = await client.bulk(7, 0x01, 31, cbw(1, 36, True, bytes([0x12, 0, 0, 0, 36, 0])))
    result["cbw_written"] = status
    status, inquiry = await client.bulk(7, 0x82, 36)
    result["inquiry"] = (status, inquiry[8:16])
    status, csw = await client.bulk(7, 0x82, 13)
    result["csw"] = (status, csw[:4], csw[12])

    await client.send(Message(proto.C_UNBIND, device=7))
    unbind = await client.expect(proto.S_UNBIND_DONE)
    result["unbind"] = struct.unpack_from("<I", unbind.payload, 0)[0]
    freed = await client.expect(proto.S_DEVICE_RECORD)
    result["freed_state"] = freed.payload[136]

    await client.send(Message(proto.C_CONTROL, bytes(8) + bytes([0x80, 6, 0, 1, 0, 0, 18, 0]), device=7))
    unbound = await client.expect(proto.S_CONTROL_DONE)
    result["after_unbind"] = struct.unpack_from("<i", unbound.payload, 8)[0]

    client.writer.close()
    tcp.close()
    await tcp.wait_closed()
    return result


def test_full_session_against_ram_disk():
    r = asyncio.run(_run_session())
    assert r["server_name"] == b"Test Hu"
    assert (r["listed_id"], r["listed_state"]) == (7, proto.STATE_FREE)
    assert r["bind_status"] == proto.BIND_OK
    assert r["in_use_state"] == proto.STATE_IN_USE
    assert r["in_use_name"] == b" (teste"
    assert r["dev_desc"][0] == 0  # status field: 0 = success (actual length is the next field)
    assert r["dev_desc"][1] == bytes([18, 1])
    assert r["dev_desc"][2] == bytes([0x09, 0x12, 0x01, 0x00])  # VID 0x1209, PID 0x0001
    assert r["stall"] == proto.EPIPE
    assert r["cbw_written"] == 31
    assert r["inquiry"][0] == 36 and r["inquiry"][1] == b"VHClone "
    assert r["csw"] == (13, b"USBS", 0)
    assert r["unbind"] == 1
    assert r["freed_state"] == proto.STATE_FREE
    assert r["after_unbind"] == proto.ENODEV
