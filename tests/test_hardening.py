import asyncio
import struct
import time
from unittest.mock import MagicMock

import pytest

from test_server_integration import MiniClient
from vhserver import protocol as proto
from vhserver import server as server_module

try:
    import lz4.block  # noqa: F401
    _HAS_FAST_LZ4 = True
except ImportError:
    _HAS_FAST_LZ4 = False
from vhserver import wire
from vhserver.fakedisk import FakeDiskBackend
from vhserver.netpolicy import AccessPolicy
from vhserver.server import Connection, VhServer
from vhserver.wire import FrameDecoder, Message

HELLO = b" (t)".ljust(64, b"\0") + b"PC".ljust(64, b"\0") + bytes([6, 0, 3, 0])


async def start(policy=None, device_id=1):
    server = VhServer(FakeDiskBackend(device_id=device_id, megabytes=1), name="Hub", policy=policy)
    tcp = await asyncio.start_server(server._on_client, "127.0.0.1", 0)
    server._loop = asyncio.get_running_loop()
    server.backend.start(server._on_plug_threadsafe)
    await asyncio.sleep(0.05)
    return server, tcp, tcp.sockets[0].getsockname()[1]


async def stop(server, tcp):
    tcp.close()
    await tcp.wait_closed()
    await server.shutdown()


async def hello(client):
    await client.send(Message(proto.C_HELLO, HELLO))
    await client.expect(proto.S_SERVER_INFO)


def literal_only_lz4(data: bytes) -> bytes:
    """A valid LZ4 block made of literals only (enough to exercise the compressed-frame path)."""
    n = len(data)
    token = bytes([min(n, 15) << 4])
    ext = b""
    if n >= 15:
        rest = n - 15
        ext = b"\xff" * (rest // 255) + bytes([rest % 255])
    return token + ext + data


# ---- LZ4 / framing -------------------------------------------------------------------------------------------
def test_lz4_bomb_is_rejected_before_it_expands():
    bomb = bytes([0x1F]) + b"A" + struct.pack("<H", 1) + b"\xff" * 5000 + b"\x00"  # asks for ~1.2 MB from 5 KB
    with pytest.raises(ValueError):
        wire.lz4_block_decompress(bomb, 100)


@pytest.mark.parametrize("stream", [b"\xf0", b"\x1fA", b"\x10A\x01", b"\xf0\xff"])
def test_lz4_truncated_streams_raise_value_error(stream):
    with pytest.raises(ValueError):
        wire.lz4_block_decompress(stream, 50)


def test_lz4_declared_size_over_protocol_limit_is_rejected():
    with pytest.raises(ValueError):
        wire.lz4_block_decompress(b"\x00", wire.MAX_MESSAGE + 1)


@pytest.mark.skipif(_HAS_FAST_LZ4, reason="hand-crafted bytes exercise the pure Python fallback's own "
                     "overlapping-copy logic; a real encoder never produces this exact sequence, so the "
                     "real liblz4 rejects it as non-canonical")
def test_lz4_overlapping_match_run():
    # 1 literal 'a', a match of offset 1 and length 15+255+0+4 = 274, then 1 literal 'Z'
    stream = bytes([0x1F]) + b"a" + struct.pack("<H", 1) + bytes([0xFF, 0x00]) + bytes([0x10]) + b"Z"
    assert wire.lz4_block_decompress(stream, 276) == b"a" * 275 + b"Z"


def test_decoder_rejects_frames_above_server_limit():
    with pytest.raises(ValueError):
        FrameDecoder().feed(struct.pack("<II", 0, wire.SERVER_MAX_MESSAGE + 1))


def test_compressed_frame_is_decoded_by_the_server():
    async def scenario():
        server, tcp, port = await start()
        client = await MiniClient.connect(port)
        body = Message(proto.C_HELLO, HELLO).encode()[8:]
        block = literal_only_lz4(body)
        client.writer.write(struct.pack("<II", len(block), len(body)) + block)
        await client.writer.drain()
        info = await client.expect(proto.S_SERVER_INFO)
        client.writer.close()
        await stop(server, tcp)
        return info.payload[1:4]

    assert asyncio.run(scenario()) == b"Hub"


# ---- malformed input -----------------------------------------------------------------------------------------
@pytest.mark.parametrize("mtype,payload", [
    (proto.C_CONTROL, b"\x00" * 10),
    (proto.C_BULK, b"\x01\x00"),
    (proto.C_BULK, bytes([0x01, 0, 0, 0, 2, 3, 0, 0, 0]) + struct.pack("<I", 100) + b"short"),
    (proto.C_BULK, bytes([0x82, 0, 0, 0, 0, 3, 0, 0, 0]) + struct.pack("<I", 0xFFFFFFFF)),
])
def test_malformed_requests_drop_only_that_connection(mtype, payload):
    async def scenario():
        server, tcp, port = await start()
        bad, good = await MiniClient.connect(port), await MiniClient.connect(port)
        await hello(good)
        await bad.send(Message(mtype, payload, device=1))
        eof = await asyncio.wait_for(bad.reader.read(65536), 2)
        await good.send(Message(proto.C_PING))
        pong = await good.expect(proto.S_PONG)
        for c in (bad, good):
            c.writer.close()
        await stop(server, tcp)
        return eof, pong.mtype

    eof, pong = asyncio.run(scenario())
    assert eof == b"" and pong == proto.S_PONG


def test_unknown_message_types_are_ignored_not_fatal():
    async def scenario():
        server, tcp, port = await start()
        client = await MiniClient.connect(port)
        await client.send(Message(250, b"junk"))
        await client.send(Message(proto.C_PING))
        reply = await client.expect(proto.S_PONG)
        client.writer.close()
        await stop(server, tcp)
        return reply.mtype

    assert asyncio.run(scenario()) == proto.S_PONG


# ---- access control and resource limits -----------------------------------------------------------------------
def test_connection_from_disallowed_address_is_refused():
    async def scenario():
        server, tcp, port = await start(policy=AccessPolicy(["203.0.113.0/24"]))
        client = await MiniClient.connect(port)
        data = await asyncio.wait_for(client.reader.read(10), 2)
        count = len(server.connections)
        await stop(server, tcp)
        return data, count

    assert asyncio.run(scenario()) == (b"", 0)


def test_slow_client_is_dropped_when_its_outbox_fills():
    writer = MagicMock()
    writer.get_extra_info.return_value = ("10.0.0.2", 5000)

    async def fill():
        conn = Connection(MagicMock(), MagicMock(), writer, 1)
        for _ in range(server_module.OUTBOX_LIMIT):
            conn.send_nowait(Message(proto.S_PONG))
        assert not conn.closed
        conn.send_nowait(Message(proto.S_PONG))
        return conn.closed

    assert asyncio.run(fill()) is True
    writer.close.assert_called()


def test_idle_connection_is_dropped(monkeypatch):
    monkeypatch.setattr(server_module, "PING_INTERVAL_S", 0.05)
    monkeypatch.setattr(server_module, "IDLE_TIMEOUT_S", 0.2)

    async def scenario():
        server, tcp, port = await start()
        client = await MiniClient.connect(port)
        await hello(client)
        got_eof = False
        try:
            while True:
                data = await asyncio.wait_for(client.reader.read(65536), 3)
                if not data:
                    got_eof = True
                    break
        except asyncio.TimeoutError:
            pass
        await stop(server, tcp)
        return got_eof

    assert asyncio.run(scenario()) is True


# ---- bind races ---------------------------------------------------------------------------------------------
def test_concurrent_binds_give_the_device_to_exactly_one_client():
    async def scenario():
        server, tcp, port = await start()
        a, b = await MiniClient.connect(port), await MiniClient.connect(port)
        await hello(a)
        await hello(b)
        await asyncio.gather(a.send(Message(proto.C_BIND, device=1)), b.send(Message(proto.C_BIND, device=1)))
        statuses = [struct.unpack_from("<i", (await c.expect(proto.S_BIND_DONE)).payload, 0)[0] for c in (a, b)]
        owned = server.devices[1].owner is not None
        for c in (a, b):
            c.writer.close()
        await stop(server, tcp)
        return sorted(statuses), owned

    statuses, owned = asyncio.run(scenario())
    assert statuses == [proto.BIND_ERROR, proto.BIND_OK] and owned


def test_rebind_by_the_owner_is_idempotent_and_does_not_leak_a_handle():
    async def scenario():
        server, tcp, port = await start()
        client = await MiniClient.connect(port)
        await hello(client)
        opened = []
        original = server.backend.open
        server.backend.open = lambda device_id: opened.append(device_id) or original(device_id)
        for _ in range(2):
            await client.send(Message(proto.C_BIND, device=1))
            status = struct.unpack_from("<i", (await client.expect(proto.S_BIND_DONE)).payload, 0)[0]
            assert status == proto.BIND_OK
        client.writer.close()
        await stop(server, tcp)
        return opened

    assert asyncio.run(scenario()) == [1]


def test_device_is_freed_when_the_owner_disconnects_and_others_are_told():
    async def scenario():
        server, tcp, port = await start()
        owner, watcher = await MiniClient.connect(port), await MiniClient.connect(port)
        await hello(owner)
        await hello(watcher)
        await owner.send(Message(proto.C_BIND, device=1))
        await owner.expect(proto.S_BIND_DONE)
        await watcher.expect(proto.S_DEVICE_RECORD)  # now in use
        owner.writer.close()
        freed = await watcher.expect(proto.S_DEVICE_RECORD)
        entry_owner = server.devices[1].owner
        watcher.writer.close()
        await stop(server, tcp)
        return freed.payload[136], entry_owner

    assert asyncio.run(scenario()) == (proto.STATE_FREE, None)


def test_client_leaving_during_bind_does_not_leave_the_device_bound():
    async def scenario():
        server, tcp, port = await start()
        client = await MiniClient.connect(port)
        await hello(client)
        await client.send(Message(proto.C_BIND, device=1))
        client.writer.close()
        await asyncio.sleep(0.3)
        state = (server.devices[1].owner, server.devices[1].handle)
        await stop(server, tcp)
        return state

    assert asyncio.run(scenario()) == (None, None)


def test_transfer_that_raises_is_answered_with_an_error():
    async def scenario():
        server, tcp, port = await start()
        client = await MiniClient.connect(port)
        await hello(client)
        await client.send(Message(proto.C_BIND, device=1))
        await client.expect(proto.S_BIND_DONE)
        server.devices[1].handle.control = MagicMock(side_effect=RuntimeError("boom"))
        status, _ = await client.control(1, bytes([0x80, 6, 0, 1, 0, 0, 18, 0]))
        client.writer.close()
        await stop(server, tcp)
        return status

    assert asyncio.run(scenario()) == proto.EIO


def test_urb_flood_gets_busy_replies_instead_of_unbounded_queueing(monkeypatch):
    monkeypatch.setattr(server_module, "URB_QUEUE_LIMIT", 2)

    async def scenario():
        server, tcp, port = await start()
        client = await MiniClient.connect(port)
        await hello(client)
        await client.send(Message(proto.C_BIND, device=1))
        await client.expect(proto.S_BIND_DONE)
        handle = server.devices[1].handle
        original = handle.bulk
        handle.bulk = lambda ep, ln, data, to: (time.sleep(0.2), original(ep, ln, data, to))[1]
        head = bytes([0x82, 0, 0, 0, 0, 3, 0, 0, 0]) + struct.pack("<I", 13)
        for i in range(6):
            await client.send(Message(proto.C_BULK, head, timeout=100, seq=i, device=1))
        replies = [await client.expect(proto.S_BULK_DONE, timeout=10) for _ in range(6)]
        busy = sum(1 for r in replies if struct.unpack_from("<i", r.payload, 0)[0] == server_module.EBUSY)
        client.writer.close()
        await stop(server, tcp)
        return busy

    assert asyncio.run(scenario()) >= 1
