import asyncio
import struct

from test_server_integration import MiniClient, cbw
from vhserver import protocol as proto
from vhserver.backend import DeviceInfo
from vhserver.fakedisk import BLOCK, FakeDiskBackend, FakeDiskHandle
from vhserver.server import VhServer
from vhserver.wire import Message


def scsi(handle: FakeDiskHandle, tag: int, cb: bytes, data_len: int, direction_in: bool, out_data: bytes = b""):
    """Run one SCSI command through the bulk endpoints and return (data, csw_status)."""
    handle.bulk(0x01, 31, cbw(tag, data_len, direction_in, cb), 1000)
    received = b""
    if out_data:
        handle.bulk(0x01, len(out_data), out_data, 1000)
    elif direction_in and data_len:
        while len(received) < data_len:
            status, chunk = handle.bulk(0x82, data_len - len(received), b"", 1000)
            assert status > 0
            received += chunk
    _, csw = handle.bulk(0x82, 13, b"", 1000)
    assert csw[:4] == b"USBS" and struct.unpack_from("<I", csw, 4)[0] == tag
    return received, csw[12]


def new_handle(megabytes: int = 1) -> FakeDiskHandle:
    return FakeDiskBackend(megabytes=megabytes).open(1)


def test_write_then_read_back_multiple_blocks_in_chunks():
    handle = new_handle()
    payload = bytes((i * 7) % 251 for i in range(4 * BLOCK))
    write = bytes([0x2A, 0]) + struct.pack(">IBH", 10, 0, 4) + bytes(3)
    handle.bulk(0x01, 31, cbw(5, len(payload), False, write), 1000)
    for start in range(0, len(payload), 1000):  # arrives in arbitrary chunk sizes
        handle.bulk(0x01, 0, payload[start:start + 1000], 1000)
    _, csw = handle.bulk(0x82, 13, b"", 1000)
    assert csw[12] == 0
    read = bytes([0x28, 0]) + struct.pack(">IBH", 10, 0, 4) + bytes(3)
    data, status = scsi(handle, 6, read, len(payload), True)
    assert status == 0 and data == payload


def test_read_capacity_and_inquiry():
    handle = new_handle(megabytes=2)
    data, status = scsi(handle, 1, bytes([0x25]) + bytes(9), 8, True)
    assert status == 0 and struct.unpack(">II", data) == (2 * 1024 * 1024 // BLOCK - 1, BLOCK)
    data, _ = scsi(handle, 2, bytes([0x12, 0, 0, 0, 36, 0]), 36, True)
    assert data[8:16] == b"VHClone " and data[16:24] == b"RAM Disk"


def test_unknown_command_fails_and_request_sense_reports_illegal_request():
    handle = new_handle()
    _, status = scsi(handle, 3, bytes([0xC0]) + bytes(5), 0, True)
    assert status == 1
    sense, status = scsi(handle, 4, bytes([0x03, 0, 0, 0, 18, 0]), 18, True)
    assert status == 0 and sense[2] == 0x05 and sense[12] == 0x20


def test_out_of_range_read_fails_with_lba_sense():
    handle = new_handle(megabytes=1)
    read = bytes([0x28, 0]) + struct.pack(">IBH", 5000, 0, 1) + bytes(3)
    handle.bulk(0x01, 31, cbw(7, BLOCK, True, read), 1000)
    _, csw = handle.bulk(0x82, 13, b"", 1000)  # failed command: no data phase, straight to the status
    assert csw[12] == 1 and struct.unpack_from("<I", csw, 8)[0] == BLOCK
    sense, _ = scsi(handle, 8, bytes([0x03, 0, 0, 0, 18, 0]), 18, True)
    assert sense[2] == 0x05 and sense[12] == 0x21  # ILLEGAL REQUEST / LBA out of range


def test_standard_control_requests():
    handle = new_handle()
    assert handle.control(struct.pack("<BBHHH", 0x80, 8, 0, 0, 1), b"", 100) == (1, b"\x01")
    assert handle.control(struct.pack("<BBHHH", 0x80, 0, 0, 0, 2), b"", 100) == (2, b"\0\0")
    assert handle.control(struct.pack("<BBHHH", 0xA1, 0xFE, 0, 0, 1), b"", 100) == (1, b"\0")
    assert handle.control(struct.pack("<BBHHH", 0x21, 0xFF, 0, 0, 0), b"", 100) == (0, b"")
    status, string0 = handle.control(struct.pack("<BBHHH", 0x80, 6, 0x0300, 0, 4), b"", 100)
    assert string0 == bytes([4, 3, 9, 4])
    status, product = handle.control(struct.pack("<BBHHH", 0x80, 6, 0x0302, 0x409, 64), b"", 100)
    assert product[2:].decode("utf-16-le") == "RAM Disk"
    assert handle.control(struct.pack("<BBHHH", 0x80, 6, 0x0600, 0, 10), b"", 100)[0] == proto.EPIPE


def test_bulk_in_timeout_when_no_data_pending():
    handle = new_handle()
    assert handle.bulk(0x82, 13, b"", 20) == (proto.ETIMEDOUT, b"")
    assert handle.bulk(0x05, 4, b"", 20) == (proto.EPIPE, b"")
    assert handle.reset() == 0 and handle.clear_halt(0x82) == 0


async def _two_clients_and_hotplug() -> dict:
    backend = FakeDiskBackend(device_id=3, megabytes=1)
    server = VhServer(backend, name="Hub")
    tcp = await asyncio.start_server(server._on_client, "127.0.0.1", 0)
    server._loop = asyncio.get_running_loop()
    backend.start(server._on_plug_threadsafe)
    await asyncio.sleep(0.05)
    port = tcp.sockets[0].getsockname()[1]
    a, b = await MiniClient.connect(port), await MiniClient.connect(port)
    hello = b" (a)".ljust(64, b"\0") + b"PC".ljust(64, b"\0") + bytes([6, 0, 3, 0])
    for c in (a, b):
        await c.send(Message(proto.C_HELLO, hello))
        await c.expect(proto.S_SERVER_INFO)
    out: dict = {}
    await a.send(Message(proto.C_BIND, device=3))
    out["a_bind"] = struct.unpack_from("<i", (await a.expect(proto.S_BIND_DONE)).payload, 0)[0]
    await b.expect(proto.S_DEVICE_RECORD)  # b is told the device is now in use
    await b.send(Message(proto.C_BIND, device=3))
    out["b_bind"] = struct.unpack_from("<i", (await b.expect(proto.S_BIND_DONE)).payload, 0)[0]
    await a.expect(proto.S_DEVICE_RECORD)

    await a.send(Message(proto.C_PING))
    out["pong"] = (await a.expect(proto.S_PONG)).mtype
    await a.send(Message(proto.C_KEEPALIVE))
    out["keepalive"] = (await a.expect(proto.S_KEEPALIVE_ACK)).mtype

    backend.info and server._on_plug_threadsafe("remove", backend.info)  # surprise removal while bound by a
    out["a_unbind"] = struct.unpack_from("<I", (await a.expect(proto.S_UNBIND_DONE)).payload, 0)[0]
    gone = await b.expect(proto.S_DEVICE_RECORD)
    out["gone_state"] = gone.payload[136]
    out["registry_empty"] = not server.devices

    server._on_plug_threadsafe("add", backend.info)
    back = await b.expect(proto.S_DEVICE_RECORD)
    out["back_state"] = back.payload[136]
    for c in (a, b):
        c.writer.close()
    tcp.close()
    await tcp.wait_closed()
    return out


def test_second_client_cannot_bind_and_removal_notifies_everyone():
    out = asyncio.run(_two_clients_and_hotplug())
    assert out["a_bind"] == proto.BIND_OK
    assert out["b_bind"] == proto.BIND_ERROR
    assert out["pong"] == proto.S_PONG and out["keepalive"] == proto.S_KEEPALIVE_ACK
    assert out["a_unbind"] == 1
    assert out["gone_state"] == proto.STATE_GONE and out["registry_empty"]
    assert out["back_state"] == proto.STATE_FREE


def test_device_info_helpers_handle_empty_descriptors():
    info = DeviceInfo(1, 1, 2, "v", "p", "s", 2, b"")
    assert info.interface_triple() == (0, 0, 0)
    assert info.counts() == (1, 1)
