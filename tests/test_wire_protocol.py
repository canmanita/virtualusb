import struct

import pytest

from vhserver import protocol as proto
from vhserver.wire import HEADER_LEN, FrameDecoder, Message, decode_body, lz4_block_decompress

try:
    import lz4.block  # noqa: F401
    _HAS_FAST_LZ4 = True
except ImportError:
    _HAS_FAST_LZ4 = False


def test_message_roundtrip_preserves_header_fields():
    msg = Message(13, b"abc", timeout=5000, seq=7, cookie=0xFFFFF80360123456, device=115)
    frame = msg.encode()
    comp, unc = struct.unpack_from("<II", frame, 0)
    assert comp == 0
    assert unc == HEADER_LEN + 3
    assert decode_body(frame[8:]) == msg


def test_reply_echoes_seq_cookie_device_and_clears_timeout():
    req = Message(13, b"", timeout=5000, seq=9, cookie=77, device=5)
    rep = req.reply(14, b"xy")
    assert (rep.seq, rep.cookie, rep.device, rep.timeout) == (9, 77, 5, 0)
    assert rep.mtype == 14


def test_frame_decoder_handles_split_and_batched_input():
    a, b = Message(10).encode(), Message(15, b"\1\2\3\4").encode()
    dec = FrameDecoder()
    out = dec.feed(a[:5])
    assert out == []
    out = dec.feed(a[5:] + b)
    assert [m.mtype for m in out] == [10, 15]
    assert out[1].payload == b"\1\2\3\4"


def test_frame_decoder_rejects_oversized_frame():
    with pytest.raises(ValueError):
        FrameDecoder().feed(struct.pack("<II", 0, 0x4000000))


@pytest.mark.skipif(_HAS_FAST_LZ4, reason="hand-crafted bytes exercise the pure Python fallback's own "
                     "overlapping-copy logic; a real encoder never produces this exact (tiny, no real "
                     "compression benefit) sequence, so the real liblz4 rejects it as non-canonical")
def test_lz4_decompress_literals_and_overlapping_match():
    # token 0x41: 4 literals "abcd", then match offset 4 length 1+4=5 -> overlap copy; ends with literal-only token
    stream = bytes([0x41]) + b"abcd" + struct.pack("<H", 4) + bytes([0x10]) + b"Z"
    assert lz4_block_decompress(stream, 10) == b"abcdabcdaZ"


def test_lz4_size_mismatch_raises():
    with pytest.raises(ValueError):
        lz4_block_decompress(bytes([0x10]) + b"Z", 5)


def test_server_info_layout():
    guid = bytes(range(16))
    info = proto.build_server_info("My Hub", "SERIAL1", "host", "eth0", guid)
    assert len(info) == proto.INFO_LEN
    assert info[0] == 8 and info[1:7] == b"My Hub"
    assert info[129:136] == b"SERIAL1"
    assert info[168:184] == guid
    assert tuple(info[184:187]) == proto.SERVER_VERSION
    assert info[188:192] == b"host" and info[444:448] == b"eth0"
    assert info[700:723] == bytes(23)  # EasyFind block disabled


def test_device_record_layout_and_timestamp_variant():
    rec = proto.DeviceRecord(device_id=115, vid=0x346D, pid=0x5678, vendor="USB", product="Disk 2.0", serial="B1",
                             state=proto.STATE_IN_USE, nickname="nick", intf_class=8, intf_subclass=6,
                             intf_protocol=0x50, user_name=" (me)", user_host="PC", user_guid=bytes([1] * 16),
                             user_ipv4=bytes([10, 0, 0, 5]))
    raw = proto.build_device_record(rec)
    assert len(raw) == proto.DEVICE_RECORD_LEN
    assert struct.unpack_from("<HHI", raw, 0)[:2] == (0x346D, 0x5678)
    assert struct.unpack_from("<I", raw, 132)[0] == 115
    assert raw[136] == proto.STATE_IN_USE
    assert raw[137:153] == bytes([1] * 16) and raw[153:157] == bytes([10, 0, 0, 5])
    assert raw[223:226] == bytes([8, 6, 0x50])
    assert raw[306:308] == b"B1" and raw[226:231] == b" (me)"
    assert len(proto.build_device_record(rec, with_timestamp=True)) == proto.DEVICE_RECORD_LEN + 32


def test_bind_reply_layout():
    blob = bytes(range(1, 51))
    raw = proto.build_bind_reply(proto.BIND_OK, 2, blob, "Prod", "Ser", "SrvSer")
    assert len(raw) == proto.BIND_REPLY_LEN
    assert struct.unpack_from("<i", raw, 0)[0] == 1 and raw[4] == 2
    assert raw[5:55] == blob
    assert raw[65558:65562] == b"Prod" and raw[65686:65689] == b"Ser" and raw[65814:65820] == b"SrvSer"


def test_control_in_reply_pads_to_wlength_and_reports_actual():
    setup = bytes([0x80, 6, 0, 1, 0, 0, 0x40, 0])
    req = proto.parse_control(bytes(8) + setup)
    assert req.is_in and req.length == 0x40
    reply = proto.build_control_reply(req, 18, bytes(range(18)))
    assert reply[:8] == setup
    assert struct.unpack_from("<iI", reply, 8) == (0, 18)
    assert len(reply) == 16 + 0x40


def test_control_out_reply_has_no_data_and_reports_written():
    setup = bytes([0x00, 9, 1, 0, 0, 0, 0, 0])
    req = proto.parse_control(bytes(8) + setup)
    assert not req.is_in
    reply = proto.build_control_reply(req, 0, b"")
    assert len(reply) == 16


def test_control_error_reply_has_negative_status():
    setup = bytes([0x80, 6, 0xEE, 3, 0, 0, 0x12, 0])
    req = proto.parse_control(bytes(8) + setup)
    reply = proto.build_control_reply(req, proto.EPIPE, b"")
    assert struct.unpack_from("<iI", reply, 8) == (-32, 0)


def test_bulk_roundtrip():
    out_payload = bytes([1, 0, 0, 0, 2, 3, 0, 0, 0]) + struct.pack("<I", 4) + b"DATA"
    out = proto.parse_bulk(out_payload)
    assert (out.endpoint, out.length, out.data, out.is_in) == (1, 4, b"DATA", False)
    assert proto.build_bulk_reply(out, 4, b"") == struct.pack("<i", 4)
    in_payload = bytes([0x82, 0, 0, 0, 0, 3, 0, 0, 0]) + struct.pack("<I", 8)
    req = proto.parse_bulk(in_payload)
    assert req.is_in and req.length == 8
    reply = proto.build_bulk_reply(req, 3, b"abc")
    assert reply == struct.pack("<i", 3) + b"abc" + bytes(5)


def test_hello_parse():
    payload = b" (user)".ljust(64, b"\0") + b"HOST".ljust(64, b"\0") + bytes([6, 0, 3, 0])
    hello = proto.parse_hello(payload)
    assert (hello.name, hello.host, hello.version) == (" (user)", "HOST", (6, 0, 3))
