"""Windows: a WinUSB-bound device is used through winusb.dll directly (like the stock server), not through libusb."""
import struct
import threading
import time

import pytest

from vhserver import protocol as proto
from vhserver import winusb_direct as wd


def descriptors(endpoints=((0x81, 2, 512), (0x02, 2, 512)), interfaces=1, config_value=1):
    device = bytes([18, 1, 0, 2, 0, 0, 0, 64]) + struct.pack("<HHH", 0x0930, 0x6544, 0x0100) + bytes([1, 2, 3, 1])
    body = b""
    for number in range(interfaces):
        eps = endpoints if number == 0 else ()
        body += bytes([9, 4, number, 0, len(eps), 8, 6, 0x50, 0])
        for address, kind, size in eps:
            body += bytes([7, 5, address, kind]) + struct.pack("<H", size) + bytes([0])
    config = bytes([9, 2]) + struct.pack("<H", 9 + len(body)) + bytes([interfaces, config_value, 0, 0x80, 50]) + body
    return device + config


class FakeApi:
    def __init__(self):
        self.calls, self.paths, self.fail = [], [], {}

    def _do(self, name, *args):
        self.calls.append((name, *args))
        error = self.fail.get(name)
        if error is not None:
            raise error
        return None

    def find_path(self, guid, instance_id):
        self.calls.append(("find_path", guid, instance_id))
        return self.paths.pop(0) if self.paths else None

    def open_device(self, path):
        self._do("open_device", path)
        return 11

    def initialize(self, file_handle):
        self._do("initialize", file_handle)
        return 22

    def control_in(self, h, bm, req, value, index, length, timeout_ms):
        self._do("control_in", bm, req, value, index, length, timeout_ms)
        return b"\x12" * min(length, 18)

    def control_out(self, h, bm, req, value, index, data, timeout_ms):
        self._do("control_out", bm, req, value, index, bytes(data), timeout_ms)
        return len(data)

    def read(self, h, pipe, length, timeout_ms):
        self._do("read", pipe, length, timeout_ms)
        return b"\xaa" * length

    def write(self, h, pipe, data, timeout_ms):
        self._do("write", pipe, bytes(data), timeout_ms)
        return len(data)

    def reset_pipe(self, h, pipe):
        self._do("reset_pipe", pipe)

    def abort_pipe(self, h, pipe):
        self._do("abort_pipe", pipe)

    def set_alt(self, h, alt):
        self._do("set_alt", alt)

    def free(self, h):
        self._do("free", h)

    def close_file(self, file_handle):
        self._do("close_file", file_handle)

    def names(self):
        return [c[0] for c in self.calls]


def make_handle(api=None, **kw):
    api = api or FakeApi()
    interfaces, endpoints, config_value = wd.parse_config(descriptors(**kw))
    closed = []
    handle = wd.WinUsbDirectHandle(api, 11, 22, endpoints, config_value, on_close=lambda: closed.append(1))
    return handle, api, closed


def test_endpoints_and_configuration_are_read_from_the_raw_descriptors():
    interfaces, endpoints, config_value = wd.parse_config(descriptors(endpoints=((0x81, 2, 512), (0x02, 2, 512), (0x83, 3, 64))))
    assert interfaces == [0] and config_value == 1
    assert endpoints == {0x81: (2, 512), 0x02: (2, 512), 0x83: (3, 64)}


def test_garbage_descriptors_give_an_empty_result_not_a_crash():
    assert wd.parse_config(b"\x00" * 5) == ([], {}, 1)
    assert wd.parse_config(b"") == ([], {}, 1)


def test_control_read_and_write_go_through_the_api():
    handle, api, _ = make_handle()
    status, data = handle.control(bytes([0x80, 6, 0, 1, 0, 0, 18, 0]), b"", 2000)
    assert (status, len(data)) == (18, 18) and ("control_in", 0x80, 6, 0x100, 0, 18, 2000) in api.calls
    status, _ = handle.control(bytes([0x21, 0xFF, 0, 0, 0, 0, 3, 0]), b"abc", 1000)
    assert status == 3 and ("control_out", 0x21, 0xFF, 0, 0, b"abc", 1000) in api.calls


def test_standard_requests_winusb_forbids_are_emulated():
    handle, api, _ = make_handle()
    assert handle.control(bytes([0x00, 9, 1, 0, 0, 0, 0, 0]), b"", 1000) == (0, b"")        # already configured
    assert handle.control(bytes([0x00, 9, 7, 0, 0, 0, 0, 0]), b"", 1000)[0] == proto.EPIPE  # no such configuration
    assert handle.control(bytes([0x01, 11, 2, 0, 0, 0, 0, 0]), b"", 1000) == (0, b"")
    assert handle.control(bytes([0x02, 1, 0, 0, 0x81, 0, 0, 0]), b"", 1000) == (0, b"")
    assert ("set_alt", 2) in api.calls and ("reset_pipe", 0x81) in api.calls
    assert not any(c[0] in ("control_in", "control_out") for c in api.calls)


@pytest.mark.parametrize("code,expected", [(121, proto.ETIMEDOUT), (31, proto.EPIPE), (1167, proto.ENODEV),
                                           (433, proto.ENODEV), (5, proto.EIO)])
def test_windows_errors_become_the_errnos_the_client_expects(code, expected):
    api = FakeApi()
    api.fail["control_in"] = wd.WinUsbIoError(code)
    handle, _, _ = make_handle(api)
    assert handle.control(bytes([0x80, 6, 0, 1, 0, 0, 18, 0]), b"", 1000)[0] == expected


def test_bulk_in_and_out():
    handle, api, _ = make_handle()
    status, data = handle.bulk(0x81, 36, b"", 3000)
    assert (status, data) == (36, b"\xaa" * 36) and ("read", 0x81, 36, 3000) in api.calls
    assert handle.bulk(0x02, 31, b"x" * 31, 0)[0] == 31
    assert ("write", 0x02, b"x" * 31, wd.DEFAULT_TIMEOUT_MS) in api.calls  # 0 means "no timeout given": use the default


def test_a_stalled_bulk_pipe_reports_epipe_and_isochronous_is_refused():
    api = FakeApi()
    api.fail["read"] = wd.WinUsbIoError(31)
    handle, _, _ = make_handle(api, endpoints=((0x81, 2, 512), (0x84, 1, 192)))
    assert handle.bulk(0x81, 13, b"", 1000)[0] == proto.EPIPE
    assert handle.bulk(0x84, 192, b"", 1000)[0] == proto.EPIPE


def test_reset_and_clear_halt():
    handle, api, _ = make_handle()
    assert handle.reset() == 0 and ("reset_pipe", 0x81) in api.calls and ("reset_pipe", 0x02) in api.calls
    assert handle.clear_halt(0x81) == 0
    assert handle.clear_halt(0x55) == proto.EPIPE            # not an endpoint of this device


def test_close_aborts_pipes_frees_everything_once_and_refuses_new_work():
    handle, api, closed = make_handle()
    handle.close()
    handle.close()
    assert closed == [1] and api.names().count("free") == 1 and api.names().count("close_file") == 1
    assert {("abort_pipe", 0x81), ("abort_pipe", 0x02)} <= set(api.calls)
    assert handle.bulk(0x81, 4, b"", 100)[0] == proto.ENODEV and handle.reset() == proto.ENODEV


def test_close_waits_for_a_transfer_in_flight():
    api = FakeApi()
    gate = threading.Event()
    original = api.read
    api.read = lambda h, pipe, length, timeout_ms: (gate.wait(5), original(h, pipe, length, timeout_ms))[1]
    handle, _, closed = make_handle(api)
    reader = threading.Thread(target=lambda: handle.bulk(0x81, 8, b"", 5000))
    reader.start()
    time.sleep(0.1)
    closer = threading.Thread(target=handle.close)
    closer.start()
    time.sleep(0.2)
    assert closed == [] and "free" not in api.names()        # still waiting for the transfer
    gate.set()
    reader.join(2)
    closer.join(2)
    assert closed == [1] and "free" in api.names()


# ---- opening ----------------------------------------------------------------------------------------------------------
def opener(api, guid="{GUID}", wait_s=2.0):
    return wd.WinUsbDirectOpener(api, guid_of=lambda instance_id: guid, wait_s=wait_s, sleep=lambda s: None)


def test_opener_waits_for_the_interface_to_appear_then_opens():
    api = FakeApi()
    api.paths = [None, None, "PATH"]
    closed = []
    handle = opener(api).open("INSTANCE", descriptors(), on_close=lambda: closed.append(1))
    assert api.names().count("find_path") == 3 and ("open_device", "PATH") in api.calls and ("initialize", 11) in api.calls
    assert isinstance(handle, wd.WinUsbDirectHandle)


def test_opener_retries_while_the_device_is_still_starting():
    api = FakeApi()
    api.paths = ["PATH", "PATH"]
    attempts = {"n": 0}
    original = api.initialize

    def flaky(file_handle):
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise wd.WinUsbIoError(2)
        return original(file_handle)

    api.initialize = flaky
    handle = opener(api).open("INSTANCE", descriptors(), on_close=lambda: None)
    assert attempts["n"] == 2 and "close_file" in api.names() and handle is not None   # the failed attempt was closed


def test_opener_gives_up_after_the_wait():
    api = FakeApi()
    clock = iter(range(0, 1000, 1))
    slow = wd.WinUsbDirectOpener(api, guid_of=lambda i: "{G}", wait_s=3, sleep=lambda s: None,
                                 clock=lambda: float(next(clock)))
    with pytest.raises(OSError):
        slow.open("INSTANCE", descriptors(), on_close=lambda: None)


def test_opener_refuses_composite_devices_before_opening_anything():
    api = FakeApi()
    api.paths = ["PATH"]
    with pytest.raises(OSError):
        opener(api).open("INSTANCE", descriptors(interfaces=2), on_close=lambda: None)
    assert api.names() == []


def test_opener_needs_the_interface_guid():
    with pytest.raises(OSError):
        wd.WinUsbDirectOpener(FakeApi(), guid_of=lambda i: None, wait_s=1, sleep=lambda s: None).open(
            "INSTANCE", descriptors(), on_close=lambda: None)


def test_guid_is_read_from_the_registry_value(monkeypatch):
    values = {"DeviceInterfaceGUID": "{AAAA}"}
    assert wd.guid_from_values(lambda name: values.get(name)) == "{AAAA}"
    assert wd.guid_from_values(lambda name: ["{BBBB}", "{CCCC}"] if name == "DeviceInterfaceGUIDs" else None) == "{BBBB}"
    assert wd.guid_from_values(lambda name: None) is None
