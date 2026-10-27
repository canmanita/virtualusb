import struct
from unittest.mock import MagicMock

import usb1

from vhserver import protocol as proto
import threading
import time

from vhserver.libusb_backend import (ConfigInfo, LibUsbHandle, endpoint_info_of, errno_of,
                                     reconstruct_config_descriptor)


def make_handle(ep_info=None, interfaces=(0,), extra_configs=None):
    raw = MagicMock()
    raw.getConfiguration.return_value = 1
    endpoints = ep_info or {0x01: (2, 512), 0x82: (2, 512), 0x83: (3, 8)}
    configs = {1: ConfigInfo(list(interfaces), endpoints)}
    configs.update(extra_configs or {})
    return raw, LibUsbHandle(raw, configs, 1)


def test_errno_mapping():
    assert errno_of(usb1.USBErrorPipe()) == proto.EPIPE
    assert errno_of(usb1.USBErrorTimeout()) == proto.ETIMEDOUT
    assert errno_of(usb1.USBErrorNoDevice()) == proto.ENODEV
    assert errno_of(usb1.USBErrorOverflow()) == -75
    assert errno_of(usb1.USBErrorOther()) == proto.EIO


def test_claims_all_interfaces_and_releases_on_close():
    raw, handle = make_handle(interfaces=(0, 1))
    assert [c.args[0] for c in raw.claimInterface.call_args_list] == [0, 1]
    handle.close()
    assert [c.args[0] for c in raw.releaseInterface.call_args_list] == [1, 0]
    raw.close.assert_called_once()


def test_control_read_returns_data_length():
    raw, handle = make_handle()
    raw.controlRead.return_value = b"\x12\x01"
    setup = struct.pack("<BBHHH", 0x80, 6, 0x0100, 0, 18)
    assert handle.control(setup, b"", 1000) == (2, b"\x12\x01")
    raw.controlRead.assert_called_with(0x80, 6, 0x0100, 0, 18, 1000)


def test_control_stall_maps_to_epipe():
    raw, handle = make_handle()
    raw.controlRead.side_effect = usb1.USBErrorPipe()
    setup = struct.pack("<BBHHH", 0x80, 6, 0x03EE, 0, 18)
    assert handle.control(setup, b"", 1000) == (proto.EPIPE, b"")


def test_control_write_reports_written_bytes():
    raw, handle = make_handle()
    raw.controlWrite.return_value = 4
    setup = struct.pack("<BBHHH", 0x21, 9, 0x200, 0, 4)
    assert handle.control(setup, b"abcd", 1000) == (4, b"")


def test_set_interface_and_clear_halt_use_dedicated_calls():
    raw, handle = make_handle()
    handle.control(struct.pack("<BBHHH", 0x01, 0x0B, 1, 0, 0), b"", 1000)
    raw.setInterfaceAltSetting.assert_called_with(0, 1)
    handle.control(struct.pack("<BBHHH", 0x02, 0x01, 0, 0x82, 0), b"", 1000)
    raw.clearHalt.assert_called_with(0x82)


def test_set_configuration_same_value_is_noop():
    raw, handle = make_handle()
    assert handle.control(struct.pack("<BBHHH", 0x00, 0x09, 1, 0, 0), b"", 1000) == (0, b"")
    raw.setConfiguration.assert_not_called()


def test_set_configuration_new_value_reclaims_interfaces_and_switches_endpoints():
    raw, handle = make_handle(extra_configs={2: ConfigInfo([0, 1], {0x85: (3, 64)})})
    assert handle.control(struct.pack("<BBHHH", 0x00, 0x09, 2, 0, 0), b"", 1000) == (0, b"")
    raw.setConfiguration.assert_called_with(2)
    assert [c.args[0] for c in raw.claimInterface.call_args_list] == [0, 0, 1]
    raw.interruptRead.return_value = b"\0" * 64
    assert handle.bulk(0x85, 64, b"", 1000)[0] == 64  # endpoint types come from the new configuration


def test_unknown_configuration_value_stalls_without_touching_the_device():
    raw, handle = make_handle()
    assert handle.control(struct.pack("<BBHHH", 0x00, 0x09, 9, 0, 0), b"", 1000) == (proto.EPIPE, b"")
    raw.setConfiguration.assert_not_called()
    raw.releaseInterface.assert_not_called()


def test_failed_set_configuration_reclaims_interfaces():
    raw, handle = make_handle(extra_configs={2: ConfigInfo([0], {})})
    raw.setConfiguration.side_effect = usb1.USBErrorBusy()
    assert handle.control(struct.pack("<BBHHH", 0x00, 0x09, 2, 0, 0), b"", 1000) == (-16, b"")
    assert raw.claimInterface.call_count == 2  # claimed again in the finally block


def test_close_waits_for_transfers_in_flight_and_refuses_new_ones():
    raw, handle = make_handle()
    started, release = threading.Event(), threading.Event()

    def slow_write(*args):
        started.set()
        release.wait(2)
        return 31

    raw.bulkWrite.side_effect = slow_write
    result = []
    worker = threading.Thread(target=lambda: result.append(handle.bulk(0x01, 31, b"x" * 31, 1000)))
    worker.start()
    assert started.wait(1)
    closer = threading.Thread(target=handle.close)
    closer.start()
    time.sleep(0.3)
    assert closer.is_alive() and not raw.close.called  # still waiting for the running transfer
    assert handle.bulk(0x01, 1, b"x", 1000) == (proto.ENODEV, b"")  # new work is refused while closing
    release.set()
    worker.join(2)
    closer.join(2)
    assert result == [(31, b"")] and raw.close.called and raw.releaseInterface.called


def test_bulk_out_returns_transferred():
    raw, handle = make_handle()
    raw.bulkWrite.return_value = 31
    assert handle.bulk(0x01, 31, b"x" * 31, 1000) == (31, b"")


def test_bulk_in_stops_on_short_packet():
    raw, handle = make_handle()
    raw.bulkRead.return_value = b"a" * 36
    status, data = handle.bulk(0x82, 512, b"", 1000)
    assert (status, len(data)) == (36, 36)
    assert raw.bulkRead.call_count == 1


def test_bulk_in_reads_until_length_for_full_packets():
    raw, handle = make_handle()
    raw.bulkRead.side_effect = [b"a" * 512, b"b" * 512]
    status, data = handle.bulk(0x82, 1024, b"", 1000)
    assert status == 1024 and data[:1] == b"a" and data[-1:] == b"b"


def test_bulk_in_timeout_without_data_reports_etimedout():
    raw, handle = make_handle()
    exc = usb1.USBErrorTimeout()
    exc.received = b""
    raw.bulkRead.side_effect = exc
    status, data = handle.bulk(0x82, 64, b"", 1)  # 1 ms overall timeout -> expires at once
    assert (status, data) == (proto.ETIMEDOUT, b"")


def test_bulk_in_partial_data_at_timeout_is_returned():
    raw, handle = make_handle()
    exc = usb1.USBErrorTimeout()
    exc.received = b"xyz"
    raw.bulkRead.side_effect = exc
    status, data = handle.bulk(0x82, 64, b"", 1)
    assert (status, data) == (3, b"xyz")


def test_interrupt_endpoint_uses_interrupt_calls():
    raw, handle = make_handle()
    raw.interruptRead.return_value = b"\0" * 8
    status, data = handle.bulk(0x83, 8, b"", 1000)
    assert status == 8 and raw.interruptRead.called and not raw.bulkRead.called


def test_clear_halt_rejects_unknown_endpoint():
    raw, handle = make_handle()
    assert handle.clear_halt(0x09) == proto.EPIPE
    raw.clearHalt.assert_not_called()


def test_isochronous_is_rejected_cleanly():
    raw, handle = make_handle(ep_info={0x81: (1, 1024)})
    assert handle.bulk(0x81, 1024, b"", 1000) == (proto.EPIPE, b"")


def test_closing_interrupts_blocked_read():
    raw, handle = make_handle()
    exc = usb1.USBErrorTimeout()
    exc.received = b""

    def blocked(*args):
        handle._closing.set()
        raise exc

    raw.bulkRead.side_effect = blocked
    assert handle.bulk(0x82, 64, b"", 0) == (proto.ENODEV, b"")


def test_reset_and_clear_halt_status_codes():
    raw, handle = make_handle()
    assert handle.reset() == 0 and handle.clear_halt(0x82) == 0
    raw.resetDevice.side_effect = usb1.USBErrorNotFound()
    assert handle.reset() == proto.ENODEV


class _Node:
    def __init__(self, items=(), extra=(), **fields):
        self._items, self._extra, self._f = list(items), [bytearray(e) for e in extra], fields

    def __iter__(self):
        return iter(self._items)

    def __getitem__(self, index):
        return self._items[index]

    def getExtra(self):
        return self._extra

    def __getattr__(self, name):
        if name.startswith("get") and name[3:] in self._f:
            return lambda: self._f[name[3:]]
        raise AttributeError(name)


def sample_config(triple=(8, 6, 0x50)):
    ep_out = _Node(Address=0x01, Attributes=2, MaxPacketSize=512, Interval=0)
    ep_in = _Node(Address=0x82, Attributes=2, MaxPacketSize=512, Interval=0,
                  extra=[bytes([6, 0x30, 0, 0, 0, 0])])
    setting = _Node([ep_out, ep_in], extra=[bytes([9, 0x21, 1, 1, 0, 1, 0x22, 5, 0])], Number=0, AlternateSetting=0,
                    NumEndpoints=2, Class=triple[0], SubClass=triple[1], Protocol=triple[2], Descriptor=0)
    interface = _Node([setting])
    return _Node([interface], NumInterfaces=1, ConfigurationValue=1, Descriptor=0, Attributes=0x80, MaxPower=100)


def test_reconstructed_config_descriptor_is_self_consistent():
    blob = reconstruct_config_descriptor(sample_config())
    assert blob[0:2] == bytes([9, 2])
    assert struct.unpack_from("<H", blob, 2)[0] == len(blob)
    assert blob[4] == 1 and blob[5] == 1 and blob[8] == 50  # bMaxPower is in 2 mA units
    walk, kinds = 0, []
    while walk < len(blob):
        kinds.append(blob[walk + 1])
        walk += blob[walk]
    assert walk == len(blob)
    assert kinds == [2, 4, 0x21, 5, 5, 0x30]


def test_endpoint_info_extraction():
    assert endpoint_info_of(sample_config()) == {0x01: (2, 512), 0x82: (2, 512)}
