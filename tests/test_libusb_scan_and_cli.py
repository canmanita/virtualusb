from unittest.mock import MagicMock

import pytest
import usb1

from test_libusb_backend import _Node, sample_config
from vhserver import libusb_backend as lb
from vhserver.__main__ import build_backend, parse_vid_pid
from vhserver.discovery import local_ipv4_addresses


class FakeDev:
    def __init__(self, vid=0x1234, pid=0x5678, cls=0, address=2, ports=(1,), strings=("Maker", "Gadget", "S1")):
        self.vid, self.pid, self.cls, self.address, self.ports, self.strings = vid, pid, cls, address, ports, strings
        self.handle = MagicMock()
        self.handle.getManufacturer.return_value = strings[0]
        self.handle.getProduct.return_value = strings[1]
        self.handle.getSerialNumber.return_value = strings[2]
        self.handle.getConfiguration.return_value = 1
        self.open_error: Exception | None = None

    def getVendorID(self): return self.vid
    def getProductID(self): return self.pid
    def getDeviceClass(self): return self.cls
    def getDeviceSubClass(self): return 0
    def getDeviceProtocol(self): return 0
    def getBusNumber(self): return 1
    def getDeviceAddress(self): return self.address
    def getPortNumberList(self): return list(self.ports)
    def getDeviceSpeed(self): return usb1.SPEED_HIGH
    def getbcdUSB(self): return 0x0200
    def getbcdDevice(self): return 0x0100
    def getMaxPacketSize0(self): return 64
    def getManufacturerDescriptor(self): return 1
    def getProductDescriptor(self): return 2
    def getSerialNumberDescriptor(self): return 3
    def getNumConfigurations(self): return 1
    triple = (8, 6, 0x50)

    def iterConfigurations(self): return iter([sample_config(self.triple)])

    def open(self):
        if self.open_error:
            raise self.open_error
        return self.handle


class FakeContext:
    def __init__(self):
        self.devices: list[FakeDev] = []

    def getDeviceList(self, skip_on_error=True):
        return list(self.devices)


def make_backend(**kwargs):
    backend = lb.LibUsbBackend(**kwargs)
    backend._ctx = FakeContext()
    return backend


def test_scan_reports_add_then_remove_and_skips_hubs():
    backend = make_backend()
    events = []
    stick, hub = FakeDev(), FakeDev(vid=0x8086, pid=1, cls=9, address=3)
    backend._ctx.devices = [stick, hub]
    backend._scan(lambda kind, info: events.append((kind, info)))
    assert [(k, i.vid, i.product, i.vendor, i.serial) for k, i in events] == [("add", 0x1234, "Gadget", "Maker", "S1")]
    info = events[0][1]
    assert info.speed == 2
    assert info.descriptors[1] == 1 and info.descriptors[18 + 1] == 2  # device descriptor then configuration
    assert int.from_bytes(info.descriptors[20:22], "little") == len(info.descriptors) - 18
    backend._ctx.devices = []
    backend._scan(lambda kind, i: events.append((kind, i)))
    assert events[-1][0] == "add"  # a single missed scan is tolerated
    backend._scan(lambda kind, i: events.append((kind, i)))
    assert events[-1][0] == "remove" and events[-1][1].device_id == info.device_id


def test_scan_is_stable_and_ignores_listed_ids():
    backend = make_backend(ignore=[(0x1234, 0x5678)])
    events = []
    backend._ctx.devices = [FakeDev(), FakeDev(vid=0xAAAA, pid=0xBBBB, address=5, ports=(2,))]
    for _ in range(3):
        backend._scan(lambda kind, i: events.append((kind, i.vid)))
    assert events == [("add", 0xAAAA)]


def test_boot_keyboards_and_mice_are_withheld_unless_requested(caplog):
    keyboard = FakeDev()
    keyboard.triple = (3, 1, 1)
    backend = make_backend()
    events = []
    backend._ctx.devices = [keyboard]
    for _ in range(3):  # a withheld device is evaluated once, not on every poll
        backend._scan(lambda kind, i: events.append(kind))
    assert events == []
    assert len(backend._withheld) == 1
    backend._ctx.devices = []
    backend._scan(lambda kind, i: events.append(kind))
    assert not backend._withheld
    opt_in = make_backend(share_input=True)
    opt_in._ctx.devices = [keyboard]
    opt_in._scan(lambda kind, i: events.append(kind))
    assert events == ["add"]


def test_one_broken_device_does_not_hide_the_others():
    backend = make_backend()
    broken = FakeDev(address=7, ports=(3,))
    broken.iterConfigurations = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
    events = []
    backend._ctx.devices = [broken, FakeDev(vid=0xAAAA, pid=0xBBBB, address=5, ports=(2,))]
    backend._scan(lambda kind, i: events.append((kind, i.vid)))
    assert events == [("add", 0xAAAA)]


def test_failing_plug_callback_does_not_break_the_scan():
    backend = make_backend()
    backend._ctx.devices = [FakeDev()]

    def explode(kind, info):
        raise RuntimeError("loop closed")

    backend._scan(explode)  # must not raise
    assert len(backend._keys) == 1


def test_share_hubs_option_lists_hubs():
    backend = make_backend(share_hubs=True)
    events = []
    backend._ctx.devices = [FakeDev(cls=9)]
    backend._scan(lambda kind, i: events.append(kind))
    assert events == ["add"]


def test_unreadable_strings_fall_back_to_hex_ids():
    backend = make_backend()
    dev = FakeDev(vid=0x0424, pid=0x9514)
    dev.open_error = usb1.USBErrorAccess()
    events = []
    backend._ctx.devices = [dev]
    backend._scan(lambda kind, i: events.append(i))
    assert (events[0].vendor, events[0].product, events[0].serial) == ("0x0424", "0x9514", "")


def test_os_names_replace_unreadable_strings():
    from vhserver.winnames import StorageNames

    backend = make_backend(name_lookup=lambda vid, pid, **_: StorageNames("Kingston", "DataTraveler 2.0", "SER1"))
    dev = FakeDev(vid=0x0930, pid=0x6544)
    dev.open_error = usb1.USBErrorNotSupported()
    info = scan_once_added(backend, dev)
    assert (info.vendor, info.product, info.serial) == ("Kingston", "DataTraveler 2.0", "SER1")


def test_failing_name_lookup_falls_back_to_hex_ids():
    def broken(vid, pid, **_):
        raise RuntimeError("registry unavailable")

    backend = make_backend(name_lookup=broken)
    dev = FakeDev(vid=0x0930, pid=0x6544)
    dev.open_error = usb1.USBErrorNotSupported()
    info = scan_once_added(backend, dev)
    assert (info.vendor, info.product) == ("0x0930", "0x6544")


def test_device_carrying_the_hosts_network_is_never_offered():
    backend = make_backend(uplink_check=lambda bus, ports: ports == [1])
    events = []
    backend._ctx.devices = [FakeDev(ports=(1,)), FakeDev(vid=0xAAAA, pid=0xBBBB, address=5, ports=(2,))]
    for _ in range(2):
        backend._scan(lambda kind, i: events.append((kind, i.vid)))
    assert events == [("add", 0xAAAA)]


def test_open_claims_interfaces_and_reports_missing_device():
    backend = make_backend()
    dev = FakeDev()
    events = []
    backend._ctx.devices = [dev]
    backend._scan(lambda kind, i: events.append(i))
    handle = backend.open(events[0].device_id)
    assert isinstance(handle, lb.LibUsbHandle)
    dev.handle.claimInterface.assert_called_with(0)
    with pytest.raises(OSError):
        backend.open(999)


def test_open_failure_is_reported_as_oserror():
    backend = make_backend()
    dev = FakeDev()
    events = []
    backend._ctx.devices = [dev]
    backend._scan(lambda kind, i: events.append(i))
    dev.open_error = usb1.USBErrorAccess()
    with pytest.raises(OSError):
        backend.open(events[0].device_id)
    dev.open_error = None
    dev.handle.claimInterface.side_effect = usb1.USBErrorBusy()
    with pytest.raises(OSError):
        backend.open(events[0].device_id)
    dev.handle.close.assert_called()


def scan_once_added(backend, dev):
    events = []
    backend._ctx.devices = [dev]
    backend._scan(lambda kind, info: events.append(info))
    return events[0]


def test_unplug_needs_consecutive_missed_scans_and_a_comeback_resets_the_count():
    backend = make_backend()
    dev = FakeDev()
    info = scan_once_added(backend, dev)
    events = []
    backend._ctx.devices = []
    backend._scan(lambda kind, i: events.append(kind))
    backend._ctx.devices = [dev]
    backend._scan(lambda kind, i: events.append(kind))
    backend._ctx.devices = []
    backend._scan(lambda kind, i: events.append(kind))
    assert events == [] and info.device_id in backend._infos


def test_device_in_use_gets_a_longer_grace_period():
    backend = make_backend()
    info = scan_once_added(backend, FakeDev())
    backend._open_ids.add(info.device_id)
    backend._ctx.devices = []
    events = []
    for _ in range(lb.GRACE_SCANS + 2):
        backend._scan(lambda kind, i: events.append(kind))
    assert events == []
    for _ in range(lb.GRACE_OPEN_SCANS):
        backend._scan(lambda kind, i: events.append(kind))
    assert events == ["remove"]


def test_device_address_change_does_not_look_like_unplug_replug():
    backend = make_backend()
    first = scan_once_added(backend, FakeDev(address=2))
    events = []
    backend._ctx.devices = [FakeDev(address=9)]  # same port path, new address after a reset
    backend._scan(lambda kind, i: events.append(kind))
    assert events == [] and first.device_id in backend._infos


class FakeBinder:
    def __init__(self, restore_id="USB\\VID_1234&PID_5678\\S1"):
        self.restore_id = restore_id
        self.prepared, self.restored = [], []

    def prepare(self, vid, pid, serial, port):
        self.prepared.append((vid, pid, serial, port))
        return self.restore_id

    def restore(self, instance_id):
        self.restored.append(instance_id)


def test_binder_is_used_on_open_and_driver_restored_on_close():
    binder = FakeBinder()
    backend = make_backend(binder=binder)
    dev = FakeDev()
    info = scan_once_added(backend, dev)
    backend._rediscover = lambda key: dev
    handle = backend.open(info.device_id)
    assert binder.prepared == [(0x1234, 0x5678, "S1", 1)]
    assert info.device_id in backend._open_ids and binder.restored == []
    handle.close()
    assert binder.restored == [binder.restore_id] and info.device_id not in backend._open_ids


def test_driver_is_restored_when_opening_fails_after_the_switch():
    binder = FakeBinder()
    backend = make_backend(binder=binder)
    dev = FakeDev()
    info = scan_once_added(backend, dev)
    backend._rediscover = lambda key: dev
    dev.handle.claimInterface.side_effect = usb1.USBErrorBusy()
    with pytest.raises(OSError):
        backend.open(info.device_id)
    assert binder.restored == [binder.restore_id] and not backend._open_ids


def test_open_without_driver_change_does_not_restore_anything():
    binder = FakeBinder(restore_id=None)
    backend = make_backend(binder=binder)
    info = scan_once_added(backend, FakeDev())
    backend.open(info.device_id).close()
    assert binder.restored == []


def test_rediscover_waits_until_the_device_can_be_opened(monkeypatch):
    monkeypatch.setattr(lb.time, "sleep", lambda s: None)
    backend = make_backend()
    dev = FakeDev()
    key = backend._key(dev)
    flaky = FakeDev()
    flaky.open_error = usb1.USBErrorNotSupported()
    backend._ctx.devices = [flaky]
    calls = {"n": 0}
    original = backend._ctx.getDeviceList

    def listing(skip_on_error=True):
        calls["n"] += 1
        if calls["n"] == 3:
            flaky.open_error = None
        return original(skip_on_error)

    backend._ctx.getDeviceList = listing
    assert backend._rediscover(key) is flaky and calls["n"] == 3


def test_parse_vid_pid_and_backend_selection():
    assert parse_vid_pid("1d6b:0002") == (0x1D6B, 0x0002)
    args = MagicMock(fake_disk=True, hotplug_demo=None, share_hubs=False, ignore=[])
    assert type(build_backend(args)).__name__ == "FakeDiskBackend"
    # windows_bind must be explicit: an unset MagicMock attribute auto-creates a (truthy) MagicMock, which
    # would silently route this into the Windows-only driver-recovery path on every other platform.
    args = MagicMock(fake_disk=False, share_hubs=True, ignore=[(1, 2)], windows_bind=False)
    backend = build_backend(args)
    assert isinstance(backend, lb.LibUsbBackend)


def test_local_addresses_are_ipv4_packed():
    for addr in local_ipv4_addresses():
        assert len(addr) == 4 and not addr.startswith(b"\x7f")


def test_same_device_reappearing_on_another_port_path_is_not_a_second_device():
    """After a driver switch Windows reports another port path for the very same stick."""
    backend = make_backend()
    events = []
    first = FakeDev(ports=(9,))
    backend._ctx.devices = [first]
    backend._scan(lambda kind, i: events.append((kind, i.device_id)))
    device_id = events[0][1]
    moved = FakeDev(ports=(1,))
    backend._ctx.devices = [moved]
    for _ in range(3):
        backend._scan(lambda kind, i: events.append((kind, i.device_id)))
    assert events == [("add", device_id)]                       # no second device, no removal
    assert backend._devices[device_id] is moved                 # open() will use the fresh libusb object
    assert list(backend._keys.values()) == [device_id]


def test_two_identical_devices_swapping_at_once_are_not_guessed():
    backend = make_backend()
    events = []
    backend._ctx.devices = [FakeDev(ports=(1,)), FakeDev(ports=(2,), address=3)]
    backend._scan(lambda kind, i: events.append(kind))
    backend._ctx.devices = [FakeDev(ports=(5,), address=4), FakeDev(ports=(6,), address=5)]  # ambiguous: no rekey
    backend._scan(lambda kind, i: events.append(kind))
    assert events.count("add") == 4


def test_a_second_identical_stick_is_still_a_second_device():
    backend = make_backend()
    events = []
    backend._ctx.devices = [FakeDev(ports=(1,))]
    backend._scan(lambda kind, i: events.append(kind))
    backend._ctx.devices = [FakeDev(ports=(1,)), FakeDev(ports=(2,), address=3)]  # the first one is still there
    backend._scan(lambda kind, i: events.append(kind))
    assert events == ["add", "add"]
