"""With a direct opener the device is opened by instance id; libusb is not asked to enumerate again."""
import pytest

from test_libusb_scan_and_cli import FakeDev, make_backend, scan_once_added
from vhserver import libusb_backend as lb
from vhserver.winusb import UsbNode, WinUsbBinder, WinUsbError

BS = chr(92)
INSTANCE = "USB" + BS + "VID_1234&PID_5678" + BS + "S1"


class DirectBinder:
    def __init__(self, switched=True):
        self.switched, self.prepared, self.restored = switched, [], []

    def prepare_direct(self, vid, pid, serial, port):
        self.prepared.append((vid, pid, serial, port))
        return INSTANCE, self.switched

    def restore(self, instance_id):
        self.restored.append(instance_id)


class Opener:
    def __init__(self, fail=False):
        self.opened, self.fail, self.handles = [], fail, []

    def open(self, instance_id, descriptors, on_close):
        self.opened.append((instance_id, len(descriptors)))
        if self.fail:
            raise OSError("the WinUSB interface of the device did not appear")
        handle = type("H", (), {"close": lambda self_: on_close()})()
        self.handles.append(handle)
        return handle


def backend_with(binder, opener):
    backend = make_backend(binder=binder)
    backend._direct_opener = opener
    return backend


def test_open_goes_through_the_direct_opener_and_never_lists_devices_again():
    binder, opener = DirectBinder(), Opener()
    backend = backend_with(binder, opener)
    info = scan_once_added(backend, FakeDev())
    listed = []
    backend._ctx.getDeviceList = lambda skip_on_error=True: listed.append(1) or []
    handle = backend.open(info.device_id)
    assert opener.opened == [(INSTANCE, len(info.descriptors))] and listed == []   # no libusb enumeration
    assert binder.prepared == [(0x1234, 0x5678, "S1", 1)] and info.device_id in backend._open_ids
    assert backend._in_switch_window(0x1234, 0x5678)
    handle.close()
    assert binder.restored == [INSTANCE] and info.device_id not in backend._open_ids


def test_a_device_that_was_already_on_winusb_is_not_restored_afterwards():
    binder = DirectBinder(switched=False)
    backend = backend_with(binder, Opener())
    info = scan_once_added(backend, FakeDev())
    backend.open(info.device_id).close()
    assert binder.restored == []


def test_a_failed_open_puts_the_driver_back():
    binder = DirectBinder()
    backend = backend_with(binder, Opener(fail=True))
    info = scan_once_added(backend, FakeDev())
    with pytest.raises(OSError):
        backend.open(info.device_id)
    assert binder.restored == [INSTANCE] and info.device_id not in backend._open_ids


def test_without_a_direct_opener_the_libusb_path_is_unchanged():
    from test_libusb_scan_and_cli import FakeBinder
    binder = FakeBinder()
    backend = make_backend(binder=binder)
    dev = FakeDev()
    info = scan_once_added(backend, dev)
    backend._rediscover = lambda key: dev
    backend.open(info.device_id).close()
    assert binder.prepared and binder.restored


# ---- the binder side ----------------------------------------------------------------------------------------------
def node(service, suffix="S1", port=1):
    return UsbNode("USB" + BS + "VID_1234&PID_5678" + BS + suffix, 0x1234, 0x5678, suffix, service, port)


def binder_with(monkeypatch, nodes):
    binder = WinUsbBinder.__new__(WinUsbBinder)
    installed = []

    class Api:
        def usb_nodes(self):
            return nodes

        def install_winusb(self, instance_id):
            installed.append(instance_id)

    binder._api = Api()
    monkeypatch.setattr(WinUsbBinder, "is_admin", staticmethod(lambda: True))
    return binder, installed


def test_prepare_direct_reports_whether_it_switched_the_driver(monkeypatch):
    binder, installed = binder_with(monkeypatch, [node("USBSTOR")])
    assert binder.prepare_direct(0x1234, 0x5678, "S1", 1) == (INSTANCE, True) and installed == [INSTANCE]
    binder, installed = binder_with(monkeypatch, [node("WinUSB")])
    assert binder.prepare_direct(0x1234, 0x5678, "S1", 1) == (INSTANCE, False) and installed == []


def test_prepare_direct_keeps_the_safety_rules(monkeypatch):
    binder, installed = binder_with(monkeypatch, [node("usbccgp")])
    with pytest.raises(WinUsbError):
        binder.prepare_direct(0x1234, 0x5678, "S1", 1)
    assert installed == []
