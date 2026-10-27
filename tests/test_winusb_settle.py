import pytest

from vhserver import winusb
from vhserver.winusb import UsbNode, WinUsbBinder


def make(monkeypatch, clock):
    binder = WinUsbBinder.__new__(WinUsbBinder)
    binder._restored_at = {}
    slept, installed = [], []

    class Api:
        def usb_nodes(self):
            return [UsbNode("USB" + chr(92) + "VID_1234&PID_5678" + chr(92) + "S1", 0x1234, 0x5678, "S1", "USBSTOR", 3)]

        def install_winusb(self, instance_id):
            installed.append(instance_id)

    binder._api = Api()
    monkeypatch.setattr(WinUsbBinder, "is_admin", staticmethod(lambda: True))
    monkeypatch.setattr(winusb.time, "monotonic", clock)
    monkeypatch.setattr(winusb.time, "sleep", slept.append)
    monkeypatch.setattr("vhserver.winusb.subprocess.run",
                        lambda cmd, **kw: type("R", (), {"returncode": 0, "stdout": ""})())
    return binder, slept, installed


def test_a_quick_second_use_waits_for_windows_to_settle(monkeypatch):
    now = [100.0]
    binder, slept, installed = make(monkeypatch, lambda: now[0])
    iid = binder.prepare(0x1234, 0x5678, "S1", 3)
    binder.restore(iid)
    now[0] += 3.0
    binder.prepare(0x1234, 0x5678, "S1", 3)
    assert len(slept) == 1 and slept[0] == pytest.approx(winusb.SETTLE_AFTER_RESTORE_S - 3.0)
    assert len(installed) == 2


def test_no_waiting_when_enough_time_has_passed_or_for_a_new_device(monkeypatch):
    now = [100.0]
    binder, slept, installed = make(monkeypatch, lambda: now[0])
    iid = binder.prepare(0x1234, 0x5678, "S1", 3)
    binder.restore(iid)
    now[0] += winusb.SETTLE_AFTER_RESTORE_S + 1
    binder.prepare(0x1234, 0x5678, "S1", 3)
    assert slept == []
