import os

import pytest

from vhserver.winusb import (UsbNode, WinUsbBinder, WinUsbError, new_interface_guid, parse_instance_id, select_node)


def node(vid=0x1234, pid=0x5678, suffix="S1", service="USBSTOR", port=3):
    return UsbNode(f"USB\\VID_{vid:04X}&PID_{pid:04X}\\{suffix}", vid, pid, suffix, service, port)


@pytest.mark.parametrize("text,expected", [
    ("USB\\VID_046D&PID_C07E\\497132493435", (0x046D, 0xC07E, "497132493435")),
    ("usb\\vid_04d9&pid_a1cd\\5&c94d647&0&4", (0x04D9, 0xA1CD, "5&c94d647&0&4")),
    ("USB\\VID_046D&PID_C07E&MI_00\\6&1&0&0000", None),
    ("USB\\ROOT_HUB30\\4&121C824C&0&0", None),
    ("PCI\\VEN_8086", None),
])
def test_instance_id_parsing(text, expected):
    assert parse_instance_id(text) == expected


def test_select_node_matches_by_serial_then_port():
    a, b = node(suffix="AAA", port=1), node(suffix="BBB", port=2)
    assert select_node([a, b], 0x1234, 0x5678, "BBB", None) is b
    c, d = node(suffix="5&1&0&1", port=1), node(suffix="5&1&0&2", port=2)
    assert select_node([c, d], 0x1234, 0x5678, "", 2) is d


def test_select_node_refuses_ambiguity_and_missing_devices():
    twins = [node(suffix="5&1&0&1", port=1), node(suffix="5&1&0&2", port=1)]
    with pytest.raises(WinUsbError):
        select_node(twins, 0x1234, 0x5678, "", 1)
    with pytest.raises(WinUsbError):
        select_node([node()], 0x9999, 0x5678, "", None)


@pytest.mark.parametrize("service", ["HidUsb", "usbhub3", "usbccgp", "BTHUSB", "kbdhid"])
def test_select_node_refuses_dangerous_devices(service):
    with pytest.raises(WinUsbError):
        select_node([node(service=service)], 0x1234, 0x5678, "S1", None)


def test_interface_guid_format():
    guid = new_interface_guid()
    assert guid.startswith("{") and guid.endswith("}") and len(guid) == 38


def test_binder_logic_without_touching_the_system(monkeypatch):
    binder = WinUsbBinder.__new__(WinUsbBinder)
    calls = []

    class Api:
        def usb_nodes(self):
            return [node(service="USBSTOR")]

        def install_winusb(self, instance_id):
            calls.append(instance_id)

    binder._api = Api()
    monkeypatch.setattr(WinUsbBinder, "is_admin", staticmethod(lambda: True))
    assert binder.prepare(0x1234, 0x5678, "S1", 3) == "USB\\VID_1234&PID_5678\\S1" and calls
    monkeypatch.setattr(Api, "usb_nodes", lambda self: [node(service="WinUSB")])
    assert binder.prepare(0x1234, 0x5678, "S1", 3) is None  # already WinUSB: nothing to restore
    monkeypatch.setattr(WinUsbBinder, "is_admin", staticmethod(lambda: False))
    with pytest.raises(WinUsbError):
        binder.prepare(0x1234, 0x5678, "S1", 3)


def test_restore_runs_pnputil_remove_then_rescan(monkeypatch):
    binder = WinUsbBinder.__new__(WinUsbBinder)
    seen = []

    class Done:
        returncode = 0
        stdout = ""

    monkeypatch.setattr("vhserver.winusb.subprocess.run", lambda cmd, **kw: seen.append(cmd) or Done())
    binder.restore("USB\\VID_1234&PID_5678\\S1")
    assert seen == [["pnputil", "/remove-device", "USB\\VID_1234&PID_5678\\S1"], ["pnputil", "/scan-devices"]]


@pytest.mark.skipif(os.name != "nt", reason="SetupAPI is Windows only")
def test_real_enumeration_runs_without_changing_anything():
    nodes = WinUsbBinder()._api.usb_nodes()
    assert nodes and all(n.instance_id.upper().startswith("USB\\VID_") for n in nodes)


def test_binder_refuses_a_generated_duplicate_of_a_device_it_already_switched(monkeypatch):
    """The field hang: the same stick showed up twice and the second node never finished installing WinUSB."""
    binder = WinUsbBinder.__new__(WinUsbBinder)
    installed = []

    class Api:
        def usb_nodes(self):
            return [node(suffix="REALSERIAL", service="WinUSB", port=9), node(suffix="2&3B7C36A2&0&1", service="USBSTOR", port=1)]

        def install_winusb(self, instance_id):
            installed.append(instance_id)

    binder._api = Api()
    monkeypatch.setattr(WinUsbBinder, "is_admin", staticmethod(lambda: True))
    with pytest.raises(WinUsbError):
        binder.prepare(0x1234, 0x5678, "", 1)
    assert installed == []


def test_binder_still_switches_a_second_stick_that_has_its_own_serial(monkeypatch):
    binder = WinUsbBinder.__new__(WinUsbBinder)
    installed = []

    class Api:
        def usb_nodes(self):
            return [node(suffix="SERIAL-A", service="WinUSB", port=9), node(suffix="SERIAL-B", service="USBSTOR", port=1)]

        def install_winusb(self, instance_id):
            installed.append(instance_id)

    binder._api = Api()
    monkeypatch.setattr(WinUsbBinder, "is_admin", staticmethod(lambda: True))
    assert binder.prepare(0x1234, 0x5678, "SERIAL-B", 1).endswith("SERIAL-B") and len(installed) == 1


def test_diagnose_never_raises(monkeypatch):
    import subprocess as sp
    binder = WinUsbBinder.__new__(WinUsbBinder)

    def hang(cmd, **kw):
        raise sp.TimeoutExpired(cmd, 8)

    monkeypatch.setattr("vhserver.winusb.subprocess.run", hang)
    assert "timed out" in binder.diagnose(0x0930, 0x6544)
