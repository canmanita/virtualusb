from vhserver.winusb import WinUsbBinder

BS = chr(92)
OUTPUT = (
    "Instance ID:       USB" + BS + "VID_0930&PID_6544" + BS + "1C1B\n"
    "Status:            Started\n"
    "\n"
    "Instance ID:       USB" + BS + "VID_1111&PID_2222" + BS + "ZZ\n"
    "Status:            Started\n"
    "\n"
    "Instance ID:       USB" + BS + "VID_0930&PID_6544" + BS + "2&3B7C36A2&0&1\n"
    "Status:            Problem\n"
    "Problem Code:      43\n"
)


def test_diagnose_reports_the_pnp_blocks_of_the_device(monkeypatch):
    binder = WinUsbBinder.__new__(WinUsbBinder)
    monkeypatch.setattr("vhserver.winusb.subprocess.run",
                        lambda cmd, **kw: type("R", (), {"returncode": 0, "stdout": OUTPUT})())
    text = binder.diagnose(0x0930, 0x6544)
    assert "1C1B" in text and "Problem Code:      43" in text and "ZZ" not in text


def test_diagnose_says_so_when_the_device_is_unknown(monkeypatch):
    binder = WinUsbBinder.__new__(WinUsbBinder)
    monkeypatch.setattr("vhserver.winusb.subprocess.run",
                        lambda cmd, **kw: type("R", (), {"returncode": 0, "stdout": OUTPUT})())
    assert "no Plug and Play node" in binder.diagnose(0x9999, 0x8888)
