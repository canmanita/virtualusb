"""Linux: vendor, product and serial of a USB device, read from sysfs when libusb could not read the
device's own string descriptors (missing usbfs permission a udev rule hasn't granted, a device that stalls
string requests, or one with no string descriptors at all).

Unlike Windows -- which has to search ``Enum\\USB\\VID_xxxx&PID_xxxx`` by VID:PID and resolve which of
possibly several ghost instances is the live one (see winnames.py) -- sysfs exposes the exact bus/port
path of the connected device, so there is no "which instance is this" ambiguity to resolve. The VID:PID
the caller already has is still checked against sysfs's own idVendor/idProduct for that path, so a device
that was unplugged and replaced by a different one at the same port between enumeration and this lookup
is never misattributed the new device's identity.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

SYSFS_USB = Path("/sys/bus/usb/devices")


@dataclass(frozen=True)
class DeviceNames:
    vendor: str
    product: str
    serial: str


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def _read_hex(path: Path) -> int | None:
    try:
        return int(_read(path), 16)
    except ValueError:
        return None


def lookup(vid: int, pid: int, registry=None, *, bus: int | None = None, ports: tuple | None = None,
           root: Path = SYSFS_USB) -> DeviceNames | None:
    """Names of the device at this exact bus/port path, or None if sysfs has nothing usable for it.

    ``registry`` is accepted (and ignored) only to match :func:`vhserver.winnames.lookup`'s shape."""
    del registry
    if bus is None or not ports:
        return None
    node = root / f"{bus}-{'.'.join(str(p) for p in ports)}"
    found_vid, found_pid = _read_hex(node / "idVendor"), _read_hex(node / "idProduct")
    if found_vid != vid or found_pid != pid:
        return None  # a different device now sits at this port -- do not hand it this one's old identity
    vendor, product, serial = _read(node / "manufacturer"), _read(node / "product"), _read(node / "serial")
    if not (vendor or product or serial):
        return None
    return DeviceNames(vendor, product, serial)


def available() -> bool:
    return SYSFS_USB.is_dir()
