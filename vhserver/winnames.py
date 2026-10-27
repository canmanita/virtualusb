"""Windows: vendor, product and serial of USB mass storage devices, read from the registry.

libusb cannot open a device that usbstor owns, so it cannot read the USB string descriptors. Windows already knows
what the disk reports (SCSI inquiry vendor/product) under ``Enum\\USBSTOR`` and the serial as the USB instance name.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

USB_ENUM = "SYSTEM\\CurrentControlSet\\Enum\\USB"
STOR_ENUM = "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR"
_STOR_KEY = re.compile(r"^[A-Za-z]+(?:&Ven_(?P<ven>[^&]*))?(?:&Prod_(?P<prod>[^&]*))?", re.IGNORECASE)


@dataclass(frozen=True)
class StorageNames:
    vendor: str
    product: str
    serial: str


class WinRegistry:
    """HKLM key listing; a missing key is simply empty."""

    def subkeys(self, path: str) -> list[str]:
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                count = winreg.QueryInfoKey(key)[0]
                return [winreg.EnumKey(key, index) for index in range(count)]
        except OSError:
            return []


def parse_usbstor_key(name: str) -> tuple[str, str] | None:
    match = _STOR_KEY.match(name)
    if match is None or (match["ven"] is None and match["prod"] is None):
        return None
    return (match["ven"] or "").replace("_", " ").strip(), (match["prod"] or "").replace("_", " ").strip()


def lookup(vid: int, pid: int, registry=None, *, bus: int | None = None, ports: tuple | None = None
           ) -> StorageNames | None:
    """Names of the storage device with this VID:PID, or None if there is none or it is genuinely ambiguous.

    ``bus``/``ports`` are accepted (and ignored) only to match the cross-platform ``name_lookup`` callback
    shape used by :mod:`linuxnames`, which needs them -- the registry has nothing keyed by bus/port path.

    ``Enum\\USB\\VID_xxxx&PID_xxxx`` often lists more than one instance for a single physical stick: Windows
    keeps a ghost entry per port/driver-switch it has ever seen it on, and most of those ghosts never
    match anything under ``Enum\\USBSTOR`` (only the instance that is -- or was -- actually bound as a disk
    does). So every instance is tried, and this only gives up when distinct instances resolve to disks with
    different vendor/product strings -- i.e. the VID:PID really is shared by more than one kind of device."""
    registry = registry or WinRegistry()
    instances = registry.subkeys(f"{USB_ENUM}\\VID_{vid:04X}&PID_{pid:04X}")
    matches: dict[str, StorageNames] = {}
    for instance in instances:
        for key in registry.subkeys(STOR_ENUM):
            parsed = parse_usbstor_key(key)
            children = registry.subkeys(f"{STOR_ENUM}\\{key}")
            if parsed and any(child.upper().startswith(instance.upper() + "&") for child in children):
                serial = "" if "&" in instance else instance  # Windows-generated ids ("5&2d6b8c1&0&4") are not serials
                matches[instance] = StorageNames(parsed[0], parsed[1], serial)
                break
    if not matches:
        return None
    if len({(m.vendor, m.product) for m in matches.values()}) > 1:
        return None  # different products share this VID:PID -- can't tell which one is actually connected
    vendor, product = next(iter(matches.values())).vendor, next(iter(matches.values())).product
    serials = {m.serial for m in matches.values() if m.serial}
    if len(serials) > 1:
        # same product, but more than one real serial has shown up under this VID:PID: that means more than
        # one physical unit of it has been plugged in before, and nothing here says which one is live right
        # now -- handing out any one of their serials would misidentify whichever is actually connected (it
        # would, for example, pick up the wrong one's per-device password). The name is still safe to show.
        return StorageNames(vendor, product, "")
    return StorageNames(vendor, product, next(iter(serials), ""))


def available() -> bool:
    return os.name == "nt"
