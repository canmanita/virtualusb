"""Linux: recognise a USB device that carries this machine's own network connection.

Handing the onboard Ethernet of a Raspberry Pi 3 / 4 (or a USB Ethernet / Wi-Fi dongle that is the only way out) to
a remote client would cut the server off from the network, so such a device is never offered.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable

SYSFS_USB = Path("/sys/bus/usb/devices")
ROUTE = Path("/proc/net/route")
ROUTE6 = Path("/proc/net/ipv6_route")
_ZERO6 = "0" * 32
RTF_REJECT = 0x0200  # "unreachable" placeholder routes (shown on lo) are not a way out


def default_route_interfaces(route: Path = ROUTE, route6: Path = ROUTE6) -> set[str]:
    names: set[str] = set()
    try:
        for line in route.read_text(encoding="ascii", errors="replace").splitlines()[1:]:
            fields = line.split()
            if len(fields) > 7 and fields[1] == "00000000" and fields[7] == "00000000":
                names.add(fields[0])
    except OSError:
        pass
    try:
        for line in route6.read_text(encoding="ascii", errors="replace").splitlines():
            fields = line.split()
            if len(fields) >= 10 and fields[0] == _ZERO6 and fields[1] == "00" and not int(fields[8], 16) & RTF_REJECT:
                names.add(fields[-1])
    except OSError:
        pass
    return names


def sysfs_interfaces(device_name: str, sysfs: Path = SYSFS_USB) -> set[str]:
    """Network interfaces of a USB device, e.g. ``1-1.1:1.0/net/eth0`` for device ``1-1.1``."""
    try:
        return {entry.name for entry in sysfs.glob(f"{device_name}:*/net/*")}
    except OSError:
        return set()


def carries_uplink(bus: int, ports: list[int], *, interfaces_of: Callable[[str], set[str]] = sysfs_interfaces,
                   route: Path = ROUTE, route6: Path = ROUTE6) -> bool:
    """True when a network interface of this USB device holds a default route."""
    if not ports:
        return False
    interfaces = interfaces_of(f"{bus}-{'.'.join(str(p) for p in ports)}")
    return bool(interfaces) and bool(interfaces & default_route_interfaces(route, route6))
