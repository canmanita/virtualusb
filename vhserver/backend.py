"""USB backend interface. A backend enumerates devices, announces hot-plug events and opens devices for transfers.

All transfer methods are blocking (the server runs them in worker threads) and return (status, data) where
status is >= 0 on success or a negative errno (e.g. -32 stall, -110 timeout, -19 no device).
"""
from __future__ import annotations

import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable

from . import protocol as proto

SPEED_LOW, SPEED_FULL, SPEED_HIGH, SPEED_SUPER = 0, 1, 2, 3


@dataclass(frozen=True)
class DeviceInfo:
    device_id: int
    vid: int
    pid: int
    vendor: str
    product: str
    serial: str
    speed: int
    descriptors: bytes  # raw device descriptor (18 bytes) followed by the full configuration descriptor
    port: int = 0
    hub_ports: int = 0

    def interface_triple(self) -> tuple[int, int, int]:
        """(class, subclass, protocol) of the first interface descriptor found in the configuration."""
        pos = 18
        blob = self.descriptors
        while pos + 2 <= len(blob):
            length, dtype = blob[pos], blob[pos + 1]
            if length == 0:
                break
            if dtype == 4 and pos + 8 <= len(blob):
                return blob[pos + 5], blob[pos + 6], blob[pos + 7]
            pos += length
        return 0, 0, 0

    def counts(self) -> tuple[int, int]:
        """(number of configurations, number of interfaces of the first configuration)."""
        num_cfg = self.descriptors[17] if len(self.descriptors) > 17 else 1
        num_intf = self.descriptors[18 + 4] if len(self.descriptors) > 22 else 1
        return num_cfg, num_intf

    def to_record(self, **overrides) -> proto.DeviceRecord:
        cls, sub, prot = self.interface_triple()
        num_cfg, num_intf = self.counts()
        base = dict(device_id=self.device_id, vid=self.vid, pid=self.pid, vendor=self.vendor, product=self.product,
                    serial=self.serial, num_configs=num_cfg, num_interfaces=num_intf, intf_class=cls,
                    intf_subclass=sub, intf_protocol=prot, port=self.port, hub_ports=self.hub_ports)
        base.update(overrides)
        return proto.DeviceRecord(**base)


class UsbHandle(ABC):
    """An opened (claimed) device."""

    @abstractmethod
    def control(self, setup: bytes, data: bytes, timeout_ms: int) -> tuple[int, bytes]: ...

    @abstractmethod
    def bulk(self, endpoint: int, length: int, data: bytes, timeout_ms: int) -> tuple[int, bytes]: ...

    @abstractmethod
    def reset(self) -> int: ...

    @abstractmethod
    def clear_halt(self, endpoint: int) -> int: ...

    @abstractmethod
    def close(self) -> None: ...


PlugCallback = Callable[[str, DeviceInfo], None]  # ("add" | "remove", device)


class UsbBackend(ABC):
    @abstractmethod
    def start(self, on_plug: PlugCallback) -> None:
        """Begin enumeration; call on_plug('add', dev) for existing devices and for hot-plug events."""

    @abstractmethod
    def open(self, device_id: int) -> UsbHandle: ...

    def stop(self) -> None:
        return None

    def diagnose(self, device_id: int) -> str:
        """Extra facts about a device that failed to open, for the log (OS driver state, ...)."""
        return ""


def utf16_string_descriptor(text: str) -> bytes:
    raw = text.encode("utf-16-le")
    return struct.pack("BB", len(raw) + 2, 3) + raw
