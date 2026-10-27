"""Emulated USB mass-storage device (SCSI over Bulk-Only Transport) backed by RAM.

Used to test the server end to end with the stock client without touching real hardware.
"""
from __future__ import annotations

import queue
import struct
import threading
import time

from . import protocol as proto
from .backend import (SPEED_HIGH, DeviceInfo, PlugCallback, UsbBackend, UsbHandle, utf16_string_descriptor)

BLOCK = 512
EP_OUT, EP_IN = 0x01, 0x82
CBW_SIG, CSW_SIG = b"USBC", b"USBS"

DEVICE_DESCRIPTOR = bytes([
    18, 1, 0x00, 0x02, 0, 0, 0, 64, 0x09, 0x12, 0x01, 0x00, 0x00, 0x01, 1, 2, 3, 1,
])  # VID 0x1209 PID 0x0001 (pid.codes test VID/PID)
CONFIG_DESCRIPTOR = bytes([
    9, 2, 32, 0, 1, 1, 0, 0x80, 50,
    9, 4, 0, 0, 2, 8, 6, 0x50, 0,
    7, 5, EP_OUT, 2, 0x00, 0x02, 0,
    7, 5, EP_IN, 2, 0x00, 0x02, 0,
])
STRINGS = {1: "VH Clone Test", 2: "RAM Disk", 3: "FAKE0001"}

SENSE_NONE = (0x00, 0x00, 0x00)
SENSE_ILLEGAL_REQUEST = (0x05, 0x20, 0x00)  # invalid command operation code
SENSE_LBA_OUT_OF_RANGE = (0x05, 0x21, 0x00)


class FakeDiskHandle(UsbHandle):
    def __init__(self, image: bytearray) -> None:
        self._image = image
        self._in: queue.Queue[bytes] = queue.Queue()
        self._lock = threading.Lock()
        self._write: tuple[int, int, bytearray, int] | None = None  # lba, remaining, buffer, tag
        self._sense = SENSE_NONE
        self._config = 1

    # ----- control transfers ---------------------------------------------------------------------------------
    def control(self, setup: bytes, data: bytes, timeout_ms: int) -> tuple[int, bytes]:
        bm, req, value, index, length = struct.unpack("<BBHHH", setup)
        if bm == 0x80 and req == 0x06:
            return self._get_descriptor(value, length)
        if bm == 0x80 and req == 0x08:
            return 1, bytes([self._config])
        if bm == 0x80 and req == 0x00:
            return 2, b"\0\0"
        if bm == 0x00 and req == 0x09:
            self._config = value & 0xFF
            return 0, b""
        if bm in (0x01, 0x02) and req in (0x01, 0x03, 0x0B):
            return 0, b""
        if bm == 0xA1 and req == 0xFE:  # GET_MAX_LUN
            return 1, b"\0"
        if bm == 0x21 and req == 0xFF:  # Bulk-Only mass storage reset
            return 0, b""
        return proto.EPIPE, b""

    def _get_descriptor(self, value: int, length: int) -> tuple[int, bytes]:
        dtype, index = value >> 8, value & 0xFF
        if dtype == 1:
            blob = DEVICE_DESCRIPTOR
        elif dtype == 2:
            blob = CONFIG_DESCRIPTOR
        elif dtype == 3 and index == 0:
            blob = bytes([4, 3, 0x09, 0x04])
        elif dtype == 3 and index in STRINGS:
            blob = utf16_string_descriptor(STRINGS[index])
        else:
            return proto.EPIPE, b""
        blob = blob[:length]
        return len(blob), blob

    # ----- bulk transfers ------------------------------------------------------------------------------------
    def bulk(self, endpoint: int, length: int, data: bytes, timeout_ms: int) -> tuple[int, bytes]:
        if endpoint == EP_OUT:
            self._bulk_out(data)
            return len(data), b""
        if endpoint == EP_IN:
            return self._bulk_in(length, timeout_ms)
        return proto.EPIPE, b""

    def _bulk_in(self, length: int, timeout_ms: int) -> tuple[int, bytes]:
        try:
            chunk = self._in.get(timeout=max(timeout_ms, 1) / 1000)
        except queue.Empty:
            return proto.ETIMEDOUT, b""
        if len(chunk) > length:
            with self._lock:
                rest = chunk[length:]
                items = [rest]
                while not self._in.empty():
                    items.append(self._in.get_nowait())
                for item in items:
                    self._in.put(item)
            chunk = chunk[:length]
        return len(chunk), chunk

    def _bulk_out(self, data: bytes) -> None:
        with self._lock:
            if self._write is not None:
                self._continue_write(data)
            elif len(data) >= 31 and data[:4] == CBW_SIG:
                self._command(data)

    def _csw(self, tag: int, residue: int, status: int) -> None:
        self._in.put(CSW_SIG + struct.pack("<IIB", tag, residue, status))

    def _continue_write(self, data: bytes) -> None:
        lba, remaining, buf, tag = self._write  # type: ignore[misc]
        buf += data
        remaining -= len(data)
        if remaining > 0:
            self._write = (lba, remaining, buf, tag)
            return
        self._write = None
        self._image[lba * BLOCK:lba * BLOCK + len(buf)] = buf
        self._csw(tag, 0, 0)

    def _command(self, cbw: bytes) -> None:
        tag, dlen, flags = struct.unpack_from("<IIB", cbw, 4)
        cb = cbw[15:15 + cbw[14]] or bytes(1)  # an empty command block is treated as TEST UNIT READY
        op = cb[0]
        if op in (0x2A,):  # WRITE(10)
            lba, blocks = struct.unpack_from(">IxH", cb, 2)
            size = blocks * BLOCK
            if (lba + blocks) * BLOCK > len(self._image):
                self._sense = SENSE_LBA_OUT_OF_RANGE
                self._csw(tag, dlen, 1)
            elif size == 0:
                self._csw(tag, 0, 0)
            else:
                self._write = (lba, size, bytearray(), tag)
            return
        status, payload = self._execute(op, cb)
        if status == 0:
            self._sense = SENSE_NONE
        if payload:
            self._in.put(payload[:dlen])
        self._csw(tag, max(0, dlen - len(payload)), status)

    def _execute(self, op: int, cb: bytes) -> tuple[int, bytes]:
        total = len(self._image) // BLOCK
        if op in (0x00, 0x1B, 0x1E, 0x35, 0x2F):  # TEST UNIT READY, START STOP, PREVENT/ALLOW, SYNC CACHE, VERIFY
            return 0, b""
        if op == 0x12:  # INQUIRY
            return 0, (bytes([0x00, 0x80, 0x02, 0x02, 31, 0, 0, 0]) + b"VHClone ".ljust(8)[:8]
                       + b"RAM Disk".ljust(16)[:16] + b"1.0 ")
        if op == 0x03:  # REQUEST SENSE
            key, asc, ascq = self._sense
            return 0, bytes([0x70, 0, key, 0, 0, 0, 0, 10, 0, 0, 0, 0, asc, ascq, 0, 0, 0, 0])
        if op == 0x25:  # READ CAPACITY(10)
            return 0, struct.pack(">II", total - 1, BLOCK)
        if op == 0x23:  # READ FORMAT CAPACITIES
            return 0, bytes([0, 0, 0, 8]) + struct.pack(">IB", total, 2) + (BLOCK).to_bytes(3, "big")
        if op == 0x1A:  # MODE SENSE(6)
            return 0, bytes([3, 0, 0, 0])
        if op == 0x5A:  # MODE SENSE(10)
            return 0, bytes([0, 6, 0, 0, 0, 0, 0, 0])
        if op == 0x28:  # READ(10)
            lba, blocks = struct.unpack_from(">IxH", cb, 2)
            if (lba + blocks) * BLOCK > len(self._image):
                self._sense = SENSE_LBA_OUT_OF_RANGE
                return 1, b""
            return 0, bytes(self._image[lba * BLOCK:(lba + blocks) * BLOCK])
        self._sense = SENSE_ILLEGAL_REQUEST
        return 1, b""

    def reset(self) -> int:
        with self._lock:
            self._write = None
            while not self._in.empty():
                self._in.get_nowait()
        return 0

    def clear_halt(self, endpoint: int) -> int:
        return 0

    def close(self) -> None:
        return None


class FakeDiskBackend(UsbBackend):
    def __init__(self, device_id: int = 1, megabytes: int = 8) -> None:
        self._device_id = device_id
        self._on_plug: PlugCallback | None = None
        self._image = bytearray(megabytes * 1024 * 1024)
        self.info = DeviceInfo(device_id, 0x1209, 0x0001, "VH Clone Test", "RAM Disk", "FAKE0001", SPEED_HIGH,
                               DEVICE_DESCRIPTOR + CONFIG_DESCRIPTOR, port=1)

    def start(self, on_plug: PlugCallback) -> None:
        self._on_plug = on_plug
        on_plug("add", self.info)

    def start_hotplug_demo(self, period_s: float) -> None:
        """Unplug and replug the emulated disk every period_s seconds (for hot-plug tests)."""
        def loop() -> None:
            present = True
            while True:
                time.sleep(period_s)
                if self._on_plug is None:
                    continue  # the server has not started the backend yet
                present = not present
                self._on_plug("add" if present else "remove", self.info)

        threading.Thread(target=loop, daemon=True, name="hotplug-demo").start()

    def open(self, device_id: int) -> UsbHandle:
        if device_id != self._device_id:
            raise OSError("no such device")
        return FakeDiskHandle(self._image)
