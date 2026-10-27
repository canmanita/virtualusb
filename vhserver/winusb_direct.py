"""Windows: use a WinUSB-bound device straight through winusb.dll, like the stock server, without libusb.

libusb enumerates every hub port on each ``libusb_get_device_list`` call, and right after a driver switch that call can
stop answering for good (seen in the field, with the device itself perfectly healthy). Here the device is opened by the
interface path Windows already gave it, so nothing else on the bus is touched. libusb stays in use only for the
background scan that tells which devices exist.
"""
from __future__ import annotations

import logging
import struct
import threading
import time
from typing import Callable

from . import protocol as proto
from .backend import UsbHandle

log = logging.getLogger("vhserver.winusb_direct")

DEFAULT_TIMEOUT_MS = 5000
MAX_TIMEOUT_MS = 120_000
CLOSE_WAIT_S = 15.0
OPEN_WAIT_S = 15.0
RETRY_PAUSE_S = 0.3

# Windows error codes -> the Linux errnos the client expects
ERROR_SEM_TIMEOUT, ERROR_GEN_FAILURE, ERROR_NO_SUCH_DEVICE = 121, 31, 433
ERROR_DEVICE_NOT_CONNECTED, ERROR_BAD_COMMAND, ERROR_INVALID_HANDLE = 1167, 22, 6
ERROR_FILE_NOT_FOUND, ERROR_OPERATION_ABORTED = 2, 995
_WIN_ERRNO = {ERROR_SEM_TIMEOUT: proto.ETIMEDOUT, ERROR_GEN_FAILURE: proto.EPIPE, ERROR_NO_SUCH_DEVICE: proto.ENODEV,
              ERROR_DEVICE_NOT_CONNECTED: proto.ENODEV, ERROR_BAD_COMMAND: proto.ENODEV,
              ERROR_INVALID_HANDLE: proto.ENODEV, ERROR_FILE_NOT_FOUND: proto.ENODEV}


class WinUsbIoError(OSError):
    def __init__(self, code: int) -> None:
        super().__init__(f"WinUSB error {code}")
        self.code = code


def errno_for(code: int) -> int:
    return _WIN_ERRNO.get(code, proto.EIO)


def parse_config(raw: bytes) -> tuple[list[int], dict[int, tuple[int, int]], int]:
    """Interfaces, endpoints ({address: (transfer type, max packet)}) and configuration value from the raw descriptors
    (an 18 byte device descriptor followed by the configuration descriptor). Garbage gives an empty result."""
    interfaces: list[int] = []
    endpoints: dict[int, tuple[int, int]] = {}
    config_value = 1
    pos = 18 if len(raw) >= 18 and raw[1] == 1 else 0
    while pos + 2 <= len(raw):
        length, kind = raw[pos], raw[pos + 1]
        if length < 2 or pos + length > len(raw):
            break
        if kind == 2 and length >= 9:
            config_value = raw[pos + 5]
        elif kind == 4 and length >= 9 and raw[pos + 2] not in interfaces:
            interfaces.append(raw[pos + 2])
        elif kind == 5 and length >= 7:
            endpoints[raw[pos + 2]] = (raw[pos + 3] & 3, struct.unpack_from("<H", raw, pos + 4)[0])
        pos += length
    return interfaces, endpoints, config_value


def guid_from_values(read: Callable[[str], object]) -> str | None:
    """The interface GUID the binder wrote into the device's registry key (single value, or the first of a list)."""
    single = read("DeviceInterfaceGUID")
    if isinstance(single, str) and single:
        return single
    several = read("DeviceInterfaceGUIDs")
    if isinstance(several, (list, tuple)) and several:
        return str(several[0])
    return None


def interface_guid(instance_id: str) -> str | None:  # pragma: no cover - needs the registry of a real device
    import winreg

    path = f"SYSTEM\\CurrentControlSet\\Enum\\{instance_id}\\Device Parameters"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
            def read(name: str):
                try:
                    return winreg.QueryValueEx(key, name)[0]
                except OSError:
                    return None

            return guid_from_values(read)
    except OSError:
        return None


class WinUsbDirectHandle(UsbHandle):
    """An opened WinUSB device. Like the libusb handle, close() waits for transfers in flight before freeing it."""

    def __init__(self, api, file_handle, winusb_handle, endpoints: dict[int, tuple[int, int]], config_value: int = 1,
                 on_close: Callable[[], None] | None = None) -> None:
        self._api, self._file, self._h = api, file_handle, winusb_handle
        self._endpoints, self._config, self._on_close = endpoints, config_value, on_close
        self._closing = threading.Event()
        self._cond = threading.Condition()
        self._inflight = 0

    # ---- in-flight bookkeeping ---------------------------------------------------------------------------------------
    def _enter(self) -> bool:
        with self._cond:
            if self._closing.is_set():
                return False
            self._inflight += 1
            return True

    def _leave(self) -> None:
        with self._cond:
            self._inflight -= 1
            self._cond.notify_all()

    @staticmethod
    def _timeout(timeout_ms: int) -> int:
        return min(timeout_ms or DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS)

    # ---- control ----------------------------------------------------------------------------------------------------
    def control(self, setup: bytes, data: bytes, timeout_ms: int) -> tuple[int, bytes]:
        if not self._enter():
            return proto.ENODEV, b""
        try:
            return self._control(setup, data, self._timeout(timeout_ms))
        except WinUsbIoError as exc:
            return errno_for(exc.code), b""
        finally:
            self._leave()

    def _control(self, setup: bytes, data: bytes, timeout_ms: int) -> tuple[int, bytes]:
        bm, req, value, index, length = struct.unpack("<BBHHH", setup)
        if bm == 0x00 and req == 0x09:                       # SET_CONFIGURATION: WinUSB does not allow it
            return (0, b"") if value == self._config else (proto.EPIPE, b"")
        if bm == 0x01 and req == 0x0B:                       # SET_INTERFACE
            self._api.set_alt(self._h, value)
            return 0, b""
        if bm == 0x02 and req == 0x01 and value == 0:        # CLEAR_FEATURE(ENDPOINT_HALT)
            self._api.reset_pipe(self._h, index & 0xFF)
            return 0, b""
        if bm & 0x80:
            received = self._api.control_in(self._h, bm, req, value, index, length, timeout_ms)
            return len(received), bytes(received)
        return self._api.control_out(self._h, bm, req, value, index, data, timeout_ms), b""

    # ---- bulk / interrupt -------------------------------------------------------------------------------------------
    def bulk(self, endpoint: int, length: int, data: bytes, timeout_ms: int) -> tuple[int, bytes]:
        if not self._enter():
            return proto.ENODEV, b""
        try:
            kind = self._endpoints.get(endpoint, (2, 512))[0]
            if kind == 1:
                return proto.EPIPE, b""                      # isochronous endpoints are not supported yet
            timeout = self._timeout(timeout_ms)
            if endpoint & 0x80:
                received = self._api.read(self._h, endpoint, length, timeout)
                return len(received), bytes(received)
            return self._api.write(self._h, endpoint, data, timeout), b""
        except WinUsbIoError as exc:
            return errno_for(exc.code), b""
        finally:
            self._leave()

    # ---- misc -------------------------------------------------------------------------------------------------------
    def reset(self) -> int:
        """WinUSB cannot reset a device; clearing every pipe is the closest safe equivalent."""
        if not self._enter():
            return proto.ENODEV
        try:
            for endpoint in self._endpoints:
                self._api.reset_pipe(self._h, endpoint)
            return 0
        except WinUsbIoError as exc:
            return errno_for(exc.code)
        finally:
            self._leave()

    def clear_halt(self, endpoint: int) -> int:
        if not self._enter():
            return proto.ENODEV
        try:
            if endpoint not in self._endpoints:
                return proto.EPIPE
            self._api.reset_pipe(self._h, endpoint)
            return 0
        except WinUsbIoError as exc:
            return errno_for(exc.code)
        finally:
            self._leave()

    def close(self) -> None:
        with self._cond:
            if self._closing.is_set():
                return
            self._closing.set()
        for endpoint in self._endpoints:                      # wakes up reads that wait for data
            try:
                self._api.abort_pipe(self._h, endpoint)
            except WinUsbIoError:
                pass
        with self._cond:
            deadline = time.monotonic() + CLOSE_WAIT_S
            while self._inflight and time.monotonic() < deadline:
                self._cond.wait(0.2)
            if self._inflight:
                log.warning("closing a device with %d transfer(s) still running", self._inflight)
        for step in (lambda: self._api.free(self._h), lambda: self._api.close_file(self._file)):
            try:
                step()
            except WinUsbIoError:
                pass
        if self._on_close is not None:
            try:
                self._on_close()
            except Exception:  # noqa: BLE001 - e.g. the driver restore failed; the device is closed regardless
                log.exception("cleanup after closing the device failed")


class WinUsbDirectOpener:
    def __init__(self, api=None, guid_of: Callable[[str], str | None] = interface_guid, wait_s: float = OPEN_WAIT_S,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic) -> None:
        self._api = api
        self._guid_of, self._wait_s, self._sleep, self._clock = guid_of, wait_s, sleep, clock

    @property
    def api(self):
        if self._api is None:
            self._api = WinUsbApi()
        return self._api

    def open(self, instance_id: str, descriptors: bytes, on_close: Callable[[], None]) -> WinUsbDirectHandle:
        interfaces, endpoints, config_value = parse_config(descriptors)
        if len(interfaces) > 1:
            raise OSError("composite devices cannot be opened through WinUSB")
        guid = self._guid_of(instance_id)
        if guid is None:
            raise OSError(f"no DeviceInterfaceGUID for {instance_id}: the WinUSB switch did not take effect")
        file_handle, winusb_handle = self._wait_for_interface(guid, instance_id)
        return WinUsbDirectHandle(self.api, file_handle, winusb_handle, endpoints, config_value, on_close)

    def _wait_for_interface(self, guid: str, instance_id: str) -> tuple[int, int]:
        api = self.api
        deadline = self._clock() + self._wait_s
        while True:
            path = api.find_path(guid, instance_id)
            if path:
                file_handle = None
                try:
                    file_handle = api.open_device(path)
                    return file_handle, api.initialize(file_handle)
                except WinUsbIoError:
                    if file_handle is not None:
                        api.close_file(file_handle)       # the device is still starting: try again
            if self._clock() >= deadline:
                raise OSError("the WinUSB interface of the device did not appear")
            self._sleep(RETRY_PAUSE_S)


# ---- the real thing: ctypes over kernel32 / winusb / setupapi -------------------------------------------------------
class WinUsbApi:  # pragma: no cover - exercised only with a real WinUSB device
    # WinUsb_Initialize needs a handle opened with FILE_FLAG_OVERLAPPED; calls without an OVERLAPPED structure stay synchronous
    GENERIC_RW, SHARE_RW, OPEN_EXISTING, ATTR_NORMAL = 0xC0000000, 3, 3, 0x80 | 0x40000000
    PIPE_TRANSFER_TIMEOUT = 0x03
    DIGCF_PRESENT, DIGCF_DEVICEINTERFACE = 0x2, 0x10

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes

        self.ct, self.wt = ctypes, wintypes
        self.k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.winusb = ctypes.WinDLL("winusb", use_last_error=True)
        self.setupapi = ctypes.WinDLL("setupapi", use_last_error=True)
        self._declare()

    def _declare(self) -> None:
        ct, wt = self.ct, self.wt
        vp, up = ct.c_void_p, ct.POINTER

        class GUID(ct.Structure):
            _fields_ = [("Data1", wt.DWORD), ("Data2", wt.WORD), ("Data3", wt.WORD), ("Data4", ct.c_ubyte * 8)]

        class SETUP(ct.Structure):
            _pack_ = 1
            _fields_ = [("RequestType", ct.c_ubyte), ("Request", ct.c_ubyte), ("Value", wt.WORD), ("Index", wt.WORD),
                        ("Length", wt.WORD)]

        class IFDATA(ct.Structure):
            _fields_ = [("cbSize", wt.DWORD), ("Guid", GUID), ("Flags", wt.DWORD), ("Reserved", vp)]

        self.GUID, self.SETUP, self.IFDATA = GUID, SETUP, IFDATA
        k, w, s = self.k32, self.winusb, self.setupapi
        k.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, vp, wt.DWORD, wt.DWORD, vp]
        k.CreateFileW.restype = vp
        k.CloseHandle.argtypes, k.CloseHandle.restype = [vp], wt.BOOL
        w.WinUsb_Initialize.argtypes, w.WinUsb_Initialize.restype = [vp, up(vp)], wt.BOOL
        w.WinUsb_Free.argtypes, w.WinUsb_Free.restype = [vp], wt.BOOL
        w.WinUsb_SetPipePolicy.argtypes = [vp, ct.c_ubyte, wt.ULONG, wt.ULONG, vp]
        w.WinUsb_SetPipePolicy.restype = wt.BOOL
        for name in ("WinUsb_ReadPipe", "WinUsb_WritePipe"):
            fn = getattr(w, name)
            fn.argtypes, fn.restype = [vp, ct.c_ubyte, vp, wt.ULONG, up(wt.ULONG), vp], wt.BOOL
        w.WinUsb_ControlTransfer.argtypes = [vp, SETUP, vp, wt.ULONG, up(wt.ULONG), vp]
        w.WinUsb_ControlTransfer.restype = wt.BOOL
        for name in ("WinUsb_ResetPipe", "WinUsb_AbortPipe", "WinUsb_SetCurrentAlternateSetting"):
            fn = getattr(w, name)
            fn.argtypes, fn.restype = [vp, ct.c_ubyte], wt.BOOL
        s.SetupDiGetClassDevsW.argtypes, s.SetupDiGetClassDevsW.restype = [up(GUID), wt.LPCWSTR, wt.HWND, wt.DWORD], vp
        s.SetupDiEnumDeviceInterfaces.argtypes = [vp, vp, up(GUID), wt.DWORD, up(IFDATA)]
        s.SetupDiEnumDeviceInterfaces.restype = wt.BOOL
        s.SetupDiGetDeviceInterfaceDetailW.argtypes = [vp, up(IFDATA), vp, wt.DWORD, up(wt.DWORD), vp]
        s.SetupDiGetDeviceInterfaceDetailW.restype = wt.BOOL
        s.SetupDiDestroyDeviceInfoList.argtypes, s.SetupDiDestroyDeviceInfoList.restype = [vp], wt.BOOL

    def _fail(self) -> WinUsbIoError:
        return WinUsbIoError(self.ct.get_last_error())

    def _guid(self, text: str):
        import uuid

        value = uuid.UUID(text.strip("{}"))
        guid = self.GUID()
        self.ct.memmove(self.ct.byref(guid), value.bytes_le, 16)
        return guid

    def find_path(self, guid: str, instance_id: str) -> str | None:
        ct, wt = self.ct, self.wt
        wanted = self._guid(guid)
        handle = self.setupapi.SetupDiGetClassDevsW(ct.byref(wanted), instance_id, None,
                                                    self.DIGCF_PRESENT | self.DIGCF_DEVICEINTERFACE)
        if handle in (None, ct.c_void_p(-1).value):
            return None
        try:
            data = self.IFDATA()
            data.cbSize = ct.sizeof(data)
            if not self.setupapi.SetupDiEnumDeviceInterfaces(handle, None, ct.byref(wanted), 0, ct.byref(data)):
                return None
            needed = wt.DWORD(0)
            self.setupapi.SetupDiGetDeviceInterfaceDetailW(handle, ct.byref(data), None, 0, ct.byref(needed), None)
            buffer = ct.create_string_buffer(max(needed.value, 8))
            ct.cast(buffer, ct.POINTER(wt.DWORD))[0] = 8 if ct.sizeof(ct.c_void_p) == 8 else 6  # cbSize of the struct
            if not self.setupapi.SetupDiGetDeviceInterfaceDetailW(handle, ct.byref(data), buffer, needed.value,
                                                                  ct.byref(needed), None):
                return None
            return ct.wstring_at(ct.addressof(buffer) + 4)
        finally:
            self.setupapi.SetupDiDestroyDeviceInfoList(handle)

    def open_device(self, path: str) -> int:
        handle = self.k32.CreateFileW(path, self.GENERIC_RW, self.SHARE_RW, None, self.OPEN_EXISTING, self.ATTR_NORMAL, None)
        if handle in (None, self.ct.c_void_p(-1).value):
            raise self._fail()
        return handle

    def initialize(self, file_handle: int) -> int:
        winusb = self.ct.c_void_p()
        if not self.winusb.WinUsb_Initialize(file_handle, self.ct.byref(winusb)):
            raise self._fail()
        return winusb.value

    def _timeout(self, h: int, pipe: int, timeout_ms: int) -> None:
        value = self.wt.ULONG(timeout_ms)
        if not self.winusb.WinUsb_SetPipePolicy(h, pipe, self.PIPE_TRANSFER_TIMEOUT, 4, self.ct.byref(value)):
            raise self._fail()

    def control_in(self, h, bm, req, value, index, length, timeout_ms) -> bytes:
        self._timeout(h, 0x00, timeout_ms)
        buffer, done = self.ct.create_string_buffer(max(length, 1)), self.wt.ULONG(0)
        if not self.winusb.WinUsb_ControlTransfer(h, self.SETUP(bm, req, value, index, length), buffer, length,
                                                  self.ct.byref(done), None):
            raise self._fail()
        return buffer.raw[:done.value]

    def control_out(self, h, bm, req, value, index, data, timeout_ms) -> int:
        self._timeout(h, 0x00, timeout_ms)
        buffer, done = self.ct.create_string_buffer(bytes(data), max(len(data), 1)), self.wt.ULONG(0)
        if not self.winusb.WinUsb_ControlTransfer(h, self.SETUP(bm, req, value, index, len(data)), buffer, len(data),
                                                  self.ct.byref(done), None):
            raise self._fail()
        return done.value

    def read(self, h, pipe, length, timeout_ms) -> bytes:
        self._timeout(h, pipe, timeout_ms)
        buffer, done = self.ct.create_string_buffer(max(length, 1)), self.wt.ULONG(0)
        if not self.winusb.WinUsb_ReadPipe(h, pipe, buffer, length, self.ct.byref(done), None):
            raise self._fail()
        return buffer.raw[:done.value]

    def write(self, h, pipe, data, timeout_ms) -> int:
        self._timeout(h, pipe, timeout_ms)
        buffer, done = self.ct.create_string_buffer(bytes(data), max(len(data), 1)), self.wt.ULONG(0)
        if not self.winusb.WinUsb_WritePipe(h, pipe, buffer, len(data), self.ct.byref(done), None):
            raise self._fail()
        return done.value

    def reset_pipe(self, h, pipe) -> None:
        if not self.winusb.WinUsb_ResetPipe(h, pipe):
            raise self._fail()

    def abort_pipe(self, h, pipe) -> None:
        if not self.winusb.WinUsb_AbortPipe(h, pipe):
            raise self._fail()

    def set_alt(self, h, alt) -> None:
        if not self.winusb.WinUsb_SetCurrentAlternateSetting(h, alt):
            raise self._fail()

    def free(self, h) -> None:
        self.winusb.WinUsb_Free(h)

    def close_file(self, file_handle) -> None:
        self.k32.CloseHandle(file_handle)
