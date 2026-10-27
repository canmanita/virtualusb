"""Windows only: temporarily switch one USB device to the WinUSB driver so libusb can open it, and restore it later.

This mirrors what the stock server does when a client starts using a device: it writes a DeviceInterfaceGUID under
the device's registry key, selects the inbox ``winusb.inf`` as the only driver and installs it with ``DiInstallDevice``.
Restoring removes the device node and lets Windows enumerate it again, so the original driver (for example usbstor)
is installed again.

Safety rules enforced here: administrator rights are required, and HID devices, hubs, composite devices and anything
that is not an unambiguous single match are refused. The module is only used when the server runs with
``--windows-bind``.
"""
from __future__ import annotations

import logging
import os
import re
import subprocess
import time
import uuid
from dataclasses import dataclass

log = logging.getLogger("vhserver.winusb")

SERVICE_WINUSB = "winusb"
SETTLE_AFTER_RESTORE_S = 10.0  # Windows needs a while to reinstall the normal driver after a restore
DIIDFLAG_INSTALLNULLDRIVER = 0x4
RESTORE_PAUSE_S = 0.5
REFUSED_SERVICES = frozenset({"hidusb", "usbhub", "usbhub3", "usbccgp", "bthusb", "kbdhid", "mouhid"})
_INSTANCE_RE = re.compile(r"^USB\\VID_([0-9A-F]{4})&PID_([0-9A-F]{4})\\(.+)$", re.IGNORECASE)

DIGCF_PRESENT = 0x2
DIGCF_ALLCLASSES = 0x4
DIOD_INHERIT_CLASSDRVS = 0x2
DICS_FLAG_GLOBAL = 0x1
DIREG_DEV = 0x1
DI_ENUMSINGLEINF = 0x00010000
DI_FLAGSEX_ALLOWEXCLUDEDDRVS = 0x00000800
SPDIT_CLASSDRIVER = 1
SPDRP_SERVICE = 0x4
SPDRP_ADDRESS = 0x1C
REG_SZ = 1
LINE_LEN = 256
MAX_PATH = 260


class WinUsbError(OSError):
    pass


@dataclass(frozen=True)
class UsbNode:
    instance_id: str
    vid: int
    pid: int
    suffix: str
    service: str
    port: int | None


def parse_instance_id(instance_id: str) -> tuple[int, int, str] | None:
    """Top-level USB device instance id -> (vid, pid, suffix); interface nodes (MI_xx) return None."""
    match = _INSTANCE_RE.match(instance_id)
    if match is None or "&MI_" in instance_id.upper():
        return None
    return int(match.group(1), 16), int(match.group(2), 16), match.group(3)


def select_node(nodes: list[UsbNode], vid: int, pid: int, serial: str, port: int | None) -> UsbNode:
    """Pick the single node that is the libusb device, or raise WinUsbError if it cannot be told apart."""
    candidates = [n for n in nodes if n.vid == vid and n.pid == pid]
    if serial:
        by_serial = [n for n in candidates if n.suffix.upper() == serial.upper()]
        candidates = by_serial or candidates
    if len(candidates) > 1 and port is not None:
        candidates = [n for n in candidates if n.port == port] or candidates
    if len(candidates) != 1:
        raise WinUsbError(f"cannot identify device {vid:04x}:{pid:04x} among {len(candidates)} candidates")
    node = candidates[0]
    if node.service.lower() in REFUSED_SERVICES:
        raise WinUsbError(f"refusing to change the driver of {vid:04x}:{pid:04x} (service {node.service})")
    return node


def new_interface_guid() -> str:
    return "{" + str(uuid.uuid4()).upper() + "}"


class WinUsbBinder:
    """Binds a libusb-visible device to WinUSB and restores it. Instances are cheap; state is kept per device."""

    _store = None

    def __init__(self, store=None) -> None:
        if os.name != "nt":
            raise WinUsbError("WinUSB binding is only available on Windows")
        self._api = _SetupApi()
        self._store = store  # PendingStore: devices left on WinUSB if the server dies before restoring them
        self._restored_at = {}

    @staticmethod
    def is_admin() -> bool:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())

    def prepare(self, vid: int, pid: int, serial: str, port: int | None) -> str | None:
        """Make the device openable. Returns the instance id to restore later, or None if nothing was changed."""
        instance_id, switched = self.prepare_direct(vid, pid, serial, port)
        return instance_id if switched else None

    def prepare_direct(self, vid: int, pid: int, serial: str, port: int | None) -> tuple[str, bool]:
        """Like ``prepare`` but always returns the node's instance id, and whether its driver was switched to WinUSB."""
        if not self.is_admin():
            raise WinUsbError("administrator rights are required to install the WinUSB driver")
        nodes = self._api.usb_nodes()
        node = select_node(nodes, vid, pid, serial, port)
        if node.service.lower() == SERVICE_WINUSB:
            return node.instance_id, False
        if "&" in node.suffix and any(n.vid == vid and n.pid == pid and n.instance_id != node.instance_id
                                      and n.service.lower() == SERVICE_WINUSB for n in nodes):
            # the same device listed twice (a second, generated instance id) while the first is already switched:
            # installing WinUSB on it never completes, so refuse instead of hanging
            raise WinUsbError(f"{node.instance_id} is a second instance of a device that is already switched")
        self._let_windows_settle(vid, pid)
        log.info("switching %s from %s to WinUSB", node.instance_id, node.service or "no driver")
        if self._store is not None:
            self._store.add(node.instance_id)  # written before the switch: a crash in between must be recoverable
        try:
            self._api.install_winusb(node.instance_id)
        except BaseException:
            try:
                self.restore(node.instance_id)
            except (OSError, subprocess.SubprocessError):
                log.exception("cannot restore %s after a failed switch", node.instance_id)
            raise
        return node.instance_id, True

    def restore(self, instance_id: str) -> bool:
        """Give the device back to Windows. Like the stock server this installs the Null driver and then the best driver
        on the same device node, which leaves no ghost nodes behind; removing the node and rescanning is the fallback.

        The pending record is dropped only when it worked; otherwise it stays for the next attempt."""
        log.info("restoring the original driver of %s", instance_id)
        removed = self._reinstall_best_driver(instance_id) or self._restore_with_pnputil(instance_id)
        if removed:
            self._forget(instance_id)
        parsed = parse_instance_id(instance_id)
        if parsed is not None:
            self.__dict__.setdefault("_restored_at", {})[(parsed[0], parsed[1])] = time.monotonic()
        return removed

    def _reinstall_best_driver(self, instance_id: str) -> bool:
        try:
            self._api.install_best_driver(instance_id, null_driver=True)
            time.sleep(RESTORE_PAUSE_S)
            self._api.install_best_driver(instance_id, null_driver=False)
        except Exception as exc:  # noqa: BLE001 - any failure here falls back to the heavier method
            log.warning("could not reinstall the driver of %s in place (%s), removing the device node instead",
                        instance_id, exc)
            return False
        return True

    def _restore_with_pnputil(self, instance_id: str) -> bool:
        removed = False
        for args in (["/remove-device", instance_id], ["/scan-devices"]):
            result = subprocess.run(["pnputil", *args], capture_output=True, text=True, timeout=60,
                                    creationflags=0x08000000)
            ok = result.returncode in (0, 3010)
            removed = removed or (ok and args[0] == "/remove-device")
            if not ok:
                log.warning("pnputil %s failed (%d): %s", args[0], result.returncode, result.stdout.strip()[:200])
        return removed

    def _let_windows_settle(self, vid: int, pid: int) -> None:
        """Switching a device again right after a restore races with Windows reinstalling its normal driver."""
        restored = self.__dict__.get("_restored_at", {}).get((vid, pid))
        if restored is None:
            return
        remaining = SETTLE_AFTER_RESTORE_S - (time.monotonic() - restored)
        if remaining > 0:
            log.info("waiting %.0f s for Windows to finish restoring %04x:%04x", remaining, vid, pid)
            time.sleep(remaining)

    def diagnose(self, vid: int, pid: int) -> str:
        """The Plug and Play state (status, problem code) of every node of this VID:PID, for the log. Never raises."""
        try:
            result = subprocess.run(["pnputil", "/enum-devices"], capture_output=True, text=True,
                                    timeout=8, creationflags=0x08000000)
        except subprocess.TimeoutExpired:
            return "pnputil timed out: the Plug and Play manager is not answering"
        except OSError as exc:
            return f"pnputil failed: {exc}"
        needle = f"VID_{vid:04X}&PID_{pid:04X}"
        text = result.stdout.replace(chr(13), "")
        blocks = [block.strip() for block in text.split(chr(10) * 2) if needle in block.upper()]
        return (chr(10) * 2).join(blocks) or "no Plug and Play node found for this device"

    def _forget(self, instance_id: str) -> None:
        if self._store is not None:
            self._store.remove(instance_id)

    def recover_pending(self) -> list[str]:
        """Restore devices a previous run left on WinUSB (crash, kill, power loss). Returns the ids restored.

        Only ids that Windows currently shows on the WinUSB driver are touched: the state file is not trusted to name
        arbitrary devices, and a device that is gone or already back on its own driver just loses its record."""
        if self._store is None:
            return []
        on_winusb = {n.instance_id.upper() for n in self._api.usb_nodes() if n.service.lower() == SERVICE_WINUSB}
        restored = []
        for instance_id in self._store.all():
            if instance_id.upper() not in on_winusb:
                self._forget(instance_id)
                continue
            log.warning("recovering %s left on WinUSB by a previous run", instance_id)
            try:
                if self.restore(instance_id):
                    restored.append(instance_id)
            except (OSError, subprocess.SubprocessError) as exc:
                log.error("cannot recover %s (will retry at the next start): %s", instance_id, exc)
        return restored


class _SetupApi:
    """Thin ctypes layer over SetupAPI / newdev (kept separate so the logic above is unit-testable)."""

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes

        self.ct, self.wt = ctypes, wintypes
        self.setupapi = ctypes.WinDLL("setupapi", use_last_error=True)
        self.advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        self.newdev = ctypes.WinDLL("newdev", use_last_error=True)
        self._define_types()
        self._declare()

    def _define_types(self) -> None:
        ct, wt = self.ct, self.wt

        class GUID(ct.Structure):
            _fields_ = [("Data1", wt.DWORD), ("Data2", wt.WORD), ("Data3", wt.WORD), ("Data4", ct.c_ubyte * 8)]

        class SP_DEVINFO_DATA(ct.Structure):
            _fields_ = [("cbSize", wt.DWORD), ("ClassGuid", GUID), ("DevInst", wt.DWORD), ("Reserved", ct.c_void_p)]

        class FILETIME(ct.Structure):
            _fields_ = [("dwLowDateTime", wt.DWORD), ("dwHighDateTime", wt.DWORD)]

        class SP_DRVINFO_DATA(ct.Structure):
            _fields_ = [("cbSize", wt.DWORD), ("DriverType", wt.DWORD), ("Reserved", ct.c_void_p),
                        ("Description", ct.c_wchar * LINE_LEN), ("MfgName", ct.c_wchar * LINE_LEN),
                        ("ProviderName", ct.c_wchar * LINE_LEN), ("DriverDate", FILETIME),
                        ("DriverVersion", ct.c_ulonglong)]

        class SP_DEVINSTALL_PARAMS(ct.Structure):
            _fields_ = [("cbSize", wt.DWORD), ("Flags", wt.DWORD), ("FlagsEx", wt.DWORD), ("hwndParent", wt.HWND),
                        ("InstallMsgHandler", ct.c_void_p), ("InstallMsgHandlerContext", ct.c_void_p),
                        ("FileQueue", ct.c_void_p), ("ClassInstallReserved", ct.c_void_p), ("Reserved", wt.DWORD),
                        ("DriverPath", ct.c_wchar * MAX_PATH)]

        self.SP_DEVINFO_DATA, self.SP_DRVINFO_DATA = SP_DEVINFO_DATA, SP_DRVINFO_DATA
        self.SP_DEVINSTALL_PARAMS = SP_DEVINSTALL_PARAMS

    def _declare(self) -> None:
        ct, wt, s = self.ct, self.wt, self.setupapi
        vp, pdi, pdr, pip = ct.c_void_p, ct.POINTER(self.SP_DEVINFO_DATA), ct.POINTER(self.SP_DRVINFO_DATA), \
            ct.POINTER(self.SP_DEVINSTALL_PARAMS)
        s.SetupDiGetClassDevsW.argtypes, s.SetupDiGetClassDevsW.restype = [vp, wt.LPCWSTR, wt.HWND, wt.DWORD], vp
        s.SetupDiCreateDeviceInfoList.argtypes, s.SetupDiCreateDeviceInfoList.restype = [vp, wt.HWND], vp
        s.SetupDiDestroyDeviceInfoList.argtypes, s.SetupDiDestroyDeviceInfoList.restype = [vp], wt.BOOL
        s.SetupDiEnumDeviceInfo.argtypes, s.SetupDiEnumDeviceInfo.restype = [vp, wt.DWORD, pdi], wt.BOOL
        s.SetupDiGetDeviceInstanceIdW.argtypes = [vp, pdi, wt.LPWSTR, wt.DWORD, ct.POINTER(wt.DWORD)]
        s.SetupDiGetDeviceInstanceIdW.restype = wt.BOOL
        s.SetupDiGetDeviceRegistryPropertyW.argtypes = [vp, pdi, wt.DWORD, ct.POINTER(wt.DWORD), ct.c_void_p,
                                                        wt.DWORD, ct.POINTER(wt.DWORD)]
        s.SetupDiGetDeviceRegistryPropertyW.restype = wt.BOOL
        s.SetupDiOpenDeviceInfoW.argtypes, s.SetupDiOpenDeviceInfoW.restype = [vp, wt.LPCWSTR, wt.HWND, wt.DWORD, pdi], wt.BOOL
        s.SetupDiCreateDevRegKeyW.argtypes = [vp, pdi, wt.DWORD, wt.DWORD, wt.DWORD, vp, wt.LPCWSTR]
        s.SetupDiCreateDevRegKeyW.restype = vp
        s.SetupDiGetDeviceInstallParamsW.argtypes, s.SetupDiGetDeviceInstallParamsW.restype = [vp, pdi, pip], wt.BOOL
        s.SetupDiSetDeviceInstallParamsW.argtypes, s.SetupDiSetDeviceInstallParamsW.restype = [vp, pdi, pip], wt.BOOL
        s.SetupDiBuildDriverInfoList.argtypes, s.SetupDiBuildDriverInfoList.restype = [vp, pdi, wt.DWORD], wt.BOOL
        s.SetupDiEnumDriverInfoW.argtypes = [vp, pdi, wt.DWORD, wt.DWORD, pdr]
        s.SetupDiEnumDriverInfoW.restype = wt.BOOL
        s.SetupDiDestroyDriverInfoList.argtypes, s.SetupDiDestroyDriverInfoList.restype = [vp, pdi, wt.DWORD], wt.BOOL
        s.SetupDiSetSelectedDevice.argtypes, s.SetupDiSetSelectedDevice.restype = [vp, pdi], wt.BOOL
        s.SetupDiSetSelectedDriverW.argtypes, s.SetupDiSetSelectedDriverW.restype = [vp, pdi, pdr], wt.BOOL
        a = self.advapi
        a.RegSetValueExW.argtypes = [vp, wt.LPCWSTR, wt.DWORD, wt.DWORD, ct.c_void_p, wt.DWORD]
        a.RegSetValueExW.restype = ct.c_long
        a.RegCloseKey.argtypes, a.RegCloseKey.restype = [vp], ct.c_long
        self.newdev.DiInstallDevice.argtypes = [wt.HWND, vp, pdi, pdr, wt.DWORD, ct.POINTER(wt.BOOL)]
        self.newdev.DiInstallDevice.restype = wt.BOOL

    def install_best_driver(self, instance_id: str, null_driver: bool = False) -> None:
        """DiInstallDevice without a chosen driver: Windows picks the best one (usbstor for a stick). With
        ``null_driver`` it installs the Null driver instead, which unloads the function driver (WinUSB)."""
        ct, wt, s = self.ct, self.wt, self.setupapi
        handle = s.SetupDiCreateDeviceInfoList(None, None)
        if handle in (None, ct.c_void_p(-1).value):
            raise WinUsbError(f"SetupDiCreateDeviceInfoList failed ({ct.get_last_error()})")
        data = self.SP_DEVINFO_DATA()
        data.cbSize = ct.sizeof(data)
        try:
            if not s.SetupDiOpenDeviceInfoW(handle, instance_id, None, 0, ct.byref(data)):
                raise WinUsbError(f"cannot open device info ({ct.get_last_error()})")
            if not s.SetupDiSetSelectedDevice(handle, ct.byref(data)):
                raise WinUsbError(f"SetupDiSetSelectedDevice failed ({ct.get_last_error()})")
            if not s.SetupDiSetSelectedDriverW(handle, ct.byref(data), None):
                raise WinUsbError(f"SetupDiSetSelectedDriver failed ({ct.get_last_error()})")
            needs_reboot = wt.BOOL(0)
            flags = DIIDFLAG_INSTALLNULLDRIVER if null_driver else 0
            if not self.newdev.DiInstallDevice(None, handle, ct.byref(data), None, flags, ct.byref(needs_reboot)):
                raise WinUsbError(f"DiInstallDevice failed ({ct.get_last_error()})")
        finally:
            s.SetupDiDestroyDeviceInfoList(handle)

    # ----- enumeration ---------------------------------------------------------------------------------------
    def usb_nodes(self) -> list[UsbNode]:
        ct, wt = self.ct, self.wt
        invalid = ct.c_void_p(-1).value
        handle = self.setupapi.SetupDiGetClassDevsW(None, "USB", None, DIGCF_PRESENT | DIGCF_ALLCLASSES)
        if handle in (None, invalid):
            raise WinUsbError(f"SetupDiGetClassDevs failed ({ct.get_last_error()})")
        nodes: list[UsbNode] = []
        try:
            index = 0
            while True:
                data = self.SP_DEVINFO_DATA()
                data.cbSize = ct.sizeof(data)
                if not self.setupapi.SetupDiEnumDeviceInfo(handle, index, ct.byref(data)):
                    break
                index += 1
                buf = ct.create_unicode_buffer(512)
                if not self.setupapi.SetupDiGetDeviceInstanceIdW(handle, ct.byref(data), buf, 512, None):
                    continue
                parsed = parse_instance_id(buf.value)
                if parsed is None:
                    continue
                nodes.append(UsbNode(buf.value, parsed[0], parsed[1], parsed[2],
                                     self._string_prop(handle, data, SPDRP_SERVICE), self._dword_prop(handle, data,
                                                                                                      SPDRP_ADDRESS)))
        finally:
            self.setupapi.SetupDiDestroyDeviceInfoList(handle)
        return nodes

    def _string_prop(self, handle, data, prop: int) -> str:
        ct = self.ct
        buf = ct.create_unicode_buffer(256)
        if self.setupapi.SetupDiGetDeviceRegistryPropertyW(handle, ct.byref(data), prop, None, buf, ct.sizeof(buf), None):
            return buf.value
        return ""

    def _dword_prop(self, handle, data, prop: int) -> int | None:
        ct, wt = self.ct, self.wt
        value = wt.DWORD()
        if self.setupapi.SetupDiGetDeviceRegistryPropertyW(handle, ct.byref(data), prop, None, ct.byref(value),
                                                           ct.sizeof(value), None):
            return value.value
        return None

    # ----- driver installation ----------------------------------------------------------------------------------
    def install_winusb(self, instance_id: str) -> None:
        ct, wt, s = self.ct, self.wt, self.setupapi
        handle = s.SetupDiCreateDeviceInfoList(None, None)
        if handle in (None, ct.c_void_p(-1).value):
            raise WinUsbError(f"SetupDiCreateDeviceInfoList failed ({ct.get_last_error()})")
        data = self.SP_DEVINFO_DATA()
        data.cbSize = ct.sizeof(data)
        try:
            # The list is built for the whole set (no device): winusb.inf is class USBDevice, a per-device list
            # would be filtered to the device's own class (USB) and come back empty. The device then inherits it.
            self._select_winusb_inf(handle)
            drv = self.SP_DRVINFO_DATA()
            drv.cbSize = ct.sizeof(drv)
            if not s.SetupDiBuildDriverInfoList(handle, None, SPDIT_CLASSDRIVER):
                raise WinUsbError(f"cannot build the WinUSB driver list ({ct.get_last_error()})")
            try:
                if not s.SetupDiEnumDriverInfoW(handle, None, SPDIT_CLASSDRIVER, 0, ct.byref(drv)):
                    raise WinUsbError(f"winusb.inf offers no driver ({ct.get_last_error()})")
                if not s.SetupDiOpenDeviceInfoW(handle, instance_id, None, DIOD_INHERIT_CLASSDRVS, ct.byref(data)):
                    raise WinUsbError(f"cannot open device info ({ct.get_last_error()})")
                self._write_interface_guid(handle, data)
                needs_reboot = wt.BOOL(0)
                if not self.newdev.DiInstallDevice(None, handle, ct.byref(data), ct.byref(drv), 0,
                                                   ct.byref(needs_reboot)):
                    raise WinUsbError(f"DiInstallDevice failed ({ct.get_last_error()})")
            finally:
                s.SetupDiDestroyDriverInfoList(handle, None, SPDIT_CLASSDRIVER)
        finally:
            s.SetupDiDestroyDeviceInfoList(handle)

    def _write_interface_guid(self, handle, data) -> None:
        ct = self.ct
        key = self.setupapi.SetupDiCreateDevRegKeyW(handle, ct.byref(data), DICS_FLAG_GLOBAL, 0, DIREG_DEV, None, None)
        if key in (None, ct.c_void_p(-1).value):
            raise WinUsbError(f"cannot open the device registry key ({ct.get_last_error()})")
        try:
            text = ct.create_unicode_buffer(new_interface_guid())
            status = self.advapi.RegSetValueExW(key, "DeviceInterfaceGUID", 0, REG_SZ, text, ct.sizeof(text))
            if status != 0:
                raise WinUsbError(f"cannot write DeviceInterfaceGUID (error {status})")
        finally:
            self.advapi.RegCloseKey(key)

    def _select_winusb_inf(self, handle) -> None:
        """Restrict the set-wide class driver search to the inbox winusb.inf."""
        ct = self.ct
        params = self.SP_DEVINSTALL_PARAMS()
        params.cbSize = ct.sizeof(params)
        if not self.setupapi.SetupDiGetDeviceInstallParamsW(handle, None, ct.byref(params)):
            raise WinUsbError(f"SetupDiGetDeviceInstallParams failed ({ct.get_last_error()})")
        params.Flags |= DI_ENUMSINGLEINF
        params.FlagsEx |= DI_FLAGSEX_ALLOWEXCLUDEDDRVS  # winusb.inf's generic model is excluded from selection
        params.DriverPath = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "INF", "winusb.inf")
        if not self.setupapi.SetupDiSetDeviceInstallParamsW(handle, None, ct.byref(params)):
            raise WinUsbError(f"SetupDiSetDeviceInstallParams failed ({ct.get_last_error()})")
