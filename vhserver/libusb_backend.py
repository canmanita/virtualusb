"""Real USB backend built on libusb (python-libusb1).

Linux: run as root (or with udev permissions). Kernel drivers are detached automatically while a device is bound and
re-attached when it is released, so the device returns to the host after the client stops using it.
Windows: only devices that already use the WinUSB/libusbK driver can be opened (listing works for every device).
"""
from __future__ import annotations

import logging
import os
import struct
import sys
import threading
import time
from pathlib import PurePath
from typing import Callable, Iterable

import usb1

from . import protocol as proto
from .keepalive import DeviceKeepalive
from .backend import (SPEED_FULL, SPEED_HIGH, SPEED_LOW, SPEED_SUPER, DeviceInfo, PlugCallback, UsbBackend,
                      UsbHandle)

log = logging.getLogger("vhserver.libusb")


def _install_unraisable_filter() -> None:
    """Quiet one specific, known-benign native fault instead of letting it print a raw, alarming traceback.

    When a USB stick is unplugged and replugged quickly enough that the grace period (GRACE_OPEN_SCANS)
    absorbs it, python-libusb1 ends up with a stale ``USBDevice`` wrapper from the scan before the blip.
    Nothing in our code frees it explicitly; it is only ever dropped by DeviceKeepalive.release_old(), up
    to ``keep_s`` later. On Windows, libusb's own device-removal handling for the WinUSB/driver-switch path
    can by then have already torn down the native structure behind that pointer, so the delayed
    ``libusb_unref_device()`` call -- made from CPython's weakref finalizer machinery, which we don't
    control -- reads/writes through it and faults. ctypes catches the resulting Windows SEH access
    violation and turns it into a Python OSError (the call never reaches our code, hence this hook rather
    than a try/except), so the process is not at risk; only the default traceback dump is alarming. Any
    other unraisable exception still gets the normal, visible traceback -- this filters nothing else.
    """
    default_hook = sys.unraisablehook

    def _hook(args) -> None:
        msg = str(args.exc_value) if args.exc_value else ""
        tb = args.exc_traceback
        while tb is not None and tb.tb_next is not None:  # the innermost frame is where it actually faulted
            tb = tb.tb_next
        tb_file = tb.tb_frame.f_code.co_filename if tb is not None else ""
        # In a PyInstaller-frozen build, this shows up as the bare "usb1\__init__.py" (no directory before
        # it: frozen modules report a synthetic path, not a real filesystem one), while an unfrozen install
        # reports the full "...\site-packages\usb1\__init__.py". PurePath.parts handles both: a leading
        # component with nothing before it, or "usb1" as one component among several.
        parts = PurePath(tb_file).parts
        if (args.exc_type is OSError and "access violation" in msg
                and len(parts) >= 2 and parts[-1] == "__init__.py" and parts[-2] == "usb1"):
            log.warning("libusb: native cleanup of a device that vanished and came back too fast for the "
                        "grace period hit a stale pointer (%s) -- harmless, already contained by ctypes", msg)
            return
        default_hook(args)

    sys.unraisablehook = _hook


_install_unraisable_filter()

POLL_INTERVAL_S = 1.0
IO_SLICE_MS = 200          # blocking IN transfers are cut in slices so that a release can interrupt them
DEFAULT_TIMEOUT_MS = 5000
CLOSE_WAIT_S = 15.0        # how long close() waits for transfers still running in worker threads
HUB_CLASS = 9
GRACE_SCANS = 2            # a device must be missing this many scans in a row before it counts as unplugged
GRACE_OPEN_SCANS = 12      # longer grace while it is in use: a driver switch makes it vanish for a moment
REDISCOVER_TIMEOUT_S = 20.0
SWITCH_WINDOW_S = 60.0     # after a driver switch the same device may be listed under another port path
BOOT_INPUT = {(3, 1, 1): "keyboard", (3, 1, 2): "mouse"}  # HID boot-protocol keyboards and mice

_SPEEDS = {usb1.SPEED_LOW: SPEED_LOW, usb1.SPEED_FULL: SPEED_FULL, usb1.SPEED_HIGH: SPEED_HIGH,
           usb1.SPEED_SUPER: SPEED_SUPER, usb1.SPEED_SUPER_PLUS: SPEED_SUPER}

_ERRNO = (
    (usb1.USBErrorPipe, proto.EPIPE),
    (usb1.USBErrorTimeout, proto.ETIMEDOUT),
    (usb1.USBErrorNoDevice, proto.ENODEV),
    (usb1.USBErrorNotFound, proto.ENODEV),
    (usb1.USBErrorOverflow, -75),
    (usb1.USBErrorBusy, -16),
    (usb1.USBErrorAccess, -13),
    (usb1.USBErrorIO, proto.EIO),
)


def errno_of(exc: Exception) -> int:
    for exc_type, code in _ERRNO:
        if isinstance(exc, exc_type):
            return code
    return proto.EIO


def _extra_bytes(node) -> bytes:
    """getExtra() yields a list of descriptor byte strings that followed the node in the raw descriptor."""
    return b"".join(bytes(part) for part in node.getExtra())


def reconstruct_config_descriptor(config) -> bytes:
    """Rebuild the raw configuration descriptor (with interfaces, endpoints and class-specific extras)."""
    body = bytearray()
    body += _extra_bytes(config)
    for interface in config:
        for setting in interface:
            body += struct.pack("<9B", 9, 4, setting.getNumber(), setting.getAlternateSetting(),
                                setting.getNumEndpoints(), setting.getClass(), setting.getSubClass(),
                                setting.getProtocol(), setting.getDescriptor())
            body += _extra_bytes(setting)
            for ep in setting:
                body += struct.pack("<BBBBHB", 7, 5, ep.getAddress(), ep.getAttributes(), ep.getMaxPacketSize(),
                                    ep.getInterval())
                body += _extra_bytes(ep)
    header = struct.pack("<BBHBBBBB", 9, 2, 9 + len(body), config.getNumInterfaces(), config.getConfigurationValue(),
                         config.getDescriptor(), config.getAttributes(), config.getMaxPower() // 2)
    return header + bytes(body)


def device_descriptor(dev) -> bytes:
    return struct.pack("<BBHBBBBHHHBBBB", 18, 1, dev.getbcdUSB(), dev.getDeviceClass(), dev.getDeviceSubClass(),
                       dev.getDeviceProtocol(), dev.getMaxPacketSize0(), dev.getVendorID(), dev.getProductID(),
                       dev.getbcdDevice(), dev.getManufacturerDescriptor(), dev.getProductDescriptor(),
                       dev.getSerialNumberDescriptor(), dev.getNumConfigurations())


def sysfs_descriptors(dev) -> bytes | None:
    """Exact raw descriptors from Linux sysfs (device descriptor + first configuration), if available.

    The bus/port path is cross-checked against the device's own VID:PID before the sysfs bytes are trusted
    (the same defense used in :mod:`linuxnames`): a stale port number, a device that was replugged between
    enumeration and this read, or -- in a test double -- a fabricated bus/port that happens to collide with a
    real device's path, must never hand this device another one's descriptors."""
    ports = dev.getPortNumberList()
    if not ports:
        return None
    node = f"/sys/bus/usb/devices/{dev.getBusNumber()}-{'.'.join(str(p) for p in ports)}"
    try:
        with open(node + "/idVendor") as fh:
            found_vid = int(fh.read().strip(), 16)
        with open(node + "/idProduct") as fh:
            found_pid = int(fh.read().strip(), 16)
    except (OSError, ValueError):
        return None
    if (found_vid, found_pid) != (dev.getVendorID(), dev.getProductID()):
        return None
    try:
        with open(node + "/descriptors", "rb") as fh:
            raw = fh.read()
    except OSError:
        return None
    if len(raw) < 27:
        return None
    total = struct.unpack_from("<H", raw, 20)[0]
    return raw[:18 + total]


def raw_descriptors(dev) -> bytes:
    exact = sysfs_descriptors(dev) if os.name == "posix" else None
    if exact is not None:
        return exact
    base = device_descriptor(dev)
    try:
        config = next(iter(dev.iterConfigurations()))
    except StopIteration:
        return base  # unconfigured device without configuration descriptors
    return base + reconstruct_config_descriptor(config)


def endpoint_info_of(config) -> dict[int, tuple[int, int]]:
    """endpoint address -> (transfer type, max packet size) for every endpoint of a configuration."""
    info: dict[int, tuple[int, int]] = {}
    for interface in config:
        for setting in interface:
            for ep in setting:
                info[ep.getAddress()] = (ep.getAttributes() & 3, ep.getMaxPacketSize())
    return info


class ConfigInfo:
    """What the handle needs to know about one configuration."""

    def __init__(self, interfaces: list[int], endpoints: dict[int, tuple[int, int]]) -> None:
        self.interfaces = interfaces
        self.endpoints = endpoints


def config_info_of(config) -> ConfigInfo:
    return ConfigInfo(sorted({iface[0].getNumber() for iface in config}), endpoint_info_of(config))


class LibUsbHandle(UsbHandle):
    """An opened device with all interfaces of the active configuration claimed.

    Every operation registers as "in flight"; close() refuses new work and waits for running work before it frees the
    interfaces, so libusb is never called on a closed handle.
    """

    def __init__(self, usb_handle, configs: dict[int, ConfigInfo], active: int,
                 on_close: Callable[[], None] | None = None) -> None:
        self._h = usb_handle
        self._configs = configs
        self._active = active
        self._on_close = on_close
        self._claimed: list[int] = []
        self._closing = threading.Event()
        self._cond = threading.Condition()
        self._inflight = 0
        try:
            self._h.setAutoDetachKernelDriver(True)
        except usb1.USBError:
            pass  # not supported on this platform
        self._claim_all()

    # ----- in-flight bookkeeping -----------------------------------------------------------------------------
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

    # ----- claiming ------------------------------------------------------------------------------------------
    @property
    def _ep_info(self) -> dict[int, tuple[int, int]]:
        return self._configs[self._active].endpoints

    def _claim_all(self) -> None:
        for number in self._configs[self._active].interfaces:
            try:
                self._h.claimInterface(number)
            except usb1.USBError as exc:
                self._release_all()
                raise OSError(f"cannot claim interface {number}: {exc}") from exc
            self._claimed.append(number)

    def _release_all(self) -> None:
        for number in reversed(self._claimed):
            try:
                self._h.releaseInterface(number)
            except usb1.USBError:
                pass
        self._claimed.clear()

    # ----- control -------------------------------------------------------------------------------------------
    def control(self, setup: bytes, data: bytes, timeout_ms: int) -> tuple[int, bytes]:
        if not self._enter():
            return proto.ENODEV, b""
        try:
            return self._control(setup, data, timeout_ms)
        finally:
            self._leave()

    def _control(self, setup: bytes, data: bytes, timeout_ms: int) -> tuple[int, bytes]:
        bm, req, value, index, length = struct.unpack("<BBHHH", setup)
        timeout = timeout_ms or DEFAULT_TIMEOUT_MS
        try:
            if bm == 0x00 and req == 0x09:
                return self._set_configuration(value)
            if bm == 0x01 and req == 0x0B:
                self._h.setInterfaceAltSetting(index, value)
                return 0, b""
            if bm == 0x02 and req == 0x01 and value == 0:
                self._h.clearHalt(index & 0xFF)
                return 0, b""
            if bm & 0x80:
                received = self._h.controlRead(bm, req, value, index, length, timeout)
                return len(received), bytes(received)
            written = self._h.controlWrite(bm, req, value, index, data, timeout)
            return written, b""
        except usb1.USBError as exc:
            return errno_of(exc), b""
        except OSError:
            return proto.EIO, b""

    def _set_configuration(self, value: int) -> tuple[int, bytes]:
        if value not in self._configs:
            return proto.EPIPE, b""  # not a configuration of this device: stall like a real device would
        if value == self._active:
            return 0, b""
        self._release_all()
        try:
            self._h.setConfiguration(value)
            self._active = value
        finally:
            self._claim_all()
        return 0, b""

    # ----- bulk / interrupt ----------------------------------------------------------------------------------
    def bulk(self, endpoint: int, length: int, data: bytes, timeout_ms: int) -> tuple[int, bytes]:
        if not self._enter():
            return proto.ENODEV, b""
        try:
            return self._bulk(endpoint, length, data, timeout_ms)
        finally:
            self._leave()

    def _bulk(self, endpoint: int, length: int, data: bytes, timeout_ms: int) -> tuple[int, bytes]:
        kind, packet = self._ep_info.get(endpoint, (2, 512))
        if kind == 1:
            return proto.EPIPE, b""  # isochronous endpoints are not supported yet
        try:
            if endpoint & 0x80:
                return self._read(endpoint, length, timeout_ms, kind, packet)
            write = self._h.interruptWrite if kind == 3 else self._h.bulkWrite
            return write(endpoint, data, timeout_ms or DEFAULT_TIMEOUT_MS), b""
        except usb1.USBError as exc:
            return errno_of(exc), b""

    def _read(self, endpoint: int, length: int, timeout_ms: int, kind: int, packet: int) -> tuple[int, bytes]:
        read = self._h.interruptRead if kind == 3 else self._h.bulkRead
        deadline = time.monotonic() + timeout_ms / 1000 if timeout_ms else None
        packet = max(packet & 0x7FF, 1)
        out = bytearray()
        while len(out) < length:
            if self._closing.is_set():
                return proto.ENODEV, b""
            try:
                chunk = bytes(read(endpoint, length - len(out), IO_SLICE_MS))
            except usb1.USBErrorTimeout as exc:
                chunk = bytes(getattr(exc, "received", b""))
                out += chunk
                if deadline is not None and time.monotonic() >= deadline:
                    return (len(out), bytes(out)) if out else (proto.ETIMEDOUT, b"")
                if chunk:
                    break
                continue
            out += chunk
            if len(chunk) % packet or not chunk:
                break  # short packet ends the transfer
        return len(out), bytes(out)

    # ----- misc ----------------------------------------------------------------------------------------------
    def reset(self) -> int:
        if not self._enter():
            return proto.ENODEV
        try:
            self._h.resetDevice()
            return 0
        except usb1.USBError as exc:
            return errno_of(exc)
        finally:
            self._leave()

    def clear_halt(self, endpoint: int) -> int:
        if not self._enter():
            return proto.ENODEV
        try:
            if endpoint not in self._ep_info:
                return proto.EPIPE
            self._h.clearHalt(endpoint)
            return 0
        except usb1.USBError as exc:
            return errno_of(exc)
        finally:
            self._leave()

    def close(self) -> None:
        with self._cond:
            if self._closing.is_set():
                return
            self._closing.set()
            deadline = time.monotonic() + CLOSE_WAIT_S
            while self._inflight and time.monotonic() < deadline:
                self._cond.wait(0.2)
            if self._inflight:
                log.warning("closing a device with %d transfer(s) still running", self._inflight)
        self._release_all()
        try:
            self._h.close()
        except usb1.USBError:
            pass
        if self._on_close is not None:
            try:
                self._on_close()
            except Exception:  # noqa: BLE001 - e.g. the driver restore failed; the device is closed regardless
                log.exception("cleanup after closing the device failed")


class LibUsbBackend(UsbBackend):
    def __init__(self, poll_interval: float = POLL_INTERVAL_S, share_hubs: bool = False,
                 share_input: bool = False, ignore: Iterable[tuple[int, int]] = (),
                 binder=None, name_lookup=None, uplink_check=None, direct_opener=None) -> None:
        self._direct_opener = direct_opener  # Windows: opens a WinUSB device by instance id, without libusb
        self._uplink_check = uplink_check  # (bus, ports) -> bool: the device carries this host's own network route
        self._name_lookup = name_lookup  # (vid, pid) -> winnames.StorageNames | None
        self._poll = poll_interval
        self._share_hubs = share_hubs
        self._share_input = share_input
        self._ignore = frozenset(ignore)
        self._ctx: usb1.USBContext | None = None
        self._stop = threading.Event()
        self._devices: dict[int, object] = {}
        self._infos: dict[int, DeviceInfo] = {}
        self._keys: dict[tuple, int] = {}
        self._withheld: set[tuple] = set()
        self._missing: dict[tuple, int] = {}
        self._switch_until: dict[tuple[int, int], float] = {}
        self._keepalive = DeviceKeepalive()
        self._open_ids: set[int] = set()
        self._binder = binder  # WinUsbBinder on Windows, None elsewhere
        self._next_id = 1
        # libusb device lists are not safe to build while another thread's list is being released (seen as an
        # access violation after a driver switch), so the poller and _rediscover enumerate one at a time
        self._enum_lock = threading.Lock()

    def start(self, on_plug: PlugCallback) -> None:
        self._ctx = usb1.USBContext()
        self._ctx.open()
        self._poller = threading.Thread(target=self._poll_loop, args=(on_plug,), daemon=True, name="usb-poll")
        self._poller.start()

    def stop(self) -> None:
        self._stop.set()
        poller = getattr(self, "_poller", None)
        if poller is not None and poller is not threading.current_thread():
            poller.join(timeout=5)
        if self._ctx is not None and (poller is None or not poller.is_alive()):
            try:
                self._ctx.close()
            except usb1.USBError:
                pass
            self._ctx = None

    @staticmethod
    def _key(dev) -> tuple:
        # no device address: it can change when a device is reset or its driver is switched, the port path does not
        return dev.getBusNumber(), tuple(dev.getPortNumberList()), dev.getVendorID(), dev.getProductID()

    def _poll_loop(self, on_plug: PlugCallback) -> None:
        while not self._stop.is_set():
            try:
                with self._enum_lock:
                    self._scan(on_plug)
                self._keepalive.release_old()  # the only place libusb wrappers are freed: this thread may block
            except Exception:  # noqa: BLE001 - the poller must survive any single failure
                log.exception("USB scan failed")
            self._stop.wait(self._poll)

    def _scan(self, on_plug: PlugCallback) -> None:
        present: dict[tuple, object] = {}
        for dev in self._list_devices():
            try:
                if self._shareable(dev):
                    present[self._key(dev)] = dev
            except usb1.USBError as exc:
                log.debug("skipping unreadable device: %s", exc)
        self._withheld &= present.keys()
        self._follow_moved_devices(present)
        for key in list(self._keys):  # removals first, after a short grace period
            device_id = self._keys[key]
            if key in present:
                self._missing.pop(key, None)
                continue
            self._missing[key] = self._missing.get(key, 0) + 1
            limit = GRACE_OPEN_SCANS if device_id in self._open_ids else GRACE_SCANS
            if self._missing[key] >= limit:
                self._missing.pop(key)
                del self._keys[key]
                if device_id not in self._keys.values():  # the device is gone only when every key of it is
                    self._devices.pop(device_id, None)
                    self._notify(on_plug, "remove", self._infos.pop(device_id))
        for key, device_id in self._keys.items():  # keep the freshest libusb object for open(): the newest key wins
            if key in present:
                self._devices[device_id] = present[key]
        for key, dev in present.items():
            if key in self._keys or key in self._withheld:
                continue
            alias = self._alias_target(key)
            if alias is not None:
                self._keys[key] = alias
                self._devices[alias] = dev
                log.info("device %d is also listed as %s: same device, driver being switched", alias, key[1])
                continue
            try:
                info = self._describe(dev)
            except _Withheld as why:
                self._withheld.add(key)
                log.info("not sharing: %s", why)
                continue
            except Exception:  # noqa: BLE001 - one broken device must not hide the others
                log.exception("cannot describe device %s", key)
                continue
            self._keys[key] = info.device_id
            self._devices[info.device_id] = dev
            self._infos[info.device_id] = info
            self._notify(on_plug, "add", info)

    def _list_devices(self):
        """Every list goes through the keepalive box so the wrappers are never freed on the event loop thread."""
        devices = self._ctx.getDeviceList(skip_on_error=True)
        self._keepalive.hold(devices)
        return devices

    def _note_switch(self, vid: int, pid: int) -> None:
        self._switch_until[(vid, pid)] = time.monotonic() + SWITCH_WINDOW_S

    def _in_switch_window(self, vid: int, pid: int) -> bool:
        return self._switch_until.get((vid, pid), 0.0) > time.monotonic()

    def _alias_target(self, key: tuple) -> int | None:
        """The device this key belongs to, if it is the same device reported under another key while its driver is
        being switched. Only when exactly one known device has these ids: identical sticks are never merged."""
        if not self._in_switch_window(key[2], key[3]):
            return None
        owners = {self._keys[k] for k in self._keys if k[2:] == key[2:]}
        return next(iter(owners)) if len(owners) == 1 else None

    def _follow_moved_devices(self, present: dict[tuple, object]) -> None:
        """A driver switch re-enumerates the device and Windows may then report another port path for it. If exactly
        one known device with some VID:PID vanished while exactly one unknown one with the same VID:PID showed up,
        it is the same device: keep its id instead of offering a second copy that cannot be opened."""
        gone = [key for key in self._keys if key not in present]
        new = [key for key in present if key not in self._keys and key not in self._withheld]
        for old_key in gone:
            same_gone = [k for k in gone if k[2:] == old_key[2:]]
            candidates = [k for k in new if k[2:] == old_key[2:]]
            if len(same_gone) != 1 or len(candidates) != 1:
                continue
            new_key = candidates[0]
            device_id = self._keys.pop(old_key)
            self._keys[new_key] = device_id
            self._missing.pop(old_key, None)
            self._devices[device_id] = present[new_key]
            new.remove(new_key)
            log.info("device %d is the same device as before, now on another port path (%s -> %s)",
                     device_id, old_key[1], new_key[1])

    @staticmethod
    def _notify(on_plug: PlugCallback, kind: str, info: DeviceInfo) -> None:
        try:
            on_plug(kind, info)
        except Exception:  # noqa: BLE001 - e.g. the event loop is already closed
            log.exception("plug callback failed")

    def _shareable(self, dev) -> bool:
        if (dev.getVendorID(), dev.getProductID()) in self._ignore:
            return False
        return self._share_hubs or dev.getDeviceClass() != HUB_CLASS

    def _describe(self, dev) -> DeviceInfo:
        vendor, product, serial = f"0x{dev.getVendorID():04x}", f"0x{dev.getProductID():04x}", ""
        ports = dev.getPortNumberList()
        try:
            handle = dev.open()
            try:
                vendor = handle.getManufacturer() or vendor
                product = handle.getProduct() or product
                serial = handle.getSerialNumber() or ""
            finally:
                handle.close()
        except usb1.USBError as exc:
            log.debug("cannot read strings of %04x:%04x: %s", dev.getVendorID(), dev.getProductID(), exc)
            vendor, product, serial = self._os_names(dev, vendor, product, ports)
        device_id = self._next_id
        self._next_id += 1
        info = DeviceInfo(device_id, dev.getVendorID(), dev.getProductID(), vendor, product, serial,
                          _SPEEDS.get(dev.getDeviceSpeed(), SPEED_HIGH), raw_descriptors(dev),
                          port=ports[-1] if ports else 0)
        kind = BOOT_INPUT.get(info.interface_triple())
        if kind is not None and not self._share_input:
            raise _Withheld(f"{vendor} {product} is a {kind} (use --share-input to offer it)")
        if self._uplink_check is not None and self._uplink_check(dev.getBusNumber(), ports):
            raise _Withheld(f"{vendor} {product} carries this machine's network connection")
        return info

    def _os_names(self, dev, vendor: str, product: str, ports: tuple) -> tuple[str, str, str]:
        """Names the OS knows when libusb cannot read the device's own strings (Windows storage devices owned
        by usbstor; occasionally Linux too, e.g. a usbfs permission a udev rule hasn't granted, or a device
        with no string descriptors for the kernel to show a name for)."""
        if self._name_lookup is None:
            return vendor, product, ""
        try:
            names = self._name_lookup(dev.getVendorID(), dev.getProductID(), bus=dev.getBusNumber(), ports=ports)
        except Exception:  # noqa: BLE001 - cosmetic data must never stop the device from being offered
            log.debug("name lookup failed", exc_info=True)
            names = None
        if names is None:
            return vendor, product, ""
        return names.vendor or vendor, names.product or product, names.serial

    def diagnose(self, device_id: int) -> str:
        info = self._infos.get(device_id)
        if self._binder is None or info is None or not hasattr(self._binder, "diagnose"):
            return ""
        return self._binder.diagnose(info.vid, info.pid)

    def _key_of(self, device_id: int) -> tuple | None:
        return next((k for k, v in self._keys.items() if v == device_id), None)

    def _rediscover(self, key: tuple):
        """After a driver switch libusb needs a fresh enumeration: wait until the device can be opened again. Windows may
        report it under another port path, so a unique device with the same ids that no other known device owns is
        accepted too (and remembered as an alias of this one)."""
        deadline = time.monotonic() + REDISCOVER_TIMEOUT_S
        device_id = self._keys.get(key)
        while time.monotonic() < deadline:
            if not self._enum_lock.acquire(timeout=1.0):  # the poller may be stuck inside libusb: keep trying
                continue
            try:
                found = self._probe_candidates(key, device_id)
            finally:
                self._enum_lock.release()
            if found is not None:
                return found
            time.sleep(0.5)
        raise OSError("device did not come back after the driver switch")

    def _probe_candidates(self, key: tuple, device_id: int | None):
        exact, others = [], []
        for dev in self._list_devices():
            try:
                found_key = self._key(dev)
            except usb1.USBError:
                continue
            if found_key == key:
                exact.append((found_key, dev))
            elif found_key[2:] == key[2:] and self._keys.get(found_key, device_id) == device_id:
                others.append((found_key, dev))
        candidates = exact or (others if len(others) == 1 else [])
        for found_key, dev in candidates:
            try:
                dev.open().close()
            except usb1.USBError:
                continue
            if found_key != key and device_id is not None:
                self._keys[found_key] = device_id
                self._devices[device_id] = dev
            return dev
        return None

    def open(self, device_id: int) -> UsbHandle:
        dev = self._devices.get(device_id)
        info = self._infos.get(device_id)
        key = self._key_of(device_id)
        if dev is None or info is None or key is None:
            raise OSError("device is gone")
        if self._binder is not None and self._direct_opener is not None:
            return self._open_direct(device_id, info)
        restore_id = None
        if self._binder is not None:
            restore_id = self._binder.prepare(info.vid, info.pid, info.serial, info.port or None)
            if restore_id is not None:
                self._note_switch(info.vid, info.pid)
                dev = self._rediscover(key)
        self._open_ids.add(device_id)
        try:
            return self._open_device(dev, device_id, restore_id)
        except BaseException:
            self._closed(device_id, restore_id)
            raise

    def _open_direct(self, device_id: int, info: DeviceInfo) -> UsbHandle:
        """Switch the driver, then open by instance id through winusb.dll: no libusb enumeration is involved, which is
        the call that could stop answering after a driver switch."""
        instance_id, switched = self._binder.prepare_direct(info.vid, info.pid, info.serial, info.port or None)
        restore_id = instance_id if switched else None
        if switched:
            self._note_switch(info.vid, info.pid)
        self._open_ids.add(device_id)
        try:
            return self._direct_opener.open(instance_id, info.descriptors,
                                            on_close=lambda: self._closed(device_id, restore_id))
        except BaseException:
            self._closed(device_id, restore_id)
            raise

    def _closed(self, device_id: int, restore_id: str | None) -> None:
        self._open_ids.discard(device_id)
        if restore_id is not None and self._binder is not None:
            info = self._infos.get(device_id)
            if info is not None:
                self._note_switch(info.vid, info.pid)  # restoring flips the port path back
            self._binder.restore(restore_id)

    def _open_device(self, dev, device_id: int, restore_id: str | None) -> UsbHandle:
        try:
            handle = dev.open()
        except usb1.USBError as exc:
            raise OSError(f"cannot open device: {exc}") from exc
        try:
            configs = {c.getConfigurationValue(): config_info_of(c) for c in dev.iterConfigurations()}
            if not configs:
                raise OSError("device has no configuration")
            active = handle.getConfiguration()
            if active not in configs:
                active = min(configs)
                handle.setConfiguration(active)
            return LibUsbHandle(handle, configs, active, on_close=lambda: self._closed(device_id, restore_id))
        except BaseException as exc:
            handle.close()
            if isinstance(exc, (usb1.USBError, StopIteration)):
                raise OSError(f"cannot claim device: {exc}") from exc
            raise


class _Withheld(Exception):
    """A device that is deliberately not shared; logged at info level and skipped."""
