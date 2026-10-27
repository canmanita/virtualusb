"""Remember which devices were switched to WinUSB so a crashed or killed server can hand them back on next start."""
from __future__ import annotations

import json
import logging
import os
import re
import threading
from pathlib import Path

log = logging.getLogger("vhserver.recovery")

_USB_INSTANCE = re.compile(r"^USB\\VID_[0-9A-F]{4}&PID_[0-9A-F]{4}\\[^\\]+$", re.IGNORECASE)


def is_usb_instance_id(text: object) -> bool:
    """Only top-level USB device ids are ever stored or restored: the state file must not become a way to remove other devices."""
    return isinstance(text, str) and _USB_INSTANCE.match(text) is not None


class PendingStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()

    def all(self) -> list[str]:
        with self._lock:
            return self._read()

    def add(self, instance_id: str) -> None:
        if not is_usb_instance_id(instance_id):
            return
        with self._lock:
            items = self._read()
            if instance_id not in items:
                self._write([*items, instance_id])

    def remove(self, instance_id: str) -> None:
        with self._lock:
            items = self._read()
            if instance_id in items:
                self._write([item for item in items if item != instance_id])

    def _read(self) -> list[str]:
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        items = raw.get("pending") if isinstance(raw, dict) else None
        if not isinstance(items, list):
            return []
        return [item for item in items if is_usb_instance_id(item)]

    def _write(self, items: list[str]) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            temp = self._path.with_suffix(".tmp")
            temp.write_text(json.dumps({"pending": items}), encoding="utf-8")
            os.replace(temp, self._path)
        except OSError as exc:
            log.warning("cannot save %s: %s", self._path, exc)
