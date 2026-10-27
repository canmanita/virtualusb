"""Device nicknames: a friendly name chosen on any client and kept by the server for everybody."""
from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path

log = logging.getLogger("vhserver.nicknames")

MAX_NICKNAME_BYTES = 63  # the record field is 64 bytes including the terminator


def device_key(vid: int, pid: int, serial: str, port: int) -> str:
    """Stable identity of a device: its serial number, or the port it sits on when it has none."""
    return f"{vid:04x}:{pid:04x}:{serial}" if serial else f"{vid:04x}:{pid:04x}@{port}"


def clean_nickname(text: str) -> str:
    printable = "".join(ch for ch in text if ch.isprintable()).strip()
    raw = printable.encode("utf-8")[:MAX_NICKNAME_BYTES]
    return raw.decode("utf-8", errors="ignore")


class NicknameStore:
    def __init__(self, path: Path | None) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._names: dict[str, str] = self._load()

    def get(self, key: str) -> str:
        with self._lock:
            return self._names.get(key, "")

    def set(self, key: str, name: str) -> None:
        name = clean_nickname(name)
        with self._lock:
            if name:
                self._names[key] = name
            else:
                self._names.pop(key, None)
            self._save()

    def _load(self) -> dict[str, str]:
        if self._path is None:
            return {}
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        names = raw.get("nicknames") if isinstance(raw, dict) else None
        if not isinstance(names, dict):
            return {}
        return {k: clean_nickname(v) for k, v in names.items() if isinstance(k, str) and isinstance(v, str) and v}

    def _save(self) -> None:
        if self._path is None:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            temp = self._path.with_suffix(".tmp")
            temp.write_text(json.dumps({"nicknames": self._names}, ensure_ascii=False), encoding="utf-8")
            os.replace(temp, self._path)
        except OSError as exc:
            log.warning("cannot save the nicknames to %s: %s", self._path, exc)
