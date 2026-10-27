"""Keeps libusb device wrappers alive for a while and frees them only on the thread that calls ``release_old``.

python-libusb1 frees a device (``libusb_unref_device``) from a weakref callback, i.e. on whichever thread drops the last
reference. On Windows that native call can block while the Plug and Play manager is busy (right after a driver switch
or restore), and when it happened on the event loop thread the whole server stopped answering. Holding a reference here
means the last one is always dropped by ``release_old``, which the USB polling thread calls; if it blocks, only that
thread waits.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Callable, Iterable


class DeviceKeepalive:
    def __init__(self, keep_s: float = 60.0, clock: Callable[[], float] = time.monotonic, max_items: int = 5000) -> None:
        self._keep_s, self._clock, self._max = keep_s, clock, max_items
        self._items: deque = deque()
        self._lock = threading.Lock()

    def hold(self, devices: Iterable) -> None:
        now = self._clock()
        with self._lock:
            for device in devices:
                self._items.append((now, device))

    def release_old(self) -> int:
        """Drop references older than ``keep_s`` (and the oldest beyond ``max_items``); returns how many."""
        now, released = self._clock(), []
        with self._lock:
            while self._items and (now - self._items[0][0] >= self._keep_s or len(self._items) > self._max):
                released.append(self._items.popleft())
        count = len(released)
        released.clear()  # the references end here, on the calling thread, outside the lock
        return count

    def size(self) -> int:
        with self._lock:
            return len(self._items)
