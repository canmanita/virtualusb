"""Detects an event loop that stopped answering (a stuck synchronous call) and leaves evidence, then restarts.

A heartbeat callback runs on the loop every ``interval`` seconds; a daemon thread checks it. After ``warn_after``
seconds without a beat every thread's stack is written to the log (once per stall); after ``exit_after`` seconds the
process exits with status 70 so the service manager (Task Scheduler / systemd) starts it again. Devices left on
WinUSB are handed back at the next start.
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
import threading
import time
import traceback
from typing import Callable

log = logging.getLogger("vhserver.watchdog")

EXIT_STATUS = 70
WARN_AFTER_S = 15.0
EXIT_AFTER_S = 90.0
INTERVAL_S = 1.0


def format_thread_stacks() -> str:
    names = {thread.ident: thread.name for thread in threading.enumerate()}
    parts = []
    for ident, frame in sys._current_frames().items():
        parts.append(f"--- thread {names.get(ident, '?')} ({ident})\n" + "".join(traceback.format_stack(frame)))
    return "\n".join(parts)


class LoopWatchdog:
    def __init__(self, loop: asyncio.AbstractEventLoop, *, interval: float = INTERVAL_S, warn_after: float = WARN_AFTER_S,
                 exit_after: float = EXIT_AFTER_S, exit_fn: Callable[[int], object] = os._exit,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._loop, self._interval = loop, interval
        self._warn_after, self._exit_after, self._exit_fn, self._clock = warn_after, exit_after, exit_fn, clock
        self._beat = clock()
        self._warned = False
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._handle: asyncio.TimerHandle | None = None

    def start(self) -> None:
        self._beat = self._clock()
        self._handle = self._loop.call_later(self._interval, self._tick)
        self._thread = threading.Thread(target=self._watch, name="loop-watchdog", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._handle is not None:
            self._handle.cancel()

    def _tick(self) -> None:  # runs on the loop
        self._beat = self._clock()
        self._handle = self._loop.call_later(self._interval, self._tick)

    def _watch(self) -> None:  # runs on its own thread
        while not self._stop.wait(self._interval):
            stalled = self._clock() - self._beat
            if stalled < self._warn_after:
                self._warned = False
                continue
            if not self._warned:
                self._warned = True
                log.error("event loop stalled for %.0f s; thread stacks:\n%s", stalled, format_thread_stacks())
            if stalled >= self._exit_after:
                log.critical("event loop stalled for %.0f s, exiting so the service is restarted", stalled)
                logging.shutdown()
                self._exit_fn(EXIT_STATUS)
                return
