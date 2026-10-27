"""What the server itself spent on a device session, to tell its own time from network and client time."""
from __future__ import annotations

import time
from dataclasses import dataclass, field

SLOW_S = 1.0


@dataclass
class SessionStats:
    started: float = field(default_factory=time.monotonic)
    transfers: int = 0
    control: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    service_total: float = 0.0
    service_max: float = 0.0
    wait_total: float = 0.0
    wait_max: float = 0.0
    slow: int = 0

    def record(self, *, control: bool, inbound: bool, nbytes: int, service_s: float, wait_s: float) -> None:
        self.transfers += 1
        self.control += control
        if nbytes > 0:
            if inbound:
                self.bytes_in += nbytes
            else:
                self.bytes_out += nbytes
        self.service_total += service_s
        self.service_max = max(self.service_max, service_s)
        self.wait_total += wait_s
        self.wait_max = max(self.wait_max, wait_s)
        if service_s > SLOW_S:
            self.slow += 1

    def summary(self, now: float | None = None) -> str:
        if not self.transfers:
            return ""
        duration = (time.monotonic() if now is None else now) - self.started
        mean = self.service_total / self.transfers * 1000
        wait = self.wait_total / self.transfers * 1000
        return (f"session of {duration:.0f} s: {self.transfers} transfers ({self.control} control), "
                f"{self.bytes_in} bytes in / {self.bytes_out} bytes out; the server needed mean {mean:.0f} ms, "
                f"max {self.service_max * 1000:.0f} ms per transfer ({self.slow} slower than 1 s), "
                f"queue wait mean {wait:.0f} ms max {self.wait_max * 1000:.0f} ms")
