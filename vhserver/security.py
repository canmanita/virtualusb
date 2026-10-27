"""Device passwords (scrypt hashes) and brute-force throttling.

The stock client does not send the password: it sends the 32 hex digits of its MD5 (observed with client 6.0.3). That
value is the credential on the wire, so anyone who can read the traffic can replay it; use the SSL port on networks
that are not fully trusted. The server stores a salted scrypt hash of that wire value, never the password itself.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import os
import re
import time
from typing import Callable, Mapping

SCHEME = "scrypt"
N, R, P = 2 ** 14, 8, 1
MAX_N = 2 ** 20           # refuse hostile parameters in a tampered configuration file
SALT_BYTES, HASH_BYTES = 16, 32
MAX_PASSWORD_BYTES = 127  # the protocol field carries at most 127 bytes
IPV6_LOCKOUT_PREFIX = 64  # one subscriber gets a whole /64, so single addresses inside it are free to rotate


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=HASH_BYTES,
                          maxmem=128 * n * r * 2 + 1024 * 1024)


_MD5_HEX = re.compile(r"^([0-9a-fA-F]{32})(?: \(.*\))?$")  # stock GUI client appends " (username)" after the hash


def wire_secret(password: str) -> str:
    """What the stock client sends for ``password``: the lowercase hex MD5."""
    return hashlib.md5(password.encode("utf-8")).hexdigest()  # noqa: S324 - fixed by the protocol, not a design choice


def new_password_hash(password: str) -> str:
    """The value to store in the configuration for ``password``."""
    return hash_password(wire_secret(password))


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(SALT_BYTES)
    digest = _scrypt(password, salt, N, R, P)
    return "$".join([SCHEME, str(N), str(R), str(P), base64.b64encode(salt).decode(), base64.b64encode(digest).decode()])


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt64, digest64 = stored.split("$")
        n, r, p = int(n), int(r), int(p)
        salt, expected = base64.b64decode(salt64, validate=True), base64.b64decode(digest64, validate=True)
        if scheme != SCHEME or not (2 <= n <= MAX_N and n & (n - 1) == 0) or not (1 <= r <= 32 and 1 <= p <= 16):
            return False
        if len(expected) != HASH_BYTES or not salt:
            return False
        actual = _scrypt(password, salt, n, r, p)
    except (ValueError, binascii.Error, MemoryError):
        return False
    return hmac.compare_digest(actual, expected)


def verify_supplied(supplied: str, stored: str) -> bool:
    """Check what a client sent: the wire value (32 hex digits), or a plain password from a client that does not hash."""
    match = _MD5_HEX.match(supplied)
    if match:
        return verify_password(match.group(1).lower(), stored)
    return bool(supplied) and verify_password(wire_secret(supplied), stored)


class PasswordPolicy:
    """Which devices need a password: an optional server-wide hash and optional per-device hashes (these win)."""

    def __init__(self, global_hash: str | None = None, per_device: Mapping[str, str] | None = None) -> None:
        self._global = global_hash or None
        self._per_device = dict(per_device or {})

    @property
    def is_open(self) -> bool:
        return self._global is None and not self._per_device

    def hash_for(self, device_key: str) -> str | None:
        return self._per_device.get(device_key) or self._global


def limiter_key(address: str) -> str:
    """What a lockout is counted against: the address for IPv4, the whole /64 network for IPv6."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return address
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return str(ip.ipv4_mapped)
        return str(ipaddress.ip_network((ip, IPV6_LOCKOUT_PREFIX), strict=False))
    return str(ip)


class FailureLimiter:
    """Blocks a key for ``lockout_s`` after ``max_failures`` wrong passwords inside ``window_s``.

    ``max_tracked`` bounds the counters of keys that are not locked out yet; an active lockout is never evicted to make
    room (that would let an attacker flush it by spraying failures from many sources)."""

    def __init__(self, max_failures: int = 5, window_s: float = 300.0, lockout_s: float = 60.0,
                 clock: Callable[[], float] = time.monotonic, max_tracked: int = 1024) -> None:
        self._max, self._window, self._lockout = max_failures, window_s, lockout_s
        self._clock, self._max_tracked = clock, max_tracked
        self._failures: dict[str, list[float]] = {}
        self._blocked_until: dict[str, float] = {}

    def blocked(self, address: str) -> float:
        """Seconds the address must still wait (0 when it may try)."""
        until = self._blocked_until.get(address, 0.0)
        remaining = until - self._clock()
        if remaining <= 0:
            self._blocked_until.pop(address, None)
            return 0.0
        return remaining

    def record_failure(self, address: str) -> None:
        now = self._clock()
        self._trim(now)
        existing = self._failures.get(address)
        if existing is None and len(self._failures) >= self._max_tracked:
            # At capacity and this address has no counter yet: refuse to start one rather than evict
            # someone else's active counter to make room (that would let an attacker flush any victim's
            # count by spraying failures from a flood of other addresses -- the bug this table-eviction
            # policy exists to close). This address simply isn't rate-limited for this one call; it is
            # not punished, because punishing it here would mean punishing based on nothing but the
            # table being busy, and `blocked()` has no way to tell "denied because this guess was wrong"
            # from "denied because of unrelated traffic" -- which would have meant turning a full table
            # into a blanket lockout that a correct password could not get past either. Its wrong guess
            # here still costs it the scrypt verification; a sustained flood large enough to keep 1024
            # distinct addresses simultaneously active is already a far more expensive attack than the
            # one this limiter exists to stop.
            return
        recent = [t for t in existing or [] if now - t < self._window]
        recent.append(now)
        self._failures[address] = recent
        if len(recent) >= self._max:
            self._blocked_until[address] = now + self._lockout
            self._failures.pop(address, None)

    def tracked(self) -> int:
        return len(self._failures) + len(self._blocked_until)

    def _trim(self, now: float) -> None:
        """Drop only entries that are genuinely stale (expired lockouts, failure counts whose window has
        fully elapsed). Active entries are never evicted to make room, which is what let an attacker flush
        a victim's counter by spraying failures from many other addresses."""
        if len(self._blocked_until) > self._max_tracked:
            for address in [a for a, until in self._blocked_until.items() if until <= now]:
                del self._blocked_until[address]
        if len(self._failures) > self._max_tracked:
            for address in [a for a, times in self._failures.items() if not any(now - t < self._window for t in times)]:
                del self._failures[address]
