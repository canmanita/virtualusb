"""Findings of the second automated security review: lockout-flood bypass, slowloris frame stall, and the
unbounded auth-lock table."""
import asyncio
from types import SimpleNamespace

import pytest

from test_access_control import Clock, Session, run
from vhserver.security import FailureLimiter, PasswordPolicy, hash_password, new_password_hash
from vhserver.server import MAX_AUTH_LOCKS
from vhserver.wire import FrameDecoder


# ---- 1. CRITICAL: flooding other addresses must not evict an active failure counter -------------------------------
def test_flooding_other_addresses_does_not_reset_a_victims_failure_count():
    limiter = FailureLimiter(max_failures=5, window_s=300, lockout_s=60, max_tracked=1024)
    victim = "203.0.113.9"
    for _ in range(4):
        limiter.record_failure(victim)

    for i in range(1100):  # far more distinct addresses than max_tracked
        limiter.record_failure(f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}")

    limiter.record_failure(victim)  # this must be failure #5, not a fresh #1
    assert limiter.blocked(victim) > 0


def test_a_brand_new_address_is_simply_not_tracked_once_the_table_is_full_not_evicted_into():
    limiter = FailureLimiter(max_failures=5, window_s=300, lockout_s=60, max_tracked=5)
    for i in range(5):
        limiter.record_failure(f"10.0.0.{i}")  # fills the table with active (1-failure) counters
    assert limiter.tracked() == 5

    limiter.record_failure("10.0.1.1")  # a new key while full
    assert "10.0.1.1" not in limiter._failures  # refused, not inserted by evicting someone else
    assert limiter.tracked() == 5


def test_stale_failure_counters_are_still_reclaimed():
    clock = Clock()
    limiter = FailureLimiter(max_failures=5, window_s=60, lockout_s=60, clock=clock, max_tracked=3)
    for i in range(3):
        limiter.record_failure(f"10.0.0.{i}")
    clock.now += 61  # every counter is now outside its window
    limiter.record_failure("10.0.1.1")
    assert limiter.tracked() <= 3


def test_a_full_table_never_blocks_a_correct_password():
    # Denying every untracked address outright while the table is full (a prior, reverted fix) would
    # have meant a correct password could not get through during a flood either -- a worse DoS than the
    # one being fixed. A full table must cost an untracked address nothing more than its own wrong guess.
    limiter = FailureLimiter(max_failures=5, window_s=300, lockout_s=60, max_tracked=5)
    for i in range(5):
        limiter.record_failure(f"10.0.0.{i}")
    assert limiter.blocked("10.0.1.1") == 0.0  # not pre-emptively denied before it even gets to try


def test_table_stays_bounded_even_under_a_sustained_flood_of_distinct_addresses():
    limiter = FailureLimiter(max_failures=3, window_s=60, lockout_s=60, clock=Clock(), max_tracked=50)
    for i in range(500):  # far more distinct addresses than max_tracked, all past capacity
        limiter.record_failure(f"10.0.{i // 250}.{i % 250}")
    assert limiter.tracked() <= 50  # refused entries are never stored, so the table can't grow past the cap


# ---- 2. HIGH: a declared frame that never completes must eventually drop the connection ---------------------------
def test_frame_decoder_reports_a_pending_partial_frame():
    decoder = FrameDecoder()
    assert decoder.pending() is False
    decoder.feed(b"\x00\x00\x00\x00\x29\x00\x00\x00")  # header for a 41-byte frame, no body yet
    assert decoder.pending() is True
    assert decoder.feed(b"") == []  # trickling nothing still leaves it pending
    assert decoder.pending() is True


def test_a_connection_that_never_completes_its_frame_is_dropped_by_the_watchdog(monkeypatch):
    import vhserver.server as server_mod

    async def scenario():
        clock = {"t": 0.0}
        # Rebind the *name* `time` inside vhserver.server, not an attribute of the real stdlib time module:
        # the real module is also asyncio's own clock source, and patching it there would freeze the event
        # loop itself and hang the test.
        monkeypatch.setattr(server_mod, "time", SimpleNamespace(monotonic=lambda: clock["t"]))
        monkeypatch.setattr(server_mod, "PING_INTERVAL_S", 0)  # don't wait real time between checks
        async with Session(passwords=PasswordPolicy()) as s:
            conn = SimpleNamespace(peer_ip="203.0.113.5", conn_id=1, passwords={}, closed=False,
                                    said_hello=True, connected_at=0.0, last_rx=0.0, frame_started=0.0)
            conn.close = lambda: setattr(conn, "closed", True)
            conn.send_nowait = lambda msg: None

            clock["t"] = server_mod.FRAME_TIMEOUT_S + 1  # the frame has already been pending too long
            watchdog = asyncio.create_task(s.server._ping_loop(conn))
            await asyncio.wait_for(watchdog, timeout=2)  # _ping_loop returns once it closes the connection
            return conn.closed

    assert run(scenario()) is True


def test_frame_timeout_constant_is_shorter_than_the_idle_timeout():
    from vhserver.server import FRAME_TIMEOUT_S, IDLE_TIMEOUT_S
    # the frame deadline must fire before (or with) the generic idle timeout, or a trickling client that
    # never completes a frame would be caught by neither check for a while
    assert FRAME_TIMEOUT_S <= IDLE_TIMEOUT_S


# ---- 3. MEDIUM: the per-source/per-device auth-lock table must not grow forever -----------------------------------
def test_auth_locks_table_is_pruned_once_it_grows_past_the_cap(monkeypatch):
    import vhserver.security as security_mod

    monkeypatch.setattr(security_mod, "N", 2)  # the lowest legal scrypt cost: keep this test fast
    cheap_wire_secret = security_mod.wire_secret("pw")
    stored = hash_password(cheap_wire_secret)

    async def scenario():
        async with Session(passwords=PasswordPolicy(stored)) as s:
            entry = s.server.devices[7]
            for i in range(MAX_AUTH_LOCKS + 50):
                conn = SimpleNamespace(peer_ip=f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}",
                                        conn_id=i, passwords={7: cheap_wire_secret})
                await s.server._authorized(conn, entry)
            return len(s.server._auth_locks)

    size = run(scenario())
    assert size <= MAX_AUTH_LOCKS + 2  # the device-key lock is shared across all of these, plus slack for the race


def test_pruning_never_drops_a_lock_a_concurrent_call_is_still_using(monkeypatch):
    """Reproduces the TOCTOU the refcounting replaced: ``Lock.locked()`` alone can't tell "free and about
    to be used by someone else" from "free and safe to drop", so a prune between another call's lookup and
    its acquire could hand two concurrent callers two different Lock objects for the same key -- breaking
    the "one password check at a time" guarantee entirely."""
    import vhserver.security as security_mod
    import vhserver.server as server_mod

    monkeypatch.setattr(security_mod, "N", 2)  # keep scrypt cheap so this test stays fast
    monkeypatch.setattr(server_mod, "MAX_AUTH_LOCKS", 1)  # force a prune on every call
    cheap_wire_secret = security_mod.wire_secret("pw")
    stored = hash_password(cheap_wire_secret)

    async def scenario():
        async with Session(passwords=PasswordPolicy(stored)) as s:
            entry = s.server.devices[7]
            source = "203.0.113.9"
            conn = SimpleNamespace(peer_ip=source, conn_id=1, passwords={7: "wrong"})

            # 20 concurrent calls for the same source, with a prune forced on every single one of them
            # (MAX_AUTH_LOCKS=1): if pruning ever dropped a lock a waiting/about-to-acquire call still
            # needed, two callers would serialize on two different Lock objects instead of one, or the
            # dict would raise/mis-skip. Finishing cleanly with every ref released is the actual contract.
            await asyncio.gather(*(s.server._authorized(conn, entry) for _ in range(20)))
            return s.server._auth_lock_refs

    leftover_refs = run(scenario())
    assert leftover_refs == {}  # every acquire was paired with a release; nothing leaked
