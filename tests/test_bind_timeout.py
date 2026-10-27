"""A device that never finishes opening (the Windows driver switch hung in the field) must not wedge the server."""
import asyncio
import logging
import threading
import time

from test_access_control import Session, bind, run
from vhserver import protocol as proto
from vhserver import server as server_module
from vhserver.fakedisk import FakeDiskBackend


def slow_backend(monkeypatch, release: threading.Event, opened: list):
    original = FakeDiskBackend.open

    def slow_open(self, device_id):
        opened.append(time.monotonic())
        if len(opened) == 1:
            release.wait(10)  # the first attempt hangs until the test lets it go
        handle = original(self, device_id)
        return handle

    monkeypatch.setattr(FakeDiskBackend, "open", slow_open)


def test_a_hung_open_answers_with_an_error_and_logs_the_thread_stacks(monkeypatch, caplog):
    monkeypatch.setattr(server_module, "BIND_TIMEOUT_S", 0.3)
    release, opened = threading.Event(), []
    slow_backend(monkeypatch, release, opened)

    async def scenario():
        async with Session() as s:
            client = await s.client()
            started = time.monotonic()
            status = await bind(client)
            elapsed = time.monotonic() - started
            entry_free = s.server.devices[7].owner is None
            release.set()
            return status, elapsed, entry_free

    with caplog.at_level(logging.ERROR, logger="vhserver"):
        status, elapsed, entry_free = run(scenario())
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert status == proto.BIND_ERROR and elapsed < 3 and entry_free
    assert "took more than" in text and "slow_open" in text  # the stack shows where the open was stuck


def test_the_server_keeps_working_and_the_device_can_be_bound_again(monkeypatch):
    monkeypatch.setattr(server_module, "BIND_TIMEOUT_S", 0.3)
    release, opened = threading.Event(), []
    slow_backend(monkeypatch, release, opened)

    async def scenario():
        async with Session() as s:
            client = await s.client()
            first = await bind(client)
            release.set()
            await asyncio.sleep(0.2)          # the abandoned open finishes now
            second = await bind(client)
            return first, second

    first, second = run(scenario())
    assert first == proto.BIND_ERROR and second == proto.BIND_OK


def test_a_handle_that_arrives_after_the_timeout_is_closed_not_leaked(monkeypatch):
    monkeypatch.setattr(server_module, "BIND_TIMEOUT_S", 0.2)
    release, opened = threading.Event(), []
    slow_backend(monkeypatch, release, opened)
    closed = []
    from vhserver.fakedisk import FakeDiskHandle

    original_close = FakeDiskHandle.close
    monkeypatch.setattr(FakeDiskHandle, "close", lambda self: (closed.append(1), original_close(self))[1])

    async def scenario():
        async with Session() as s:
            client = await s.client()
            await bind(client)
            release.set()
            await asyncio.sleep(0.3)

    run(scenario())
    assert closed == [1]


def test_after_a_hung_open_the_service_restarts_itself(monkeypatch, caplog):
    """A native call stuck inside the OS cannot be cancelled; a clean restart is the only way out."""
    monkeypatch.setattr(server_module, "BIND_TIMEOUT_S", 0.2)
    monkeypatch.setattr(server_module, "RESTART_DELAY_S", 0.1)
    release, opened, exits = threading.Event(), [], []
    slow_backend(monkeypatch, release, opened)

    async def scenario():
        async with Session(exit_fn=exits.append) as s:
            client = await s.client()
            status = await bind(client)   # the client still gets its answer first
            await asyncio.sleep(0.4)
            release.set()
            return status

    with caplog.at_level(logging.ERROR, logger="vhserver"):
        status = run(scenario())
    assert status == proto.BIND_ERROR and exits == [70]
    assert "restarting" in "\n".join(r.getMessage() for r in caplog.records)


def test_restart_can_be_switched_off(monkeypatch):
    monkeypatch.setattr(server_module, "BIND_TIMEOUT_S", 0.2)
    monkeypatch.setattr(server_module, "RESTART_DELAY_S", 0.05)
    release, opened, exits = threading.Event(), [], []
    slow_backend(monkeypatch, release, opened)

    async def scenario():
        async with Session(exit_fn=exits.append, restart_on_hang=False) as s:
            client = await s.client()
            await bind(client)
            await asyncio.sleep(0.3)
            release.set()

    run(scenario())
    assert exits == []


def test_the_backend_is_asked_for_a_diagnosis_when_an_open_hangs(monkeypatch, caplog):
    monkeypatch.setattr(server_module, "BIND_TIMEOUT_S", 0.2)
    release, opened = threading.Event(), []
    slow_backend(monkeypatch, release, opened)
    monkeypatch.setattr(FakeDiskBackend, "diagnose", lambda self, device_id: "PnP state: problem code 0x2A", raising=False)

    async def scenario():
        async with Session(restart_on_hang=False) as s:
            client = await s.client()
            await bind(client)
            release.set()

    with caplog.at_level(logging.ERROR, logger="vhserver"):
        run(scenario())
    assert "problem code 0x2A" in "\n".join(r.getMessage() for r in caplog.records)
