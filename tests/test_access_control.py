"""Device passwords (message 66, bind status -8) and nicknames (message 42) against a server with a RAM disk."""
import asyncio
import struct

import pytest

from test_server_integration import MiniClient
from vhserver import protocol as proto
from vhserver.fakedisk import FakeDiskBackend
from vhserver.nicknames import NicknameStore, device_key
from vhserver.security import FailureLimiter, PasswordPolicy, new_password_hash, wire_secret
from vhserver.server import VhServer
from vhserver.wire import Message

HELLO = b" (tester)".ljust(64, b"\0") + b"TESTPC".ljust(64, b"\0") + bytes([6, 0, 3, 0])


class Clock:
    now = 1000.0

    def __call__(self):
        return self.now


class Session:
    """A running server plus helpers; used as ``async with``."""

    def __init__(self, **server_kwargs):
        self.kwargs = server_kwargs
        self.clock = Clock()

    async def __aenter__(self):
        self.server = VhServer(FakeDiskBackend(device_id=7, megabytes=1), name="Test Hub", **self.kwargs)
        self.tcp = await asyncio.start_server(self.server._on_client, "127.0.0.1", 0)
        self.server._loop = asyncio.get_running_loop()
        self.server.backend.start(self.server._on_plug_threadsafe)
        await asyncio.sleep(0.05)
        self.port = self.tcp.sockets[0].getsockname()[1]
        self.clients = []
        return self

    async def __aexit__(self, *exc):
        for client in self.clients:
            client.writer.close()
        self.tcp.close()
        await self.tcp.wait_closed()

    async def client(self) -> MiniClient:
        client = await MiniClient.connect(self.port)
        self.clients.append(client)
        await client.send(Message(proto.C_HELLO, HELLO))
        await client.expect(proto.S_SERVER_INFO)
        return client

    @property
    def key(self) -> str:
        info = self.server.devices[7].info
        return device_key(info.vid, info.pid, info.serial, info.port)


async def bind(client: MiniClient) -> int:
    await client.send(Message(proto.C_BIND, device=7))
    return struct.unpack_from("<i", (await client.expect(proto.S_BIND_DONE)).payload, 0)[0]


async def set_password(client: MiniClient, password: str, device: int = 7) -> Message:
    await client.send(Message(proto.C_SET_PASSWORD, wire_secret(password).encode(), device=device))
    return await client.expect(proto.S_PASSWORD_ACK)


def nickname_payload(device_id: int, name: str, serial: str = "") -> bytes:
    head = struct.pack("<HHI", 0x1209, 0x0001, device_id) + name.encode().ljust(64, b"\0")
    return head + serial.encode().ljust(136, b"\0") if serial else head


def run(coro):
    return asyncio.run(coro)


def test_open_server_binds_without_a_password():
    async def scenario():
        async with Session() as s:
            return await bind(await s.client())

    assert run(scenario()) == proto.BIND_OK


def test_password_is_required_and_checked():
    async def scenario():
        policy = PasswordPolicy(new_password_hash("s3cret"))
        async with Session(passwords=policy) as s:
            client = await s.client()
            outcome = {"none": await bind(client)}
            ack = await set_password(client, "wrong")
            outcome["ack_device"] = ack.device
            outcome["wrong"] = await bind(client)
            await set_password(client, "s3cret")
            outcome["right"] = await bind(client)
            outcome["owner"] = s.server.devices[7].owner is not None
            return outcome

    out = run(scenario())
    assert out["none"] == proto.BIND_PASSWORD_REQUIRED and out["wrong"] == proto.BIND_PASSWORD_REQUIRED
    assert out["ack_device"] == 7
    assert out["right"] == proto.BIND_OK and out["owner"] is True


def test_failed_bind_does_not_leak_the_descriptors():
    async def scenario():
        async with Session(passwords=PasswordPolicy(new_password_hash("pw"))) as s:
            client = await s.client()
            await client.send(Message(proto.C_BIND, device=7))
            return (await client.expect(proto.S_BIND_DONE)).payload

    payload = run(scenario())
    assert struct.unpack_from("<i", payload, 0)[0] == proto.BIND_PASSWORD_REQUIRED
    assert set(payload[5:5 + 64]) == {0}  # no descriptor bytes


def test_a_password_set_by_another_connection_does_not_authorise_this_one():
    async def scenario():
        async with Session(passwords=PasswordPolicy(new_password_hash("pw"))) as s:
            first, second = await s.client(), await s.client()
            await set_password(first, "pw")
            return await bind(second)

    assert run(scenario()) == proto.BIND_PASSWORD_REQUIRED


def test_repeated_wrong_passwords_lock_the_address_out():
    async def scenario():
        clock = Clock()
        limiter = FailureLimiter(max_failures=3, window_s=60, lockout_s=120, clock=clock)
        async with Session(passwords=PasswordPolicy(new_password_hash("pw")), limiter=limiter) as s:
            client = await s.client()
            await set_password(client, "bad")
            for _ in range(3):
                await bind(client)
            await set_password(client, "pw")
            locked = await bind(client)
            clock.now += 121
            return locked, await bind(client)

    locked, after = run(scenario())
    assert locked == proto.BIND_PASSWORD_REQUIRED  # even the right password is refused while locked out
    assert after == proto.BIND_OK


def test_per_device_password_leaves_other_devices_alone():
    async def scenario():
        async with Session() as probe:
            key = probe.key
        policy = PasswordPolicy(None, {"0000:0000:OTHER": new_password_hash("pw")})
        async with Session(passwords=policy) as s:
            return await bind(await s.client()), key

    status, _ = run(scenario())
    assert status == proto.BIND_OK


def test_oversized_password_is_ignored_but_acknowledged():
    async def scenario():
        async with Session(passwords=PasswordPolicy(new_password_hash("pw"))) as s:
            client = await s.client()
            await client.send(Message(proto.C_SET_PASSWORD, b"x" * 200, device=7))
            ack = await client.expect(proto.S_PASSWORD_ACK)
            return ack.mtype, await bind(client)

    mtype, status = run(scenario())
    assert mtype == proto.S_PASSWORD_ACK and status == proto.BIND_PASSWORD_REQUIRED


def test_nickname_is_stored_and_broadcast_to_every_client(tmp_path):
    async def scenario():
        store = NicknameStore(tmp_path / "nicknames.json")
        async with Session(nicknames=store) as s:
            first, second = await s.client(), await s.client()
            await first.send(Message(proto.C_SET_NICKNAME, nickname_payload(7, "Backup stick")))
            seen = [(await c.expect(proto.S_DEVICE_RECORD)).payload[157:157 + 12] for c in (first, second)]
            await second.send(Message(proto.C_LIST_DEVICES))
            listed = (await second.expect(proto.S_DEVICE_RECORD)).payload[157:157 + 12]
            return seen, listed, store.get(s.key)

    seen, listed, stored = run(scenario())
    assert seen == [b"Backup stick", b"Backup stick"] and listed == b"Backup stick" and stored == "Backup stick"


def test_empty_nickname_removes_it():
    async def scenario():
        store = NicknameStore(None)
        async with Session(nicknames=store) as s:
            client = await s.client()
            await client.send(Message(proto.C_SET_NICKNAME, nickname_payload(7, "Temp")))
            await client.expect(proto.S_DEVICE_RECORD)
            await client.send(Message(proto.C_SET_NICKNAME, nickname_payload(7, "")))
            record = await client.expect(proto.S_DEVICE_RECORD)
            return record.payload[157:160], store.get(s.key)

    shown, stored = run(scenario())
    assert shown == b"\0\0\0" and stored == ""


def test_nickname_of_a_protected_device_needs_the_password():
    async def scenario():
        store = NicknameStore(None)
        async with Session(nicknames=store, passwords=PasswordPolicy(new_password_hash("pw"))) as s:
            client = await s.client()
            await client.send(Message(proto.C_SET_NICKNAME, nickname_payload(7, "Sneaky")))
            denied = await client.expect(proto.S_TEXT)
            before = store.get(s.key)
            await set_password(client, "pw")
            await client.send(Message(proto.C_SET_NICKNAME, nickname_payload(7, "Allowed")))
            await client.expect(proto.S_DEVICE_RECORD)
            return denied.payload, before, store.get(s.key)

    denied, before, after = run(scenario())
    assert denied.startswith(b"INSUFFICIENT_PERMISSIONS_MSG") and before == "" and after == "Allowed"


def test_renaming_can_be_disabled():
    async def scenario():
        store = NicknameStore(None)
        async with Session(nicknames=store, allow_rename=False) as s:
            client = await s.client()
            await client.send(Message(proto.C_SET_NICKNAME, nickname_payload(7, "Nope")))
            await client.expect(proto.S_TEXT)
            return store.get(s.key)

    assert run(scenario()) == ""


def test_nickname_for_an_unknown_device_is_ignored():
    async def scenario():
        store = NicknameStore(None)
        async with Session(nicknames=store) as s:
            client = await s.client()
            await client.send(Message(proto.C_SET_NICKNAME, nickname_payload(99, "Ghost")))
            await client.send(Message(proto.C_PING))
            await client.expect(proto.S_PONG)  # still alive and in order
            return store.get(s.key)

    assert run(scenario()) == ""


def test_nickname_found_by_serial_when_the_id_is_stale():
    async def scenario():
        store = NicknameStore(None)
        async with Session(nicknames=store) as s:
            serial = s.server.devices[7].info.serial
            client = await s.client()
            await client.send(Message(proto.C_SET_NICKNAME, nickname_payload(555, "BySerial", serial=serial)))
            await client.expect(proto.S_DEVICE_RECORD)
            return store.get(s.key)

    assert run(scenario()) == "BySerial"


def test_truncated_nickname_payload_closes_the_connection():
    async def scenario():
        async with Session() as s:
            client = await s.client()
            await client.send(Message(proto.C_SET_NICKNAME, b"\x01\x02"))
            data = await asyncio.wait_for(client.reader.read(65536), 3)
            return data

    assert run(scenario()) == b""


def test_a_plain_password_from_a_client_that_does_not_hash_is_accepted():
    async def scenario():
        async with Session(passwords=PasswordPolicy(new_password_hash("s3cret"))) as s:
            client = await s.client()
            await client.send(Message(proto.C_SET_PASSWORD, b"s3cret", device=7))
            await client.expect(proto.S_PASSWORD_ACK)
            return await bind(client)

    assert run(scenario()) == proto.BIND_OK
