"""VirtualUSB server (asyncio). Speaks the stock client's wire protocol over plain TCP."""
from __future__ import annotations

import asyncio
import logging
import os
import socket
import ssl
import struct
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from . import protocol as proto
from .backend import DeviceInfo, UsbBackend, UsbHandle
from .discovery import Discovery
from .netpolicy import AccessPolicy
from .nicknames import NicknameStore, device_key
from .sessionstats import SessionStats
from .security import FailureLimiter, PasswordPolicy, limiter_key, verify_supplied
from .watchdog import LoopWatchdog, format_thread_stacks
from .wire import FrameDecoder, Message

log = logging.getLogger("vhserver")

PING_INTERVAL_S = 4
IDLE_TIMEOUT_S = 20          # the stock client pings about once a second
WRITE_TIMEOUT_S = 15
OUTBOX_LIMIT = 512           # queued messages per connection before it is dropped as too slow
URB_QUEUE_LIMIT = 128        # queued transfers per endpoint
MAX_CONNECTIONS = 32
BIND_TIMEOUT_S = 45           # opening a device (driver switch included) that takes longer is abandoned
RESTART_DELAY_S = 2.0         # after a hung open the answer is sent first, then the process restarts
RESTART_EXIT_STATUS = 70
MAX_CONNECTIONS_PER_IP = 8
HELLO_TIMEOUT_S = 10          # a client that stays silent after connecting is dropped
MAX_STORED_PASSWORDS = 64
FRAME_TIMEOUT_S = 15          # a declared frame that stays incomplete this long is a stalled/slowloris client
MAX_AUTH_LOCKS = 1024         # cap on tracked per-source/per-device auth locks; only unheld ones are pruned
SSL_HANDSHAKE_TIMEOUT_S = 10
DEFAULT_SSL_PORT = 7574
DEFAULT_URB_TIMEOUT_MS = 5000
UNLIMITED_URB_TIMEOUT_MS = 120_000   # a request without timeout (0) is capped here
MAX_URB_TIMEOUT_MS = 120_000
IO_THREADS = 48
EBUSY = -16

Call = Callable[[UsbHandle], tuple[int, bytes]]


@dataclass
class DeviceEntry:
    info: DeviceInfo
    owner: "Connection | None" = None
    handle: UsbHandle | None = None
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    queues: dict[int, asyncio.Queue] = field(default_factory=dict)
    workers: list[asyncio.Task] = field(default_factory=list)
    removed: bool = False
    stats: SessionStats | None = None

    @property
    def state(self) -> int:
        return proto.STATE_IN_USE if self.owner else proto.STATE_FREE


class Connection:
    def __init__(self, server: "VhServer", reader: asyncio.StreamReader, writer: asyncio.StreamWriter, conn_id: int):
        self.server = server
        self.reader = reader
        self.writer = writer
        self.conn_id = conn_id
        self.guid = uuid.uuid4().bytes
        peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
        self.peer_ip: str = peer[0]
        self.passwords: dict[int, str] = {}  # device id -> password the client sent for it (message 66)
        self.hello = proto.ClientHello("", "", (0, 0, 0))
        self.closed = False
        self.last_rx = time.monotonic()
        self.connected_at = self.last_rx
        self.frame_started: float | None = None  # when the current incomplete frame started buffering
        self.said_hello = False
        self._outbox: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=OUTBOX_LIMIT)
        self._writer_task: asyncio.Task | None = None

    def start_writer(self) -> None:
        self._writer_task = asyncio.create_task(self._write_loop())

    async def _write_loop(self) -> None:
        try:
            while True:
                data = await self._outbox.get()
                if data is None:
                    break
                self.writer.write(data)
                await asyncio.wait_for(self.writer.drain(), WRITE_TIMEOUT_S)
        except (ConnectionError, OSError, asyncio.TimeoutError):
            log.warning("connection %d: write failed or timed out, dropping it", self.conn_id)
        finally:
            self.close()

    def send_nowait(self, msg: Message) -> None:
        if self.closed:
            return
        try:
            self._outbox.put_nowait(msg.encode())
        except asyncio.QueueFull:
            log.warning("connection %d is too slow (outbox full), dropping it", self.conn_id)
            self.close()

    async def send(self, msg: Message) -> None:
        self.send_nowait(msg)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            self.writer.close()
        except OSError:
            pass
        if self._writer_task is not None and self._writer_task is not asyncio.current_task():
            self._writer_task.cancel()

    def ipv4_bytes(self) -> bytes:
        try:
            return socket.inet_aton(self.peer_ip)
        except OSError:
            return bytes(4)

    def local_iface_name(self) -> str:
        return self.server.iface_name


class VhServer:
    def __init__(self, backend: UsbBackend, name: str = "VH Clone", port: int = 7575, serial: str | None = None,
                 bind_host: str = "0.0.0.0", policy: AccessPolicy | None = None,
                 passwords: PasswordPolicy | None = None, nicknames: NicknameStore | None = None,
                 limiter: FailureLimiter | None = None,
                 allow_rename: bool = True,
                 ssl_context: ssl.SSLContext | None = None, ssl_port: int = DEFAULT_SSL_PORT,
                 allow_plaintext: bool = True, discovery_name: str | None = None,
                 restart_on_hang: bool = True, exit_fn: Callable[[int], object] = os._exit):
        self.backend = backend
        self.name = name
        self.port = port
        self.bind_host = bind_host
        self.policy = policy or AccessPolicy()
        self.passwords = passwords or PasswordPolicy()
        self.nicknames = nicknames or NicknameStore(None)
        self.limiter = limiter or FailureLimiter()
        self.allow_rename = allow_rename
        if not allow_plaintext and ssl_context is None:
            raise ValueError("plain connections are disabled but no TLS certificate is configured")
        self.ssl_context, self.ssl_port, self.allow_plaintext = ssl_context, ssl_port, allow_plaintext
        self.discovery_name = discovery_name  # mDNS instance name; None keeps the stock one
        self.restart_on_hang, self._exit_fn = restart_on_hang, exit_fn
        self.serial = serial or f"{uuid.getnode():012x}"
        self.iface_name = "eth0"
        self.devices: dict[int, DeviceEntry] = {}
        self.connections: dict[int, Connection] = {}
        self._next_conn = 1
        self._loop: asyncio.AbstractEventLoop | None = None
        self._io = ThreadPoolExecutor(max_workers=IO_THREADS, thread_name_prefix="usb-io")
        self._ctl = ThreadPoolExecutor(max_workers=4, thread_name_prefix="usb-ctl")
        self._plug_events: asyncio.Queue | None = None
        self._plug_task: asyncio.Task | None = None
        self._auth_locks: dict[str, asyncio.Lock] = {}  # one password check at a time per address (or IPv6 /64)
        self._auth_lock_refs: dict[str, int] = {}  # how many calls currently hold or are about to use each lock

    # ---- lifecycle ------------------------------------------------------------------------------------------
    async def run(self, announce: bool = True) -> None:
        self._loop = asyncio.get_running_loop()
        watchdog = LoopWatchdog(self._loop)
        watchdog.start()
        self._ensure_plug_consumer()
        self.backend.start(self._on_plug_threadsafe)
        listeners = await self.start_listeners()
        discovery = None
        if announce:
            names = {"friendly_name": self.discovery_name} if self.discovery_name else {}
            discovery = Discovery(self.serial, self.port, ssl_port=self.ssl_port if self.ssl_context else None,
                                  plain=self.allow_plaintext, **names)
        try:
            if discovery is not None:
                await discovery.start()
            await asyncio.gather(*(listener.serve_forever() for listener in listeners))
        finally:
            watchdog.stop()
            for listener in listeners:
                listener.close()
            await self.shutdown(discovery)

    async def start_listeners(self) -> list[asyncio.Server]:
        """The plain TCP port and/or the TLS port (certificate required), as configured."""
        listeners: list[asyncio.Server] = []
        if self.allow_plaintext:
            listeners.append(await asyncio.start_server(self._on_client, host=self.bind_host, port=self.port))
            log.info("listening on %s:%d as %r", self.bind_host, self.port, self.name)
        if self.ssl_context is not None:
            listeners.append(await asyncio.start_server(self._on_client, host=self.bind_host, port=self.ssl_port,
                                                        ssl=self.ssl_context,
                                                        ssl_handshake_timeout=SSL_HANDSHAKE_TIMEOUT_S))
            log.info("listening on %s:%d (TLS) as %r", self.bind_host, self.ssl_port, self.name)
        return listeners

    async def shutdown(self, discovery: Discovery | None = None) -> None:
        if discovery is not None:
            await discovery.stop()
        self.backend.stop()
        for conn in list(self.connections.values()):
            conn.close()
        for entry in list(self.devices.values()):
            await self._safe_release(entry)
        if self._plug_task is not None:
            self._plug_task.cancel()
        self._io.shutdown(wait=False, cancel_futures=True)
        self._ctl.shutdown(wait=False)

    # ---- hot-plug events (single consumer keeps add/remove ordered) -------------------------------------------
    def _ensure_plug_consumer(self) -> None:
        if self._plug_events is None:
            self._plug_events = asyncio.Queue()
            self._plug_task = asyncio.create_task(self._plug_consumer())

    async def _plug_consumer(self) -> None:
        assert self._plug_events is not None
        while True:
            kind, info = await self._plug_events.get()
            try:
                await self._plug(kind, info)
            except Exception:  # noqa: BLE001 - one bad event must not stop hot-plug handling
                log.exception("hot-plug event %s failed", kind)

    def _on_plug_threadsafe(self, kind: str, info: DeviceInfo) -> None:
        loop = self._loop
        if loop is None:
            self._apply_plug(kind, info)
        else:
            loop.call_soon_threadsafe(self._enqueue_plug, kind, info)

    def _enqueue_plug(self, kind: str, info: DeviceInfo) -> None:
        self._ensure_plug_consumer()
        assert self._plug_events is not None
        self._plug_events.put_nowait((kind, info))

    def _apply_plug(self, kind: str, info: DeviceInfo) -> None:
        if kind == "add":
            self.devices.setdefault(info.device_id, DeviceEntry(info))
        else:
            self.devices.pop(info.device_id, None)

    async def _plug(self, kind: str, info: DeviceInfo) -> None:
        log.info("device %s %04x:%04x %s [key %s]", kind, info.vid, info.pid, info.product,
                 device_key(info.vid, info.pid, info.serial, info.port))
        if kind == "add":
            self._apply_plug(kind, info)
            self._broadcast(self._record_msg(self.devices[info.device_id]))
            return
        entry = self.devices.pop(info.device_id, None)
        if entry is not None:
            entry.removed = True
            owner = entry.owner
            await self._safe_release(entry)  # surprise removal: tell the owner the device is gone
            if owner is not None:
                owner.send_nowait(Message(proto.S_UNBIND_DONE, struct.pack("<I", 1), device=info.device_id))
        self._broadcast(Message(proto.S_DEVICE_RECORD,
                                proto.build_device_record(info.to_record(state=proto.STATE_GONE))))

    # ---- connection handling --------------------------------------------------------------------------------
    async def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("?", 0)
        peer_key = limiter_key(peer[0])
        same_ip = sum(1 for c in self.connections.values() if limiter_key(c.peer_ip) == peer_key)
        if (not self.policy.permits(peer[0]) or len(self.connections) >= MAX_CONNECTIONS
                or same_ip >= MAX_CONNECTIONS_PER_IP):
            log.warning("refusing connection from %s", peer[0])
            writer.close()
            return
        sock = writer.get_extra_info("socket")
        if sock is not None:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        conn = Connection(self, reader, writer, self._next_conn)
        self._next_conn += 1
        self.connections[conn.conn_id] = conn
        conn.start_writer()
        log.info("client %s connected as connection %d", conn.peer_ip, conn.conn_id)
        watchdog = asyncio.create_task(self._ping_loop(conn))
        decoder = FrameDecoder()
        try:
            while not conn.closed:
                data = await reader.read(65536)
                if not data:
                    break
                conn.last_rx = time.monotonic()
                for msg in decoder.feed(data):
                    await self._dispatch_safe(conn, msg)
                if not decoder.pending():
                    conn.frame_started = None
                elif conn.frame_started is None:
                    conn.frame_started = conn.last_rx
        except (ConnectionError, OSError, ValueError) as exc:
            log.warning("connection %d: %s", conn.conn_id, exc)
        except Exception:  # noqa: BLE001
            log.exception("connection %d: unexpected error", conn.conn_id)
        finally:
            watchdog.cancel()
            conn.close()
            self.connections.pop(conn.conn_id, None)
            for entry in list(self.devices.values()):
                if entry.owner is conn:
                    await self._safe_release(entry)
                    self._broadcast(self._record_msg(entry))
            log.info("connection %d closed", conn.conn_id)

    async def _ping_loop(self, conn: Connection) -> None:
        while not conn.closed:
            await asyncio.sleep(PING_INTERVAL_S)
            if not conn.said_hello and time.monotonic() - conn.connected_at > HELLO_TIMEOUT_S:
                log.warning("connection %d sent no hello within %ds, dropping it", conn.conn_id, HELLO_TIMEOUT_S)
                conn.close()
                return
            if time.monotonic() - conn.last_rx > IDLE_TIMEOUT_S:
                log.warning("connection %d idle for %ds, dropping it", conn.conn_id, IDLE_TIMEOUT_S)
                conn.close()
                return
            if conn.frame_started is not None and time.monotonic() - conn.frame_started > FRAME_TIMEOUT_S:
                log.warning("connection %d: frame incomplete after %ds, dropping it (slow trickle)",
                            conn.conn_id, FRAME_TIMEOUT_S)
                conn.close()
                return
            conn.send_nowait(Message(proto.S_PING, struct.pack("<I", int(time.time()) & 0xFFFFFFFF)))

    # ---- dispatch -------------------------------------------------------------------------------------------
    async def _dispatch_safe(self, conn: Connection, msg: Message) -> None:
        try:
            await self._dispatch(conn, msg)
        except ValueError as exc:  # malformed payload: protocol violation
            log.warning("connection %d: bad type %d message: %s", conn.conn_id, msg.mtype, exc)
            conn.close()
        except Exception:  # noqa: BLE001
            log.exception("connection %d: handler for type %d failed", conn.conn_id, msg.mtype)

    async def _dispatch(self, conn: Connection, msg: Message) -> None:
        handler = {
            proto.C_HELLO: self._h_hello,
            proto.C_KEEPALIVE: self._h_keepalive,
            proto.C_LIST_DEVICES: self._h_list,
            proto.C_PING: self._h_ping,
            proto.C_PONG: self._h_noop,
            proto.C_BIND: self._h_bind,
            proto.C_UNBIND: self._h_unbind,
            proto.C_CONTROL: self._h_control,
            proto.C_BULK: self._h_bulk,
            proto.C_BULK_STREAMS: self._h_bulk,
            proto.C_QUERY_STATUS: self._h_query,
            proto.C_SET_PASSWORD: self._h_set_password,
            proto.C_SET_NICKNAME: self._h_set_nickname,
        }.get(msg.mtype)
        if handler:
            await handler(conn, msg)
        elif msg.mtype in proto.STATUS_REPLY_TYPES:
            await self._h_status(conn, msg)
        else:
            log.debug("conn %d: ignoring unsupported message type %d (%d bytes)", conn.conn_id, msg.mtype,
                      len(msg.payload))

    async def _h_noop(self, conn: Connection, msg: Message) -> None:
        return None

    async def _h_hello(self, conn: Connection, msg: Message) -> None:
        conn.hello = proto.parse_hello(msg.payload)
        conn.said_hello = True
        log.info("hello from %r (%s) client v%s", conn.hello.name, conn.hello.host, conn.hello.version)
        info = proto.build_server_info(self.name, self.serial, socket.gethostname(), conn.local_iface_name(), conn.guid)
        conn.send_nowait(msg.reply(proto.S_SERVER_INFO, info))

    async def _h_keepalive(self, conn: Connection, msg: Message) -> None:
        conn.send_nowait(msg.reply(proto.S_KEEPALIVE_ACK))

    async def _h_ping(self, conn: Connection, msg: Message) -> None:
        conn.send_nowait(msg.reply(proto.S_PONG))

    async def _h_query(self, conn: Connection, msg: Message) -> None:
        conn.send_nowait(msg.reply(proto.S_QUERY_STATUS_DONE, struct.pack("<iH", 0, 0)))

    async def _h_list(self, conn: Connection, msg: Message) -> None:
        for entry in list(self.devices.values()):
            conn.send_nowait(self._record_msg(entry))

    # ---- device records -------------------------------------------------------------------------------------
    def _record_msg(self, entry: DeviceEntry) -> Message:
        owner = entry.owner
        overrides: dict = {"state": entry.state, "nickname": self.nicknames.get(self._key(entry))}
        if owner:
            overrides.update(user_guid=owner.guid, user_ipv4=owner.ipv4_bytes(), user_name=owner.hello.name,
                             user_host=owner.hello.host)
        return Message(proto.S_DEVICE_RECORD, proto.build_device_record(entry.info.to_record(**overrides)))

    def _broadcast(self, msg: Message) -> None:
        for conn in list(self.connections.values()):
            conn.send_nowait(msg)

    @staticmethod
    def _key(entry: DeviceEntry) -> str:
        info = entry.info
        return device_key(info.vid, info.pid, info.serial, info.port)

    # ---- passwords and nicknames ----------------------------------------------------------------------------
    async def _h_set_password(self, conn: Connection, msg: Message) -> None:
        password = proto.parse_password(msg.payload)
        log.debug('connection %d: password message for device %d: %s', conn.conn_id, msg.device,
                  proto.describe_password_payload(msg.payload))
        if password is None:
            log.warning("connection %d: password for device %d is too long, ignored", conn.conn_id, msg.device)
        elif msg.device in conn.passwords or len(conn.passwords) < MAX_STORED_PASSWORDS:
            conn.passwords[msg.device] = password
        conn.send_nowait(msg.reply(proto.S_PASSWORD_ACK))

    def _acquire_auth_lock(self, key: str) -> asyncio.Lock:
        """Look up (or create) the lock for ``key`` and mark it in use. Pair with ``_release_auth_lock``.

        Reference-counted rather than pruned by ``Lock.locked()``: a lock can be looked up by one call and
        not yet acquired when another call prunes the table, and ``locked()`` alone can't distinguish "free
        and about to be used" from "free and safe to drop" — refcounting can."""
        self._auth_lock_refs[key] = self._auth_lock_refs.get(key, 0) + 1
        return self._auth_locks.setdefault(key, asyncio.Lock())

    def _release_auth_lock(self, key: str) -> None:
        refs = self._auth_lock_refs.get(key, 0) - 1
        if refs <= 0:
            self._auth_lock_refs.pop(key, None)
        else:
            self._auth_lock_refs[key] = refs
        self._prune_auth_locks()

    def _prune_auth_locks(self) -> None:
        """Keep ``_auth_locks`` bounded: drop locks with no current user (refcount zero). Lets a flood of
        distinct sources grow the table only up to ``MAX_AUTH_LOCKS``, instead of without limit for the
        server's whole lifetime, without ever dropping a lock another call is still relying on."""
        if len(self._auth_locks) <= MAX_AUTH_LOCKS:
            return
        for key in [k for k in self._auth_locks if self._auth_lock_refs.get(k, 0) == 0]:
            del self._auth_locks[key]

    async def _authorized(self, conn: Connection, entry: DeviceEntry) -> bool:
        """True when the device needs no password or this connection supplied the right one."""
        stored = self.passwords.hash_for(self._key(entry))
        if stored is None:
            return True
        source = limiter_key(conn.peer_ip)
        device_key_name = f"device:{self._key(entry)}"
        supplied = conn.passwords.get(entry.info.device_id, "")
        self._prune_auth_locks()
        source_lock = self._acquire_auth_lock(source)
        device_lock = self._acquire_auth_lock(device_key_name)
        try:
            async with source_lock, device_lock:  # parallel connections cannot all slip past the lockout check
                wait = self.limiter.blocked(source)
                if wait > 0:
                    log.warning("%s is locked out for another %.0f s after wrong passwords", conn.peer_ip, wait)
                    return False
                loop = asyncio.get_running_loop()
                if await loop.run_in_executor(None, verify_supplied, supplied, stored):
                    return True
                if supplied:  # a client that has not sent a password yet is asked for one, not punished
                    self.limiter.record_failure(source)
                    log.warning("wrong password for device %d from %s", entry.info.device_id, conn.peer_ip)
                return False
        finally:
            self._release_auth_lock(source)
            self._release_auth_lock(device_key_name)

    async def _h_set_nickname(self, conn: Connection, msg: Message) -> None:
        req = proto.parse_set_nickname(msg.payload)
        entry = self.devices.get(req.device_id) or self._find_by_serial(req)
        if entry is None:
            log.info("connection %d: nickname for unknown device %d ignored", conn.conn_id, req.device_id)
            return
        if not self.allow_rename or not await self._authorized(conn, entry):
            conn.send_nowait(Message(proto.S_TEXT, proto.INSUFFICIENT_PERMISSIONS))
            return
        self.nicknames.set(self._key(entry), req.nickname)
        log.info("device %d nickname set to %r", entry.info.device_id, self.nicknames.get(self._key(entry)))
        self._broadcast(self._record_msg(entry))

    def _find_by_serial(self, req: proto.NicknameRequest) -> DeviceEntry | None:
        if not req.serial:
            return None
        return next((e for e in self.devices.values()
                     if (e.info.vid, e.info.pid, e.info.serial) == (req.vid, req.pid, req.serial)), None)

    # ---- bind / unbind --------------------------------------------------------------------------------------
    async def _h_bind(self, conn: Connection, msg: Message) -> None:
        entry = self.devices.get(msg.device)
        if entry is None:
            conn.send_nowait(msg.reply(proto.S_BIND_DONE, self._bind_payload(None, proto.BIND_ERROR)))
            return
        if not await self._authorized(conn, entry):
            conn.send_nowait(msg.reply(proto.S_BIND_DONE, self._bind_payload(None, proto.BIND_PASSWORD_REQUIRED)))
            return
        status = await self._bind(conn, entry)
        conn.send_nowait(msg.reply(proto.S_BIND_DONE, self._bind_payload(entry, status)))
        if status == proto.BIND_OK:
            self._broadcast(self._record_msg(entry))

    async def _bind(self, conn: Connection, entry: DeviceEntry) -> int:
        async with entry.lock:
            if conn.closed or entry.removed or self.devices.get(entry.info.device_id) is not entry:
                return proto.BIND_ERROR
            if entry.owner is conn and entry.handle is not None:
                return proto.BIND_OK  # idempotent re-bind
            if entry.owner is not None:
                return proto.BIND_ERROR
            loop = asyncio.get_running_loop()
            future = self._ctl.submit(self.backend.open, entry.info.device_id)
            try:
                handle = await asyncio.wait_for(asyncio.wrap_future(future), BIND_TIMEOUT_S)
            except asyncio.TimeoutError:
                log.error("opening device %d took more than %d s, giving up; thread stacks:\n%s",
                          entry.info.device_id, BIND_TIMEOUT_S, format_thread_stacks())
                future.add_done_callback(self._close_late_handle)
                self._after_hung_open(entry)
                return proto.BIND_ERROR
            except OSError as exc:
                log.error("cannot open device %d: %s", entry.info.device_id, exc)
                return proto.BIND_ERROR
            if conn.closed or entry.removed:  # the client left or the device vanished while it was being opened
                await loop.run_in_executor(self._ctl, handle.close)
                return proto.BIND_ERROR
            entry.owner, entry.handle = conn, handle
            entry.stats = SessionStats()
        log.info("device %d [%04x:%04x] BOUND to connection %d", entry.info.device_id, entry.info.vid,
                 entry.info.pid, conn.conn_id)
        return proto.BIND_OK

    def _after_hung_open(self, entry: DeviceEntry) -> None:
        """A native call stuck inside the OS cannot be cancelled and keeps the USB enumeration lock, so every later
        open would hang too. Log what the OS says about the device, then restart: the service manager starts a fresh
        process, which also hands devices left on WinUSB back to Windows."""
        try:
            log.error("device state according to the OS:%s%s", chr(10), self.backend.diagnose(entry.info.device_id))
        except Exception:  # noqa: BLE001 - diagnosis is best effort
            log.exception("diagnosis failed")
        if not self.restart_on_hang or self._loop is None:
            return
        log.error("restarting in %.0f s to recover from the hung driver operation", RESTART_DELAY_S)
        self._loop.call_later(RESTART_DELAY_S, self._restart_now)

    def _restart_now(self) -> None:
        logging.shutdown()
        self._exit_fn(RESTART_EXIT_STATUS)

    @staticmethod
    def _close_late_handle(future) -> None:
        """An open that finished after its request was abandoned: free the device instead of leaking it."""
        try:
            handle = future.result()
        except BaseException:  # noqa: BLE001 - it failed after all, nothing to free
            return
        try:
            handle.close()
        except Exception:  # noqa: BLE001
            log.exception("closing a late handle failed")

    def _bind_payload(self, entry: DeviceEntry | None, status: int) -> bytes:
        if entry is None:
            return proto.build_bind_reply(status, 0, b"", "", "", self.serial)
        info = entry.info
        return proto.build_bind_reply(status, info.speed, info.descriptors, info.product, info.serial, self.serial)

    async def _h_unbind(self, conn: Connection, msg: Message) -> None:
        entry = self.devices.get(msg.device)
        owned = entry is not None and entry.owner is conn
        if owned:
            await self._safe_release(entry)
        conn.send_nowait(msg.reply(proto.S_UNBIND_DONE, struct.pack("<I", 1)))
        if owned and not entry.removed:
            self._broadcast(self._record_msg(entry))

    async def _safe_release(self, entry: DeviceEntry) -> None:
        try:
            await self._release(entry)
        except Exception:  # noqa: BLE001 - keep releasing the remaining devices
            log.exception("releasing device %d failed", entry.info.device_id)

    async def _release(self, entry: DeviceEntry) -> None:
        async with entry.lock:
            for worker in entry.workers:
                worker.cancel()
            entry.workers.clear()
            entry.queues.clear()
            handle = entry.handle
            if handle is not None:
                # the handle waits for transfers in flight before it frees the device
                await asyncio.get_running_loop().run_in_executor(self._ctl, handle.close)
            entry.handle, entry.owner = None, None
        if entry.stats is not None and entry.stats.summary():
            log.info("device %d %s", entry.info.device_id, entry.stats.summary())
        entry.stats = None
        log.info("device %d UNBOUND", entry.info.device_id)

    # ---- URBs -----------------------------------------------------------------------------------------------
    def _queue_for(self, entry: DeviceEntry, key: int) -> asyncio.Queue:
        q = entry.queues.get(key)
        if q is None:
            q = entry.queues[key] = asyncio.Queue(maxsize=URB_QUEUE_LIMIT)
            entry.workers.append(asyncio.create_task(self._urb_worker(q)))
        return q

    async def _urb_worker(self, q: asyncio.Queue) -> None:
        while True:
            job = await q.get()
            try:
                await job()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - one bad URB must not kill the endpoint worker
                log.exception("URB failed")

    def _bound(self, conn: Connection, msg: Message) -> DeviceEntry | None:
        entry = self.devices.get(msg.device)
        return entry if entry and entry.owner is conn and entry.handle is not None else None

    @staticmethod
    def _timeout_ms(msg: Message) -> int:
        if msg.timeout == 0:
            return UNLIMITED_URB_TIMEOUT_MS
        return min(msg.timeout, MAX_URB_TIMEOUT_MS)

    def _submit(self, conn: Connection, entry: DeviceEntry, key: int, msg: Message, reply_type: int, call: Call,
                make_reply: Callable[[int, bytes], bytes], *, control: bool = False, inbound: bool = True) -> None:
        """Queue a blocking USB call on its endpoint queue; always answers the request (success or error)."""
        loop = asyncio.get_running_loop()
        queued = time.monotonic()

        async def job() -> None:
            handle = entry.handle
            began = time.monotonic()
            try:
                if handle is None:
                    status, data = proto.ENODEV, b""
                else:
                    status, data = await loop.run_in_executor(self._io, call, handle)
            except Exception:  # noqa: BLE001
                log.exception("USB transfer raised")
                status, data = proto.EIO, b""
            if entry.stats is not None:
                entry.stats.record(control=control, inbound=inbound, nbytes=status, service_s=time.monotonic() - began,
                                   wait_s=began - queued)
            conn.send_nowait(msg.reply(reply_type, make_reply(status, data)))

        try:
            self._queue_for(entry, key).put_nowait(job)
        except asyncio.QueueFull:
            conn.send_nowait(msg.reply(reply_type, make_reply(EBUSY, b"")))

    async def _h_control(self, conn: Connection, msg: Message) -> None:
        req = proto.parse_control(msg.payload)
        entry = self._bound(conn, msg)
        if entry is None:
            conn.send_nowait(msg.reply(proto.S_CONTROL_DONE, proto.build_control_reply(req, proto.ENODEV, b"")))
            return
        timeout = self._timeout_ms(msg)
        self._submit(conn, entry, -1, msg, proto.S_CONTROL_DONE, lambda h: h.control(req.setup, req.data, timeout),
                     lambda status, data: proto.build_control_reply(req, status, data),
                     control=True, inbound=bool(req.setup[0] & 0x80))

    async def _h_bulk(self, conn: Connection, msg: Message) -> None:
        req = proto.parse_bulk(msg.payload)
        entry = self._bound(conn, msg)
        if entry is None:
            conn.send_nowait(msg.reply(proto.S_BULK_DONE, proto.build_bulk_reply(req, proto.ENODEV, b"")))
            return
        timeout = self._timeout_ms(msg)
        self._submit(conn, entry, req.endpoint, msg, proto.S_BULK_DONE,
                     lambda h: h.bulk(req.endpoint, req.length, req.data, timeout),
                     lambda status, data: proto.build_bulk_reply(req, status, data), inbound=bool(req.endpoint & 0x80))

    async def _h_status(self, conn: Connection, msg: Message) -> None:
        reply_type = proto.STATUS_REPLY_TYPES[msg.mtype]
        entry = self._bound(conn, msg)
        if entry is None:
            conn.send_nowait(msg.reply(reply_type, proto.build_status_reply(proto.ENODEV)))
            return
        if msg.mtype == proto.C_RESET_DEVICE:
            call: Call = lambda h: (h.reset(), b"")
        elif msg.mtype in proto.CLEAR_HALT_TYPES and len(msg.payload) >= 4:
            ep = struct.unpack_from("<I", msg.payload, 0)[0] & 0xFF
            call = lambda h: (h.clear_halt(ep), b"")
        else:
            log.debug("status request type %d acknowledged without action", msg.mtype)
            conn.send_nowait(msg.reply(reply_type, proto.build_status_reply(0)))
            return
        self._submit(conn, entry, -1, msg, reply_type, call, lambda status, data: proto.build_status_reply(status))


def default_iface_name() -> str:
    import os
    return "eth0" if os.name != "nt" else "Ethernet"
