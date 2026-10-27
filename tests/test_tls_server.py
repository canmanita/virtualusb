"""The TLS port: same protocol over an encrypted connection, optional client certificates, plaintext can be off."""
import asyncio
import ssl
import struct

import pytest

from vhserver import protocol as proto
from vhserver import tlsconfig
from vhserver.fakedisk import FakeDiskBackend
from vhserver.server import VhServer
from vhserver.wire import FrameDecoder, Message

HELLO = b" (tester)".ljust(64, b"\0") + b"TESTPC".ljust(64, b"\0") + bytes([6, 0, 3, 0])


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    directory = tmp_path_factory.mktemp("pki")
    files = tlsconfig.generate_certificates(directory, common_name="Test", hostnames=["localhost"], addresses=["127.0.0.1"])
    client = tlsconfig.generate_client_certificate(files, directory, common_name="laptop")
    return files, client


def client_ctx(files, client=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.load_verify_locations(str(files.ca_cert))
    if client:
        ctx.load_cert_chain(str(client[0]), str(client[1]))
    return ctx


async def talk(port, ctx):
    reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=ctx)
    writer.write(Message(proto.C_HELLO, HELLO).encode())
    await writer.drain()
    decoder = FrameDecoder()
    while True:
        data = await asyncio.wait_for(reader.read(65536), 5)
        if not data:
            return None
        for msg in decoder.feed(data):
            if msg.mtype == proto.S_SERVER_INFO:
                writer.close()
                return msg


async def start(**kwargs):
    server = VhServer(FakeDiskBackend(device_id=7, megabytes=1), name="TLS Hub", port=0, ssl_port=0, **kwargs)
    server._loop = asyncio.get_running_loop()
    listeners = await server.start_listeners()
    ports = [l.sockets[0].getsockname()[1] for l in listeners]
    return server, listeners, ports


async def stop(listeners):
    for listener in listeners:
        listener.close()
        await listener.wait_closed()


def test_hello_works_over_tls_and_plain_side_by_side(pki):
    files, _ = pki

    async def scenario():
        ctx = tlsconfig.build_context(files.server_cert, files.server_key)
        server, listeners, (plain, tls) = await start(ssl_context=ctx)
        try:
            return await talk(tls, client_ctx(files)), await talk_plain(plain)
        finally:
            await stop(listeners)

    over_tls, over_plain = asyncio.run(scenario())
    assert over_tls.payload[1:9] == b"TLS Hub\0" and over_plain.payload[1:9] == b"TLS Hub\0"


async def talk_plain(port):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(Message(proto.C_HELLO, HELLO).encode())
    await writer.drain()
    decoder = FrameDecoder()
    while True:
        data = await asyncio.wait_for(reader.read(65536), 5)
        for msg in decoder.feed(data):
            if msg.mtype == proto.S_SERVER_INFO:
                writer.close()
                return msg


def test_plain_port_can_be_switched_off(pki):
    files, _ = pki

    async def scenario():
        ctx = tlsconfig.build_context(files.server_cert, files.server_key)
        server, listeners, ports = await start(ssl_context=ctx, allow_plaintext=False)
        try:
            return len(ports), await talk(ports[0], client_ctx(files))
        finally:
            await stop(listeners)

    count, reply = asyncio.run(scenario())
    assert count == 1 and reply is not None


def test_tls_only_without_a_certificate_is_rejected():
    with pytest.raises(ValueError):
        VhServer(FakeDiskBackend(device_id=7, megabytes=1), allow_plaintext=False)


def test_client_certificate_policy_is_enforced(pki):
    files, client = pki

    async def scenario():
        ctx = tlsconfig.build_context(files.server_cert, files.server_key, ca=files.ca_cert, require_client_cert=True)
        server, listeners, (plain, tls) = await start(ssl_context=ctx)
        try:
            accepted = await talk(tls, client_ctx(files, client))
            try:
                rejected = await talk(tls, client_ctx(files))
            except (ssl.SSLError, ConnectionError, OSError, asyncio.TimeoutError):
                rejected = None
            return accepted, rejected
        finally:
            await stop(listeners)

    accepted, rejected = asyncio.run(scenario())
    assert accepted is not None and rejected is None


def test_plain_text_to_the_tls_port_does_not_crash_the_server(pki):
    files, _ = pki

    async def scenario():
        ctx = tlsconfig.build_context(files.server_cert, files.server_key)
        server, listeners, (plain, tls) = await start(ssl_context=ctx)
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", tls)
            writer.write(b"\x00" * 64)
            await writer.drain()
            await asyncio.wait_for(reader.read(100), 5)
            writer.close()
            return await talk(tls, client_ctx(files))  # still serving afterwards
        finally:
            await stop(listeners)

    assert asyncio.run(scenario()) is not None
