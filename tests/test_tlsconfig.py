import asyncio
import ssl

import pytest

from vhserver import tlsconfig


@pytest.fixture(scope="module")
def files(tmp_path_factory):
    directory = tmp_path_factory.mktemp("tls")
    return tlsconfig.generate_certificates(directory, common_name="Test Hub", hostnames=["testhub"],
                                           addresses=["192.168.0.10"])


def test_generation_creates_the_expected_files(files):
    for path in (files.ca_cert, files.ca_key, files.server_cert, files.server_key):
        assert path.is_file() and path.stat().st_size > 100
    assert files.ca_cert.read_text().startswith("-----BEGIN CERTIFICATE-----")
    assert "PRIVATE KEY" in files.server_key.read_text()


def test_existing_certificates_are_kept_unless_forced(tmp_path):
    first = tlsconfig.generate_certificates(tmp_path, common_name="Hub", hostnames=[], addresses=[])
    before = first.server_cert.read_bytes()
    again = tlsconfig.generate_certificates(tmp_path, common_name="Other", hostnames=[], addresses=[])
    assert again.server_cert.read_bytes() == before
    forced = tlsconfig.generate_certificates(tmp_path, common_name="Other", hostnames=[], addresses=[], force=True)
    assert forced.server_cert.read_bytes() != before


def test_certificate_details(files):
    info = tlsconfig.certificate_info(files.server_cert)
    assert info.days_left > 365 and "Test Hub" in info.subject and "192.168.0.10" in info.names
    assert tlsconfig.certificate_info(files.ca_cert).is_ca


def test_unreadable_certificate_info_is_none(tmp_path):
    assert tlsconfig.certificate_info(tmp_path / "missing.pem") is None
    bad = tmp_path / "bad.pem"
    bad.write_text("not a certificate")
    assert tlsconfig.certificate_info(bad) is None


async def _handshake(server_ctx, client_ctx):
    async def handle(reader, writer):
        writer.write(b"hello")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=server_ctx)
    port = server.sockets[0].getsockname()[1]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=client_ctx, server_hostname=None)
        data = await reader.read(5)
        writer.close()
        return data
    finally:
        server.close()
        await server.wait_closed()


def client_context(ca=None, cert=None, key=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False  # the stock client does not check the host name either
    if ca:
        ctx.load_verify_locations(str(ca))
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.verify_mode = ssl.CERT_NONE
    if cert:
        ctx.load_cert_chain(str(cert), str(key))
    return ctx


def test_client_trusting_the_generated_ca_connects(files):
    server_ctx = tlsconfig.build_context(files.server_cert, files.server_key)
    assert asyncio.run(_handshake(server_ctx, client_context(ca=files.ca_cert))) == b"hello"


def test_client_with_another_ca_is_refused(files, tmp_path):
    other = tlsconfig.generate_certificates(tmp_path, common_name="Other CA", hostnames=[], addresses=[])
    server_ctx = tlsconfig.build_context(files.server_cert, files.server_key)
    with pytest.raises(ssl.SSLError):
        asyncio.run(_handshake(server_ctx, client_context(ca=other.ca_cert)))


def test_client_certificates_can_be_required(files, tmp_path):
    server_ctx = tlsconfig.build_context(files.server_cert, files.server_key, ca=files.ca_cert,
                                         require_client_cert=True)
    try:  # TLS 1.3 reports the missing client certificate on the first read, older versions during the handshake
        refused = asyncio.run(_handshake(server_ctx, client_context(ca=files.ca_cert))) != b"hello"
    except (ssl.SSLError, ConnectionError, OSError):
        refused = True
    assert refused  # no client certificate presented
    client = tlsconfig.generate_client_certificate(files, tmp_path, common_name="laptop")
    assert asyncio.run(_handshake(server_ctx, client_context(ca=files.ca_cert, cert=client[0], key=client[1]))) == b"hello"


def test_modern_protocol_versions_only(files):
    ctx = tlsconfig.build_context(files.server_cert, files.server_key)
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_bad_inputs_give_a_clear_error(tmp_path, files):
    with pytest.raises(tlsconfig.TlsError):
        tlsconfig.build_context(tmp_path / "nope.pem", tmp_path / "nope.key")
    with pytest.raises(tlsconfig.TlsError):
        tlsconfig.build_context(files.server_cert, files.server_key, require_client_cert=True)  # no CA to verify with
