"""Regression tests for the problems found by the code and security reviews of the password/SSL/nickname work."""
import asyncio
import os
import time
from dataclasses import replace

import pytest

from test_access_control import Session, bind, run, set_password
from vhserver import admincli, discovery, doctor, tlsconfig, winsetup
from vhserver import protocol as proto
from vhserver import server as server_module
from vhserver.config import load_config, update_config
from vhserver.security import FailureLimiter, PasswordPolicy, new_password_hash
from vhserver.wire import Message


def trusted_folder_answer(args):
    """What PowerShell prints for the two folder checks of ``secure_data_dir`` when administrators own everything."""
    joined = " ".join(args)
    return "OK" if "TREECHECK" in joined else winsetup.ADMINS_SID if "Get-Acl" in joined else ""


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("VHSERVER_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("VHSERVER_LANG", "en")
    return tmp_path / "home"


def test_parallel_wrong_guesses_cannot_all_slip_past_the_lockout():
    async def scenario():
        limiter = FailureLimiter(max_failures=3, window_s=60, lockout_s=60)
        async with Session(passwords=PasswordPolicy(new_password_hash("pw")), limiter=limiter) as s:
            clients = [await s.client() for _ in range(6)]
            for client in clients:
                await set_password(client, "wrong")
            results = await asyncio.gather(*(bind(c) for c in clients))
            return results, limiter.blocked("127.0.0.1")

    results, blocked = run(scenario())
    assert set(results) == {proto.BIND_PASSWORD_REQUIRED} and blocked > 0


def test_a_correct_bind_does_not_erase_earlier_wrong_guesses():
    async def scenario():
        limiter = FailureLimiter(max_failures=3, window_s=60, lockout_s=60)
        async with Session(passwords=PasswordPolicy(new_password_hash("right")), limiter=limiter) as s:
            client = await s.client()
            await set_password(client, "wrong")
            for _ in range(2):
                await bind(client)
            await set_password(client, "right")
            assert await bind(client) == proto.BIND_OK
            await client.send(Message(proto.C_UNBIND, device=7))
            await client.expect(proto.S_UNBIND_DONE)
            await set_password(client, "wrong")
            await bind(client)  # third wrong guess inside the window; the success in between must not reset it
            return limiter.blocked("127.0.0.1")

    assert run(scenario()) > 0


def test_one_address_cannot_use_up_every_connection_slot(monkeypatch):
    monkeypatch.setattr(server_module, "MAX_CONNECTIONS_PER_IP", 3)

    async def scenario():
        async with Session() as s:
            kept = [await s.client() for _ in range(3)]
            reader, writer = await asyncio.open_connection("127.0.0.1", s.port)
            data = await asyncio.wait_for(reader.read(10), 3)
            writer.close()
            return data, len(kept)

    data, _ = run(scenario())
    assert data == b""  # the fourth connection was refused


def test_silent_connections_are_dropped_after_the_hello_timeout(monkeypatch):
    monkeypatch.setattr(server_module, "HELLO_TIMEOUT_S", 0.2)
    monkeypatch.setattr(server_module, "PING_INTERVAL_S", 0.1)

    async def scenario():
        async with Session() as s:
            reader, writer = await asyncio.open_connection("127.0.0.1", s.port)
            data = b"x"
            deadline = time.monotonic() + 3
            while data and time.monotonic() < deadline:
                data = await asyncio.wait_for(reader.read(65536), 3)  # pings arrive, then EOF
            writer.close()
            return data

    assert run(scenario()) == b""


def test_stored_passwords_per_connection_are_capped(monkeypatch):
    monkeypatch.setattr(server_module, "MAX_STORED_PASSWORDS", 5)

    async def scenario():
        async with Session() as s:
            client = await s.client()
            for device in range(50):
                await set_password(client, "x", device=1000 + device)
            return len(next(iter(s.server.connections.values())).passwords)

    assert run(scenario()) == 5


def test_tls_enable_keeps_an_earlier_only_setting(home):
    admincli.main(["tls", "enable", "--only"])
    admincli.main(["tls", "enable"])  # e.g. renewing: must not reopen the plain port
    assert load_config(home / "config.json").allow_plaintext is False
    admincli.main(["tls", "enable", "--with-plain"])
    assert load_config(home / "config.json").allow_plaintext is True


def test_permission_errors_are_reported_as_such(home, monkeypatch, capsys):
    def deny(*args, **kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr("vhserver.config.Path.write_text", deny)
    answers = iter(["correct horse", "correct horse"])
    code = admincli.main(["password"], prompt=lambda message: next(answers))
    assert code == 1 and "administrator" in capsys.readouterr().out.lower()


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_rewriting_the_config_keeps_its_mode(tmp_path):
    path = tmp_path / "config.json"
    path.write_text("{}", encoding="utf-8")
    path.chmod(0o640)
    update_config(path, {"name": "Lab"})
    assert path.stat().st_mode & 0o777 == 0o640


def test_client_certificate_names_are_restricted(home):
    admincli.main(["tls", "enable"])
    assert admincli.main(["tls", "client", "../evil"]) == 1
    assert not (home / "evil.pem").exists() and not (home / "tls" / "evil.pem").exists()


def test_partial_certificate_folder_is_never_silently_replaced(tmp_path):
    files = tlsconfig.generate_certificates(tmp_path, common_name="Hub", hostnames=[], addresses=[])
    files.ca_key.unlink()
    with pytest.raises(tlsconfig.TlsError):
        tlsconfig.generate_certificates(tmp_path, common_name="Hub", hostnames=[], addresses=[])
    with pytest.raises(tlsconfig.TlsError):
        tlsconfig.generate_client_certificate(files, tmp_path / "c", common_name="laptop")


def test_long_names_and_bad_addresses_do_not_crash_certificate_creation(tmp_path):
    files = tlsconfig.generate_certificates(tmp_path / "a", common_name="N" * 64, hostnames=[], addresses=[])
    assert files.server_cert.exists()
    with pytest.raises(tlsconfig.TlsError):
        tlsconfig.generate_certificates(tmp_path / "b", common_name="Hub", hostnames=[], addresses=["not-an-ip"])


def test_a_certificate_with_hours_left_is_not_expired(tmp_path):
    info = tlsconfig.CertificateInfo("CN=x", (), 0, False)
    cert = tmp_path / "c.pem"
    cert.write_text("x")
    config = replace(load_config(tmp_path / "none"), ssl_cert=str(cert), ssl_key=str(cert))
    checks = {c.key: c for c in doctor.security_checks(config, certificate_info=lambda path: info)}
    assert checks["tls"].status == "warn"


def test_first_announcement_failure_does_not_stop_the_watcher():
    class Boom:
        calls = 0

        def __init__(self, **kwargs):
            Boom.calls += 1

        async def async_register_service(self, info, allow_name_change=False, strict=True):
            if Boom.calls == 1:
                raise OSError("interface vanished")

        async def async_unregister_service(self, info):
            pass

        async def async_close(self):
            pass

    async def scenario():
        d = discovery.Discovery("S", 7575, address_provider=lambda: ["10.0.0.7"], zeroconf_factory=Boom, interval=0.01)
        await d.start()
        await asyncio.sleep(0.15)
        running = d._watcher is not None and d._addresses == ["10.0.0.7"]
        await d.stop()
        return running

    assert asyncio.run(scenario()) is True


def test_the_task_is_stopped_before_it_is_started_again(tmp_path):
    calls = []

    def runner(args):
        calls.append(" ".join(args))
        return type("R", (), {"returncode": 0, "stdout": trusted_folder_answer(args)})()

    winsetup.install("C:/x/vhserver.exe", tmp_path, name="Lab", port=7575, allow_public=False, runner=runner,
                     is_admin=lambda: True, port_check=lambda port, host=None: True)
    assert calls.index("schtasks /End /TN VHServer") < calls.index("schtasks /Run /TN VHServer")


def test_port_conflict_is_only_an_error_when_ssl_is_configured(tmp_path):
    path = tmp_path / "c.json"
    path.write_text('{"port": 7574}', encoding="utf-8")
    assert load_config(path).port == 7574


def test_tls_only_server_has_no_plain_port_rule_and_is_probed_on_the_ssl_port(tmp_path):
    rules = winsetup.firewall_rules("C:/x/vhserver.exe", 7575, False, ssl_port=7574, plain=False)
    assert [(r.label, r.port) for r in rules] == [("mDNS UDP", 5353), ("TCP SSL", 7574)]
    config = replace(load_config(tmp_path / "none"), ssl_cert="c", ssl_key="k", allow_plaintext=False)
    assert doctor.serving_port(config) == 7574 and doctor.serving_port(load_config(tmp_path / "none")) == 7575
    assert doctor.serving_port(None) == 7575


def test_install_checks_the_ssl_port_when_plain_connections_are_off(tmp_path):
    (tmp_path / "config.json").write_text(
        '{"ssl_cert": "c.pem", "ssl_key": "k.pem", "allow_plaintext": false}', encoding="utf-8")
    checked, calls = [], []

    def runner(args):
        calls.append(" ".join(args))
        return type("R", (), {"returncode": 0, "stdout": trusted_folder_answer(args)})()

    winsetup.install("C:/x/vhserver.exe", tmp_path, name="Lab", port=7575, allow_public=False, runner=runner,
                     is_admin=lambda: True, port_check=lambda port, host=None: checked.append(port) or True,
                     wait=lambda: None)
    assert checked == [7574]
    assert not any("add rule" in c and "localport=7575" in c for c in calls)
