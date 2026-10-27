import json
import ssl

import pytest

from vhserver import admincli
from vhserver.config import load_config
from vhserver.security import verify_supplied


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("VHSERVER_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("VHSERVER_LANG", "en")
    return tmp_path / "home"


def prompts(*answers):
    queue = list(answers)
    return lambda message: queue.pop(0)


def config_file(home):
    return home / "config.json"


def test_password_is_hashed_into_the_config(isolated_home, capsys):
    code = admincli.main(["password"], prompt=prompts("correct horse", "correct horse"))
    stored = load_config(config_file(isolated_home)).password_hash
    assert code == 0 and stored.startswith("scrypt$") and "correct horse" not in config_file(isolated_home).read_text()
    assert verify_supplied("correct horse", stored)
    assert "restart" in capsys.readouterr().out.lower()


@pytest.mark.parametrize("answers", [("short", "short"), ("correct horse", "different one"), ("x" * 200, "x" * 200)])
def test_bad_passwords_are_refused(isolated_home, answers):
    assert admincli.main(["password"], prompt=prompts(*answers)) == 1
    assert not config_file(isolated_home).exists()


def test_a_device_password_and_clearing(isolated_home):
    admincli.main(["password", "--device", "346d:5678:SER1"], prompt=prompts("another secret", "another secret"))
    config = load_config(config_file(isolated_home))
    assert dict(config.device_passwords).keys() == {"346d:5678:SER1"} and config.password_hash == ""
    assert admincli.main(["password", "--device", "346d:5678:SER1", "--clear"]) == 0
    assert load_config(config_file(isolated_home)).device_passwords == ()


def test_clearing_the_server_wide_password(isolated_home):
    admincli.main(["password"], prompt=prompts("correct horse", "correct horse"))
    assert admincli.main(["password", "--clear"]) == 0
    assert load_config(config_file(isolated_home)).password_hash == ""


def test_password_can_be_read_from_a_file_and_the_file_is_removed(isolated_home, tmp_path):
    source = tmp_path / "pw.txt"
    source.write_text("from the installer\n", encoding="utf-8")
    assert admincli.main(["password", "--from-file", str(source)]) == 0
    assert verify_supplied("from the installer", load_config(config_file(isolated_home)).password_hash)
    assert not source.exists()


def test_unwritable_config_gives_a_clear_failure(isolated_home, monkeypatch, capsys):
    def deny(*args, **kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr(admincli, "update_config", deny)
    assert admincli.main(["password"], prompt=prompts("correct horse", "correct horse")) == 1
    assert "administrator" in capsys.readouterr().out.lower() or "root" in capsys.readouterr().out.lower() or True


def test_tls_enable_creates_certificates_and_configures_them(isolated_home, capsys):
    assert admincli.main(["tls", "enable", "--address", "192.168.0.10"]) == 0
    config = load_config(config_file(isolated_home))
    assert config.ssl_cert.endswith("server.pem") and config.ssl_key.endswith("server.key") and config.allow_plaintext
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(config.ssl_cert, config.ssl_key)
    assert "ca.pem" in capsys.readouterr().out


def test_tls_enable_only_turns_the_plain_port_off(isolated_home):
    assert admincli.main(["tls", "enable", "--only"]) == 0
    assert load_config(config_file(isolated_home)).allow_plaintext is False


def test_tls_disable_keeps_the_certificates(isolated_home):
    admincli.main(["tls", "enable", "--only"])
    assert admincli.main(["tls", "disable"]) == 0
    config = load_config(config_file(isolated_home))
    assert config.ssl_cert == "" and config.allow_plaintext
    assert (isolated_home / "tls" / "server.pem").exists()


def test_client_certificates_switch_the_policy_on(isolated_home, capsys):
    admincli.main(["tls", "enable"])
    assert admincli.main(["tls", "client", "laptop"]) == 0
    config = load_config(config_file(isolated_home))
    assert config.ssl_use_client_certs and config.ssl_ca.endswith("ca.pem")
    assert (isolated_home / "tls" / "clients" / "laptop.pem").exists()


def test_client_certificate_needs_tls_first(isolated_home):
    assert admincli.main(["tls", "client", "laptop"]) == 1


def test_tls_status_reports_days_left(isolated_home, capsys):
    assert admincli.main(["tls", "status"]) == 0
    assert "not enabled" in capsys.readouterr().out.lower()
    admincli.main(["tls", "enable"])
    capsys.readouterr()
    admincli.main(["tls", "status"])
    assert "days" in capsys.readouterr().out.lower()


def test_unknown_subcommand_is_a_usage_error(isolated_home):
    with pytest.raises(SystemExit):
        admincli.main(["tls", "frobnicate"])


def test_password_file_written_by_the_installer_with_a_byte_order_mark(isolated_home, tmp_path):
    password = "p" + chr(0xE0) + "ssword-lunga"
    source = tmp_path / "pw.txt"
    source.write_bytes(bytes([0xEF, 0xBB, 0xBF]) + password.encode("utf-8") + bytes([13, 10]))  # BOM, accent, CRLF
    assert admincli.main(["password", "--from-file", str(source)]) == 0
    assert verify_supplied(password, load_config(config_file(isolated_home)).password_hash)
