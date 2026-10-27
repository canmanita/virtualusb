from pathlib import Path

import pytest

from vhserver import doctor
from vhserver.config import ServerConfig
from vhserver.security import new_password_hash
from vhserver.tlsconfig import CertificateInfo

HASH = new_password_hash("a long password")


def info(days):
    return lambda path: CertificateInfo("CN=Hub", ("hub",), days, False)


@pytest.fixture(autouse=True)
def english(monkeypatch):
    monkeypatch.setenv("VHSERVER_LANG", "en")


def by_key(checks):
    return {c.key: c for c in checks}


def test_open_server_without_password_has_nothing_to_warn_about():
    checks = by_key(doctor.security_checks(ServerConfig()))
    assert checks["tls"].status == "ok" and checks["password"].status == "ok"


def test_password_without_ssl_is_a_warning_with_the_fix():
    checks = by_key(doctor.security_checks(ServerConfig(password_hash=HASH)))
    assert checks["tls"].status == "warn" and "vhserver tls enable" in checks["tls"].fix
    assert "set" in checks["password"].title.lower()


def test_ssl_with_a_valid_certificate(tmp_path):
    cert = tmp_path / "server.pem"
    cert.write_text("x")
    config = ServerConfig(ssl_cert=str(cert), ssl_key=str(cert), ssl_ca=str(cert))
    check = by_key(doctor.security_checks(config, certificate_info=info(900)))["tls"]
    assert check.status == "ok" and "900" in check.title


@pytest.mark.parametrize("days,status", [(10, "warn"), (0, "warn"), (-1, "fail"), (-5, "fail")])
def test_expiring_or_expired_certificates(tmp_path, days, status):
    cert = tmp_path / "server.pem"
    cert.write_text("x")
    config = ServerConfig(ssl_cert=str(cert), ssl_key=str(cert))
    assert by_key(doctor.security_checks(config, certificate_info=info(days)))["tls"].status == status


def test_missing_certificate_file_is_a_failure(tmp_path):
    config = ServerConfig(ssl_cert=str(tmp_path / "gone.pem"), ssl_key=str(tmp_path / "gone.key"))
    check = by_key(doctor.security_checks(config, certificate_info=info(900)))["tls"]
    assert check.status == "fail" and "gone.pem" in check.fix


def test_unreadable_certificate_is_a_warning_not_a_crash(tmp_path):
    cert = tmp_path / "server.pem"
    cert.write_text("x")
    config = ServerConfig(ssl_cert=str(cert), ssl_key=str(cert))
    assert by_key(doctor.security_checks(config, certificate_info=lambda p: None))["tls"].status == "warn"


def test_config_less_probe_skips_security_checks():
    assert doctor.security_checks(None) == []
