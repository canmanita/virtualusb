import os

from vhserver import doctor
from vhserver.config import ServerConfig
from vhserver.paths import config_path


class Probe:
    config = ServerConfig(port=7575)
    config_error = None
    service = True
    libusb_ok = True
    rules = True
    listening = True
    firewall = None          # None | "ufw" | "firewalld"
    firewall_rule = None     # True / False / None (unknown)
    announce = "192.168.1.20"

    def libusb(self): return self.libusb_ok
    def service_active(self): return self.service
    def usb_rules_installed(self): return self.rules
    def port_open(self, port): return self.listening
    def firewall_active(self): return self.firewall
    def firewall_allows(self, port): return self.firewall_rule
    def announce_address(self): return self.announce


def result(probe):
    return {c.key: c for c in doctor.run_linux_checks(probe)}


def test_healthy_linux_host():
    assert {c.status for c in doctor.run_linux_checks(Probe())} == {"ok"}


def test_each_linux_problem_has_a_fix(monkeypatch):
    monkeypatch.setenv("VHSERVER_LANG", "en")
    probe = Probe()
    probe.service, probe.rules, probe.listening, probe.libusb_ok, probe.announce = False, False, False, False, None
    checks = result(probe)
    assert checks["service"].status == "fail" and "systemctl enable --now vhserver" in checks["service"].fix
    assert checks["usb"].status == "fail" and "udev" in checks["usb"].fix
    assert checks["port"].status == "fail" and checks["libusb"].status == "fail"
    assert checks["mdns"].status == "warn"


def test_active_firewall_without_a_known_rule_is_a_warning(monkeypatch):
    monkeypatch.setenv("VHSERVER_LANG", "en")
    probe = Probe()
    probe.firewall = "ufw"
    check = result(probe)["firewall"]
    assert check.status == "warn" and "ufw allow" in check.fix and "7575" in check.fix
    probe.firewall_rule = True
    assert result(probe)["firewall"].status == "ok"
    probe.firewall, probe.firewall_rule = "firewalld", None
    assert "firewall-cmd" in result(probe)["firewall"].fix


def test_config_path_prefers_the_system_directory_when_it_exists(monkeypatch, tmp_path):
    monkeypatch.delenv("VHSERVER_HOME", raising=False)
    monkeypatch.setattr("vhserver.paths.SYSTEM_DIR", tmp_path / "etc-vhserver")
    assert config_path().parent != tmp_path / "etc-vhserver"
    (tmp_path / "etc-vhserver").mkdir()
    if os.name != "nt":
        assert config_path() == tmp_path / "etc-vhserver" / "config.json"
