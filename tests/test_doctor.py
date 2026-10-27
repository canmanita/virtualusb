from types import SimpleNamespace

from vhserver import doctor
from vhserver.config import ServerConfig

EXE = r"C:\Program Files\VHServer\vhserver.exe"


class Probe:
    """Everything the checks ask the machine, with healthy defaults."""
    exe = EXE
    config = ServerConfig(port=7575)
    config_error = None
    pending: list = []
    admin = True
    libusb_ok = True
    listening = True
    task_installed = True
    rules_present = True
    block_rules: list = []
    public_networks: list = []
    announce = "192.168.0.182"

    def is_admin(self): return self.admin
    def libusb(self): return self.libusb_ok
    def port_open(self, port): return self.listening
    def task_exists(self): return self.task_installed
    def rules_exist(self): return self.rules_present
    def blocking_rules(self): return self.block_rules
    def public_lan(self): return self.public_networks
    def pending_devices(self): return self.pending
    def announce_address(self): return self.announce


def statuses(probe):
    return {check.key: check.status for check in doctor.run_checks(probe)}


def test_healthy_machine_has_no_problems():
    result = statuses(Probe())
    assert set(result.values()) == {"ok"}


def test_each_problem_is_reported_with_a_fix(monkeypatch):
    monkeypatch.setenv("VHSERVER_LANG", "en")
    probe = Probe()
    probe.admin, probe.listening, probe.rules_present = False, False, False
    probe.block_rules, probe.public_networks = ["Python"], ["Ethernet 2"]
    probe.pending, probe.announce = ["USB\\VID_0930&PID_6544\\AAA"], None
    checks = {c.key: c for c in doctor.run_checks(probe)}
    assert checks["admin"].status == "fail"
    assert checks["port"].status == "fail" and "schtasks /Run" in checks["port"].fix
    assert checks["rules"].status == "fail"
    assert checks["block"].status == "fail" and "Python" in checks["block"].fix
    assert checks["profile"].status == "warn" and 'Set-NetConnectionProfile -InterfaceAlias "Ethernet 2"' in checks["profile"].fix
    assert checks["pending"].status == "warn"
    assert checks["mdns"].status == "warn"


def test_invalid_config_is_a_failure():
    probe = Probe()
    probe.config, probe.config_error = None, "unknown setting(s)"
    assert statuses(probe)["config"] == "fail"


def test_missing_task_and_libusb_are_failures():
    probe = Probe()
    probe.task_installed, probe.libusb_ok = False, False
    result = statuses(probe)
    assert result["task"] == "fail" and result["libusb"] == "fail"


def test_report_text_lists_problems_and_returns_exit_code(monkeypatch):
    monkeypatch.setenv("VHSERVER_LANG", "it")
    probe = Probe()
    probe.listening = False
    lines, code = doctor.report(doctor.run_checks(probe))
    assert code == 1 and any(line.startswith("[FAIL]") for line in lines) and any(line.startswith("[ OK ]") for line in lines)
    lines, code = doctor.report(doctor.run_checks(Probe()))
    assert code == 0


def test_blocking_rule_names_are_parsed_from_powershell_output():
    out = SimpleNamespace(returncode=0, stdout="Python\r\nPython\r\n\r\nOther\r\n")
    assert doctor.parse_names(out) == ["Python", "Other"]
    assert doctor.parse_names(SimpleNamespace(returncode=1, stdout="x")) == []


def test_public_lan_parser_ignores_other_profiles():
    payload = '[{"InterfaceAlias":"Ethernet 2","NetworkCategory":0},{"InterfaceAlias":"Tailscale","NetworkCategory":1}]'
    assert doctor.parse_public(SimpleNamespace(returncode=0, stdout=payload)) == ["Ethernet 2"]
    single = '{"InterfaceAlias":"Wi-Fi","NetworkCategory":0}'
    assert doctor.parse_public(SimpleNamespace(returncode=0, stdout=single)) == ["Wi-Fi"]
    assert doctor.parse_public(SimpleNamespace(returncode=0, stdout="not json")) == []
