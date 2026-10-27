import xml.etree.ElementTree as ET
from types import SimpleNamespace

import pytest

from vhserver import winsetup
from vhserver.config import ServerConfig, load_config

EXE = r"C:\Program Files\VHServer\vhserver.exe"
NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}


class FakeRunner:
    def __init__(self, fail_on=()):
        self.calls, self.fail_on = [], tuple(fail_on)

    def __call__(self, args):
        self.calls.append(list(args))
        code = 1 if any(token in " ".join(args) for token in self.fail_on) else 0
        joined = " ".join(args)
        if "TREECHECK" in joined:
            answer = "OK"  # nothing inside the folder belongs to anybody else
        else:
            answer = winsetup.ADMINS_SID if "Get-Acl" in joined else ""  # a folder an administrator owns
        return SimpleNamespace(returncode=code, stdout=answer)

    def joined(self):
        return [" ".join(call) for call in self.calls]


def test_firewall_rules_are_program_scoped_and_local_only():
    rules = winsetup.firewall_rules(EXE, 7575, allow_public=False)
    assert [r.protocol for r in rules] == ["TCP", "UDP"] and [r.port for r in rules] == [7575, 5353]
    for rule in rules:
        args = rule.add_args(EXE)
        assert f"program={EXE}" in args and "dir=in" in args and "action=allow" in args
        assert "profile=private,domain" in args
        assert "remoteip=LocalSubnet,100.64.0.0/10" in args  # never "any"


def test_public_profile_is_opt_in():
    rule = winsetup.firewall_rules(EXE, 7575, allow_public=True)[0]
    assert "profile=private,domain,public" in rule.add_args(EXE)


def test_task_xml_runs_as_system_at_boot_and_restarts_on_failure():
    root = ET.fromstring(winsetup.task_xml(EXE))
    assert root.find("t:Principals/t:Principal/t:UserId", NS).text == "S-1-5-18"
    assert root.find("t:Principals/t:Principal/t:RunLevel", NS).text == "HighestAvailable"
    assert root.find("t:Triggers/t:BootTrigger", NS) is not None
    assert root.find("t:Actions/t:Exec/t:Command", NS).text == f'"{EXE}"'
    assert root.find("t:Actions/t:Exec/t:Arguments", NS).text == "run"
    assert root.find("t:Settings/t:RestartOnFailure/t:Count", NS) is not None
    assert root.find("t:Settings/t:ExecutionTimeLimit", NS).text == "PT0S"
    assert root.find("t:Settings/t:DisallowStartIfOnBatteries", NS).text == "false"


def test_task_xml_escapes_the_path():
    root = ET.fromstring(winsetup.task_xml(r"C:\R&D <x>\vhserver.exe"))
    assert root.find("t:Actions/t:Exec/t:Command", NS).text == '"C:\\R&D <x>\\vhserver.exe"'


def test_install_creates_config_rules_task_and_starts_it(tmp_path):
    runner = FakeRunner()
    steps = winsetup.install(EXE, tmp_path, name="Lab", port=7600, allow_public=False, runner=runner,
                             is_admin=lambda: True, port_check=lambda port, host=None: True)
    assert all(step.ok for step in steps)
    config = load_config(tmp_path / "config.json")
    assert (config.name, config.port, config.windows_bind) == ("Lab", 7600, True)
    joined = runner.joined()
    assert any("delete rule name=vhserver TCP 7575" in c for c in joined)  # leftovers of manual attempts
    assert sum("add rule" in c for c in joined) == 2
    assert any(c.startswith("schtasks /Create /TN VHServer /XML") for c in joined)
    assert any(c.startswith("schtasks /Run /TN VHServer") for c in joined)


def test_install_keeps_an_existing_config(tmp_path):
    (tmp_path / "config.json").write_text('{"name": "Mine", "port": 7777}', encoding="utf-8")
    winsetup.install(EXE, tmp_path, name="Other", port=7575, allow_public=False, runner=FakeRunner(),
                     is_admin=lambda: True, port_check=lambda port, host=None: True)
    assert load_config(tmp_path / "config.json").name == "Mine"


def test_install_requires_administrator(tmp_path):
    runner = FakeRunner()
    steps = winsetup.install(EXE, tmp_path, name="Lab", port=7575, allow_public=False, runner=runner,
                             is_admin=lambda: False, port_check=lambda port, host=None: True)
    assert not steps[0].ok and runner.calls == []


def test_install_reports_a_task_that_does_not_listen(tmp_path):
    steps = winsetup.install(EXE, tmp_path, name="Lab", port=7575, allow_public=False, runner=FakeRunner(),
                             is_admin=lambda: True, port_check=lambda port, host=None: False, wait=lambda: None)
    assert not steps[-1].ok and steps[-1].name == "listening"


def test_install_reports_a_failed_firewall_rule(tmp_path):
    steps = winsetup.install(EXE, tmp_path, name="Lab", port=7575, allow_public=False,
                             runner=FakeRunner(fail_on=["add rule"]), is_admin=lambda: True,
                             port_check=lambda port, host=None: True)
    assert any(not step.ok and step.name == "firewall" for step in steps)


def test_uninstall_stops_task_recovers_drivers_and_removes_rules(tmp_path):
    runner = FakeRunner()
    recovered = []
    steps = winsetup.uninstall(tmp_path, runner=runner, is_admin=lambda: True,
                               recover=lambda: recovered.append(True) or ["USB\\VID_1&PID_2\\3"], purge=False)
    joined = runner.joined()
    assert all(step.ok for step in steps) and recovered
    assert joined.index("schtasks /End /TN VHServer") < len(joined)
    assert any(c.startswith("schtasks /Delete /TN VHServer /F") for c in joined)
    assert sum("delete rule" in c for c in joined) >= 2


def test_uninstall_purge_removes_data(tmp_path):
    data = tmp_path / "VHServer"
    data.mkdir()
    (data / "config.json").write_text("{}", encoding="utf-8")
    winsetup.uninstall(data, runner=FakeRunner(), is_admin=lambda: True, recover=lambda: [], purge=True)
    assert not data.exists()


def test_default_config_enables_windows_binding():
    assert winsetup.default_config("Lab", 7575) == {"name": "Lab", "port": 7575, "windows_bind": True}


@pytest.mark.parametrize("name", ["", "x" * 65])
def test_install_rejects_bad_names(tmp_path, name):
    steps = winsetup.install(EXE, tmp_path, name=name, port=7575, allow_public=False, runner=FakeRunner(),
                             is_admin=lambda: True, port_check=lambda port, host=None: True)
    assert not steps[0].ok


def test_server_config_import_still_valid():
    assert ServerConfig().port == 7575


def test_install_locks_the_data_folder_before_anything_is_written(tmp_path):
    runner = FakeRunner()
    steps = winsetup.install(EXE, tmp_path / "VHServer", name="Lab", port=7575, allow_public=False, runner=runner,
                             is_admin=lambda: True, port_check=lambda port, host=None: True)
    joined = runner.joined()
    owner = next(i for i, c in enumerate(joined) if "icacls" in c and "/setowner *S-1-5-32-544" in c)
    acl = next(i for i, c in enumerate(joined) if "/inheritance:r" in c and "*S-1-5-18:(OI)(CI)F" in c
               and "*S-1-5-32-544:(OI)(CI)F" in c)
    task = next(i for i, c in enumerate(joined) if c.startswith("schtasks /Create"))
    assert steps[0].name == "secure" and owner < acl < task
    assert not any("S-1-5-32-545" in c or "Everyone" in c for c in joined)  # no read access for ordinary users


def test_install_stops_when_the_folder_cannot_be_locked(tmp_path):
    runner = FakeRunner(fail_on=["icacls"])
    steps = winsetup.install(EXE, tmp_path / "VHServer", name="Lab", port=7575, allow_public=False, runner=runner,
                             is_admin=lambda: True, port_check=lambda port, host=None: True)
    assert [s.name for s in steps] == ["secure"] and not steps[0].ok
    assert not (tmp_path / "VHServer" / "config.json").exists() and not any("schtasks" in c for c in runner.joined())


@pytest.mark.parametrize("port", [0, 65536, -1])
def test_install_rejects_invalid_ports(tmp_path, port):
    runner = FakeRunner()
    steps = winsetup.install(EXE, tmp_path, name="Lab", port=port, allow_public=False, runner=runner,
                             is_admin=lambda: True, port_check=lambda port, host=None: True)
    assert steps[0].name == "port" and not steps[0].ok and runner.calls == []


def test_firewall_and_check_follow_the_port_the_server_will_really_use(tmp_path):
    (tmp_path / "config.json").write_text('{"port": 7777}', encoding="utf-8")
    runner, checked = FakeRunner(), []
    winsetup.install(EXE, tmp_path, name="Lab", port=8000, allow_public=False, runner=runner, is_admin=lambda: True,
                     port_check=lambda port, host=None: checked.append(port) or True, wait=lambda: None)
    assert any("localport=7777" in c for c in runner.joined()) and not any("localport=8000" in c for c in runner.joined())
    assert checked == [7777]


def test_install_reports_a_broken_existing_config(tmp_path):
    (tmp_path / "config.json").write_text("{oops", encoding="utf-8")
    steps = winsetup.install(EXE, tmp_path, name="Lab", port=7575, allow_public=False, runner=FakeRunner(),
                             is_admin=lambda: True, port_check=lambda port, host=None: True)
    assert steps[-1].name == "config" and not steps[-1].ok


def test_purge_and_install_refuse_a_redirected_data_folder(tmp_path, monkeypatch):
    monkeypatch.setattr(winsetup, "is_reparse_point", lambda path: True)
    runner = FakeRunner()
    steps = winsetup.uninstall(tmp_path, purge=True, runner=runner, is_admin=lambda: True, recover=lambda: [])
    assert steps[-1].name == "purge" and not steps[-1].ok and tmp_path.exists()
    steps = winsetup.install(EXE, tmp_path, name="Lab", port=7575, allow_public=False, runner=runner,
                             is_admin=lambda: True, port_check=lambda port, host=None: True)
    assert not steps[0].ok and steps[0].name == "secure"


def test_name_limit_is_counted_in_utf8_bytes(tmp_path):
    runner = FakeRunner()
    steps = winsetup.install(EXE, tmp_path, name="é" * 33, port=7575, allow_public=False, runner=runner,
                             is_admin=lambda: True, port_check=lambda port, host=None: True)
    assert steps[0].name == "name" and not steps[0].ok


def test_default_runner_turns_a_missing_program_into_a_failed_result():
    result = winsetup.default_runner(["definitely-not-a-program-xyz"])
    assert result.returncode != 0


def test_default_runner_passes_no_windows_flags_on_other_systems(monkeypatch):
    seen = {}
    monkeypatch.setattr(winsetup.os, "name", "posix")
    monkeypatch.setattr(winsetup.subprocess, "run", lambda args, **kw: seen.update(kw) or SimpleNamespace(returncode=0))
    winsetup.default_runner(["true"])
    assert "creationflags" not in seen
    monkeypatch.setattr(winsetup.os, "name", "nt")
    winsetup.default_runner(["true"])
    assert seen["creationflags"] == winsetup.CREATE_NO_WINDOW


def test_ssl_port_gets_its_own_program_scoped_rule():
    rules = winsetup.firewall_rules(EXE, 7575, False, ssl_port=7574)
    assert [(r.label, r.port) for r in rules] == [("TCP", 7575), ("mDNS UDP", 5353), ("TCP SSL", 7574)]
    assert "localport=7574" in rules[2].add_args(EXE) and "remoteip=LocalSubnet,100.64.0.0/10" in rules[2].add_args(EXE)
    assert len(winsetup.firewall_rules(EXE, 7575, False)) == 2


def test_install_with_ssl_opens_the_ssl_port_after_the_security_step(tmp_path):
    runner = FakeRunner()

    def security():
        from vhserver.config import update_config
        update_config(tmp_path / "config.json", {"ssl_cert": "c.pem", "ssl_key": "k.pem"})
        return [winsetup.Step("ssl", True, "SSL enabled")]

    steps = winsetup.install(EXE, tmp_path, name="Lab", port=7575, allow_public=False, runner=runner,
                             is_admin=lambda: True, port_check=lambda port, host=None: True, security=security)
    assert any(s.name == "ssl" for s in steps) and all(s.ok for s in steps)
    assert any("localport=7574" in c for c in runner.joined())


def test_install_without_ssl_removes_a_stale_ssl_rule(tmp_path):
    runner = FakeRunner()
    winsetup.install(EXE, tmp_path, name="Lab", port=7575, allow_public=False, runner=runner, is_admin=lambda: True,
                     port_check=lambda port, host=None: True)
    joined = runner.joined()
    assert any("delete rule name=VirtualUSB Server (TCP SSL)" in c for c in joined)
    assert not any("localport=7574" in c and "add rule" in c for c in joined)


def test_a_failed_security_step_stops_the_installation_before_any_rule_or_task(tmp_path):
    runner = FakeRunner()
    steps = winsetup.install(EXE, tmp_path, name="Lab", port=7575, allow_public=False, runner=runner,
                             is_admin=lambda: True, port_check=lambda port, host=None: True,
                             security=lambda: [winsetup.Step("password", False, "too short")])
    assert not steps[-1].ok and steps[-1].name == "password"
    assert not any("add rule" in c or "schtasks /Create" in c for c in runner.joined())


def test_uninstall_removes_the_ssl_rule_too(tmp_path):
    runner = FakeRunner()
    winsetup.uninstall(tmp_path, runner=runner, is_admin=lambda: True, recover=lambda: [], purge=False)
    assert any("(TCP SSL)" in c for c in runner.joined())


def test_the_task_is_started_again_every_five_minutes_if_it_is_not_running():
    root = ET.fromstring(winsetup.task_xml(EXE))
    repeat = root.find("t:Triggers/t:TimeTrigger/t:Repetition", NS)
    assert repeat.find("t:Interval", NS).text == "PT5M" and repeat.find("t:StopAtDurationEnd", NS).text == "false"
    assert root.find("t:Settings/t:MultipleInstancesPolicy", NS).text == "IgnoreNew"
