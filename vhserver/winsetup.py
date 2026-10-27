"""Windows installation steps: configuration, firewall rules and the boot task that runs the server as SYSTEM.

Everything external goes through an injected ``runner`` (argument lists, never a shell), so the logic is unit tested
without touching the machine. The same steps are exposed as ``vhserver install`` / ``vhserver uninstall``.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from xml.sax.saxutils import escape

from .config import ConfigError, DEFAULT_PORT, DEFAULT_SSL_PORT, load_config, valid_name
from .messages import text

TASK_NAME = "VHServer"
RULE_NAME = "VirtualUSB Server"
LEGACY_RULES = ("vhserver TCP 7575", "vhserver mDNS UDP 5353")  # created by hand while testing
MDNS_PORT = 5353
TAILSCALE_NET = "100.64.0.0/10"
SYSTEM_SID = "S-1-5-18"
ADMINS_SID = "S-1-5-32-544"
REPARSE_POINT = 0x400  # symlinks and junctions
CREATE_NO_WINDOW = 0x08000000
STARTUP_WAIT_S = 4.0
TRUSTED_OWNERS = (SYSTEM_SID, ADMINS_SID)
_SID = re.compile(r"^S-1-\d+(-\d+)+$")

Runner = Callable[[list], "subprocess.CompletedProcess"]


@dataclass(frozen=True)
class Step:
    name: str
    ok: bool
    detail: str


@dataclass(frozen=True)
class FirewallRule:
    label: str
    protocol: str
    port: int
    profiles: str

    @property
    def name(self) -> str:
        return f"{RULE_NAME} ({self.label})"

    def add_args(self, exe: str) -> list[str]:
        return ["netsh", "advfirewall", "firewall", "add", "rule", f"name={self.name}", "dir=in", "action=allow",
                f"program={exe}", f"protocol={self.protocol}", f"localport={self.port}",
                f"profile={self.profiles}", f"remoteip=LocalSubnet,{TAILSCALE_NET}", "enable=yes"]

    def delete_args(self) -> list[str]:
        return ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={self.name}"]


def firewall_rules(exe: str, port: int, allow_public: bool, ssl_port: int | None = None,
                   plain: bool = True) -> list[FirewallRule]:
    """The plain port (unless switched off), mDNS and, when SSL is configured, the SSL port."""
    profiles = "private,domain,public" if allow_public else "private,domain"
    rules = [FirewallRule("mDNS UDP", "UDP", MDNS_PORT, profiles)]
    if plain:
        rules.insert(0, FirewallRule("TCP", "TCP", port, profiles))
    if ssl_port:
        rules.append(FirewallRule("TCP SSL", "TCP", ssl_port, profiles))
    return rules


def all_rule_names() -> list[FirewallRule]:
    """Every rule this package may have created, for removal."""
    return firewall_rules("", DEFAULT_PORT, True, DEFAULT_SSL_PORT)


def task_xml(exe: str) -> str:
    """Task Scheduler definition: start at boot as SYSTEM, no time limit. If the process dies (or exits to recover from a
    hang) it is started again within 5 minutes by the repeating trigger; IgnoreNew stops duplicate instances."""
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>VirtualUSB server</Description></RegistrationInfo>
  <Triggers>
    <BootTrigger><Enabled>true</Enabled></BootTrigger>
    <TimeTrigger>
      <Repetition><Interval>PT5M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>
      <StartBoundary>2020-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author"><UserId>{SYSTEM_SID}</UserId><RunLevel>HighestAvailable</RunLevel></Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>
  </Settings>
  <Actions Context="Author"><Exec><Command>"{escape(exe)}"</Command><Arguments>run</Arguments></Exec></Actions>
</Task>
"""


def default_config(name: str, port: int) -> dict:
    return {"name": name, "port": port, "windows_bind": True}


def default_runner(args: list) -> "subprocess.CompletedProcess":
    """Run a command; a missing program or a timeout is reported as a failed result instead of an exception."""
    extra = {"creationflags": CREATE_NO_WINDOW} if os.name == "nt" else {}  # the flag exists on Windows only
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=120, **extra)
    except (OSError, subprocess.SubprocessError) as exc:
        return subprocess.CompletedProcess(args, 1, "", str(exc))


def is_admin() -> bool:
    import ctypes

    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def port_listening(port: int, host: str = "127.0.0.1") -> bool:
    try:
        with socket.create_connection(("127.0.0.1" if host in ("0.0.0.0", "") else host, port), timeout=2):
            return True
    except OSError:
        return False


def is_reparse_point(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & REPARSE_POINT)


def folder_owner_sid(path: Path, runner: Runner) -> str | None:
    """SID of the folder's owner (language independent), or None when it cannot be read."""
    quoted = str(path).replace("'", "''")
    script = f"(Get-Acl -LiteralPath '{quoted}').GetOwner([System.Security.Principal.SecurityIdentifier]).Value"
    result = runner(["powershell", "-NoProfile", "-NonInteractive", "-Command", script])
    owner = (getattr(result, "stdout", "") or "").strip()
    return owner if result.returncode == 0 and _SID.match(owner) else None


def tree_is_trusted(path: Path, runner: Runner) -> bool:
    """True only when nothing inside ``path`` is a link and everything is owned by SYSTEM or administrators."""
    trusted = ",".join(f"'{sid}'" for sid in TRUSTED_OWNERS)
    quoted = str(path).replace("'", "''")
    script = "; ".join([
        "$ErrorActionPreference = 'Stop'",
        "$check = 'TREECHECK'",  # marks the script for the unit tests' fake runner; a comment would swallow the rest
        f"$trusted = @({trusted})",
        "function Walk($dir) { foreach ($item in Get-ChildItem -LiteralPath $dir -Force) {"
        " if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false };"
        " $owner = (Get-Acl -LiteralPath $item.FullName).GetOwner([System.Security.Principal.SecurityIdentifier]).Value;"
        " if ($trusted -notcontains $owner) { return $false };"
        " if ($item.PSIsContainer -and -not (Walk $item.FullName)) { return $false } }; return $true }",
        f"if (Walk '{quoted}') {{ 'OK' }} else {{ 'BAD' }}",
    ])
    result = runner(["powershell", "-NoProfile", "-NonInteractive", "-Command", script])
    return result.returncode == 0 and (getattr(result, "stdout", "") or "").strip() == "OK"


def _remove_tree(path: Path) -> None:
    """Delete ``path`` and everything below it; a junction or symlink is removed itself, never followed."""
    if is_reparse_point(path):
        os.rmdir(path) if path.is_dir() else path.unlink()
    elif path.is_dir():
        for child in list(path.iterdir()):
            _remove_tree(child)
        path.rmdir()
    else:
        path.unlink()


def _remove_contents(folder: Path) -> None:
    for child in list(folder.iterdir()):
        _remove_tree(child)


def _create_exclusively(data_dir: Path) -> bool:
    """True when this call created the folder (so it is empty and ours), False when it was already there."""
    try:
        data_dir.mkdir(parents=True)
    except FileExistsError:
        if not data_dir.is_dir():
            raise
        return False
    return True


def secure_data_dir(data_dir: Path, runner: Runner) -> Step:
    """The server runs as SYSTEM and reads its settings, state and logs from here, so only SYSTEM and administrators
    may own or write the folder (ProgramData lets any user create a folder first and keep control of it).

    A folder this call creates is trusted. One that was already there is locked down first (top level only, so no
    recursion through links an attacker left inside), then trusted only if its former owner and every entry inside are
    SYSTEM or administrators and no entry is a link; otherwise it is emptied and the installer writes fresh files."""
    if is_reparse_point(data_dir):
        return Step("secure", False, text("dir_unsafe", path=data_dir))
    try:
        created = _create_exclusively(data_dir)
    except OSError as exc:
        return Step("secure", False, text("config_failed", error=exc))
    former_owner_trusted = created or folder_owner_sid(data_dir, runner) in TRUSTED_OWNERS
    target = str(data_dir)
    lock = (["icacls", target, "/setowner", f"*{ADMINS_SID}", "/C"],
            ["icacls", target, "/inheritance:r", "/grant:r", f"*{SYSTEM_SID}:(OI)(CI)F", f"*{ADMINS_SID}:(OI)(CI)F"])
    for args in lock:
        if runner(args).returncode != 0:
            return Step("secure", False, text("dir_unsafe", path=data_dir))
    if not (created or (former_owner_trusted and tree_is_trusted(data_dir, runner))):
        try:
            _remove_contents(data_dir)
        except OSError:
            return Step("secure", False, text("dir_unsafe", path=data_dir))
        return Step("secure", True, text("dir_reset", path=data_dir))
    if not created:  # /L: act on a link itself; the tree was just checked, so this is only belt and braces
        runner(["icacls", target, "/setowner", f"*{ADMINS_SID}", "/T", "/C", "/L"])
        runner(["icacls", target + "\\*", "/reset", "/T", "/C", "/L"])  # children inherit the locked ACL
    return Step("secure", True, text("dir_secured", path=data_dir))


def _write_config(data_dir: Path, name: str, port: int) -> Step:
    path = data_dir / "config.json"
    if path.exists():
        return Step("config", True, text("config_kept", path=path))
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(default_config(name, port), indent=2), encoding="utf-8")
    except OSError as exc:
        return Step("config", False, text("config_failed", error=exc))
    return Step("config", True, text("config_written", path=path))


def _install_firewall(exe: str, port: int, allow_public: bool, runner: Runner, ssl_port: int | None = None,
                      plain: bool = True) -> Step:
    for legacy in LEGACY_RULES:
        runner(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={legacy}"])
    for stale in all_rule_names():
        runner(stale.delete_args())  # e.g. the SSL rule left over after SSL was switched off
    for rule in firewall_rules(exe, port, allow_public, ssl_port, plain):
        runner(rule.delete_args())  # reinstalling must not stack duplicates
        if runner(rule.add_args(exe)).returncode != 0:
            return Step("firewall", False, text("firewall_failed", rule=rule.name))
    return Step("firewall", True, text("firewall_ok"))


def _install_task(exe: str, data_dir: Path, runner: Runner) -> Step:
    xml_path = data_dir / "task.xml"
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        xml_path.write_bytes(b"\xff\xfe" + task_xml(exe).encode("utf-16-le"))  # schtasks wants UTF-16 with BOM
    except OSError as exc:
        return Step("task", False, text("task_failed", error=exc))
    result = runner(["schtasks", "/Create", "/TN", TASK_NAME, "/XML", str(xml_path), "/F"])
    xml_path.unlink(missing_ok=True)
    if result.returncode != 0:
        return Step("task", False, text("task_failed", error=(result.stdout or "").strip()[:200]))
    runner(["schtasks", "/End", "/TN", TASK_NAME])  # IgnoreNew would keep an old process (and its old settings) alive
    runner(["schtasks", "/Run", "/TN", TASK_NAME])
    return Step("task", True, text("task_ok"))


def install(exe: str, data_dir: Path, *, name: str, port: int, allow_public: bool, runner: Runner = default_runner,
            is_admin: Callable[[], bool] = is_admin, port_check: Callable[..., bool] = port_listening,
            wait: Callable[[], None] = lambda: time.sleep(STARTUP_WAIT_S),
            security: Callable[[], list[Step]] = lambda: []) -> list[Step]:
    """``security`` runs after the configuration exists and before the firewall: it may switch SSL on or set a
    password (``vhserver tls enable`` / ``vhserver password``), so the rules and the task match the final settings."""
    if not is_admin():
        return [Step("admin", False, text("need_admin"))]
    if not valid_name(name):
        return [Step("name", False, text("bad_name"))]
    if type(port) is not int or not 0 < port < 65536:
        return [Step("port", False, text("bad_port"))]
    steps = [secure_data_dir(data_dir, runner)]
    if not steps[-1].ok:
        return steps
    steps.append(_write_config(data_dir, name, port))
    if not steps[-1].ok:
        return steps
    steps.extend(security())
    if not all(step.ok for step in steps):
        return steps
    try:
        config = load_config(data_dir / "config.json")  # an existing file wins: rules and checks follow what the server uses
    except ConfigError as exc:
        return [*steps, Step("config", False, text("config_failed", error=exc))]
    steps.append(_install_firewall(exe, config.port, allow_public, runner, config.ssl_port if config.ssl_cert else None,
                                   config.allow_plaintext))
    steps.append(_install_task(exe, data_dir, runner))
    if all(step.ok for step in steps):
        wait()
        served = config.port if config.allow_plaintext else config.ssl_port
        listening = port_check(served, config.bind)
        steps.append(Step("listening", listening, text("listening_ok" if listening else "listening_failed", port=served)))
    return steps


def uninstall(data_dir: Path, *, purge: bool, runner: Runner = default_runner,
              is_admin: Callable[[], bool] = is_admin, recover: Callable[[], list]) -> list[Step]:
    if not is_admin():
        return [Step("admin", False, text("need_admin"))]
    runner(["schtasks", "/End", "/TN", TASK_NAME])
    runner(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"])
    steps = [Step("task", True, text("removed_task"))]
    for rule in all_rule_names():
        runner(rule.delete_args())
    for legacy in LEGACY_RULES:
        runner(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={legacy}"])
    steps.append(Step("firewall", True, text("removed_rules")))
    steps.append(Step("recovery", True, text("recovered", count=len(recover()))))
    if purge:
        if is_reparse_point(data_dir):
            steps.append(Step("purge", False, text("dir_unsafe", path=data_dir)))
        else:
            shutil.rmtree(data_dir, ignore_errors=True)
            steps.append(Step("purge", True, text("purged")))
    return steps
