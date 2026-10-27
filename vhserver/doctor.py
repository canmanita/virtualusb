"""`vhserver doctor`: explains why a client cannot find or use this server, in the problems we actually met."""
from __future__ import annotations

import json
import os
from pathlib import Path
from dataclasses import dataclass

from .config import DEFAULT_SSL_PORT, ConfigError, ServerConfig, load_config
from .tlsconfig import certificate_info as read_certificate
from .messages import text
from .paths import config_path, state_path
from .winsetup import RULE_NAME, TASK_NAME, default_runner, firewall_rules, is_admin, port_listening

PUBLIC_CATEGORY = 0  # NetworkCategory: 0 Public, 1 Private, 2 Domain


@dataclass(frozen=True)
class Check:
    key: str
    status: str  # ok | warn | fail
    title: str
    fix: str = ""


def parse_names(result) -> list[str]:
    if result.returncode != 0:
        return []
    names = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return list(dict.fromkeys(names))


def parse_public(result) -> list[str]:
    try:
        rows = json.loads(result.stdout)
    except ValueError:
        return []
    rows = rows if isinstance(rows, list) else [rows]
    return [row["InterfaceAlias"] for row in rows
            if isinstance(row, dict) and row.get("NetworkCategory") == PUBLIC_CATEGORY and row.get("InterfaceAlias")]


def _powershell(command: str):
    return default_runner(["powershell", "-NoProfile", "-NonInteractive", "-Command", command])


class SystemProbe:
    """The real machine, behind the same small interface the tests fake."""

    def __init__(self, exe: str) -> None:
        self.exe = exe
        self.config_error = None
        try:
            self.config: ServerConfig | None = load_config(config_path())
        except ConfigError as exc:
            self.config, self.config_error = None, str(exc)

    def is_admin(self): return is_admin()
    def port_open(self, port): return port_listening(port, self.config.bind if self.config else "127.0.0.1")
    def task_exists(self): return default_runner(["schtasks", "/Query", "/TN", TASK_NAME]).returncode == 0

    def libusb(self):
        try:
            import usb1

            with usb1.USBContext():
                return True
        except Exception:  # noqa: BLE001 - any failure to load the native library is the finding
            return False

    def rules_exist(self):
        config = self.config or ServerConfig()
        rules = firewall_rules(self.exe, config.port, False, config.ssl_port if config.ssl_cert else None,
                               plain=config.allow_plaintext)
        return all(default_runner(["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule.name}"]).returncode == 0
                   for rule in rules)

    def blocking_rules(self):
        quoted = self.exe.replace("'", "''")
        return parse_names(_powershell(
            f"Get-NetFirewallApplicationFilter -Program '{quoted}' -ErrorAction SilentlyContinue | "
            "Get-NetFirewallRule | Where-Object { $_.Action -eq 'Block' -and $_.Enabled -eq 'True' } | "
            "ForEach-Object { $_.DisplayName }"))

    def public_lan(self):
        return parse_public(_powershell("Get-NetConnectionProfile | Select-Object InterfaceAlias,NetworkCategory | "
                                        "ConvertTo-Json -Compress"))

    def pending_devices(self):
        from .recovery import PendingStore

        return PendingStore(state_path()).all()

    def announce_address(self):
        from .discovery import primary_ipv4

        return primary_ipv4()


def serving_port(config: ServerConfig | None) -> int:
    """The port a client can reach: the plain one, or the SSL one when plain connections are switched off."""
    if config is None:
        return 7575
    return config.port if config.allow_plaintext else config.ssl_port


def run_checks(probe) -> list[Check]:
    port = serving_port(probe.config)
    admin, task, rules = probe.is_admin(), probe.task_exists(), probe.rules_exist()
    checks = [
        Check("admin", "ok" if admin else "fail", text("doctor_admin"), "" if admin else text("doctor_admin_fix")),
        Check("libusb", "ok" if probe.libusb() else "fail", text("doctor_libusb")),
        Check("config", "ok" if probe.config else "fail", text("doctor_config"), probe.config_error or ""),
        Check("task", "ok" if task else "fail", text("doctor_task"), "" if task else text("doctor_task_fix")),
        Check("rules", "ok" if rules else "fail", text("doctor_rules"), "" if rules else text("doctor_rules_fix")),
    ]
    blocks = probe.blocking_rules()
    checks.append(Check("block", "fail" if blocks else "ok", text("doctor_block"),
                        text("doctor_block_fix", rules=", ".join(blocks)) if blocks else ""))
    public = probe.public_lan()
    checks.append(Check("profile", "warn" if public else "ok", text("doctor_profile"),
                        text("doctor_profile_fix", alias=public[0]) if public else ""))
    listening = probe.port_open(port)
    checks.append(Check("port", "ok" if listening else "fail", text("doctor_port", port=port),
                        "" if listening else text("doctor_port_fix")))
    pending = probe.pending_devices()
    checks.append(Check("pending", "warn" if pending else "ok", text("doctor_pending"),
                        text("doctor_pending_fix", ids=", ".join(pending)) if pending else ""))
    address = probe.announce_address()
    checks.append(Check("mdns", "ok" if address else "warn", text("doctor_mdns", address=address or "-"),
                        "" if address else text("doctor_mdns_fix")))
    return checks + security_checks(probe.config)


_TAGS = {"ok": "[ OK ]", "warn": "[WARN]", "fail": "[FAIL]"}


def report(checks: list[Check]) -> tuple[list[str], int]:
    lines: list[str] = []
    for check in checks:
        lines.append(f"{_TAGS[check.status]} {check.title}")
        if check.fix:
            lines.append(f"       {check.fix}")
    return lines, 1 if any(check.status == "fail" for check in checks) else 0


class LinuxProbe:
    """The real Linux host, behind the interface the tests fake."""

    RULE_FILES = ("/etc/udev/rules.d/70-vhserver.rules", "/usr/lib/udev/rules.d/70-vhserver.rules",
                  "/lib/udev/rules.d/70-vhserver.rules")

    def __init__(self) -> None:
        try:
            self.config: ServerConfig | None = load_config(config_path())
            self.config_error = None
        except ConfigError as exc:
            self.config, self.config_error = None, str(exc)

    def libusb(self):
        return SystemProbe.libusb(self)

    def service_active(self):
        return default_runner(["systemctl", "is-active", "--quiet", "vhserver"]).returncode == 0

    def usb_rules_installed(self):
        import pwd

        try:
            pwd.getpwnam("vhserver")
        except KeyError:
            return False
        return any(os.path.exists(path) for path in self.RULE_FILES)

    def port_open(self, port):
        return port_listening(port, self.config.bind if self.config else "127.0.0.1")

    def firewall_active(self):
        if default_runner(["ufw", "status"]).stdout.startswith("Status: active"):
            return "ufw"
        if default_runner(["firewall-cmd", "--state"]).stdout.strip() == "running":
            return "firewalld"
        return None

    def firewall_allows(self, port):
        out = default_runner(["ufw", "status"]).stdout
        return str(port) in out if out.startswith("Status: active") else None  # needs root to be reliable

    def announce_address(self):
        from .discovery import primary_ipv4

        return primary_ipv4()

    def usb_access(self):
        """True/False: can the service user write to a USB device node (testable only as root); None if unknown."""
        if os.geteuid() != 0:
            return None
        import glob

        nodes = sorted(glob.glob('/dev/bus/usb/*/*'))
        if not nodes:
            return None
        result = default_runner(['runuser', '-u', SERVICE_USER, '--', 'test', '-w', nodes[-1]])
        return result.returncode == 0


SERVICE_USER = 'vhserver'


def run_linux_checks(probe) -> list[Check]:
    port = serving_port(probe.config)
    service, rules, listening = probe.service_active(), probe.usb_rules_installed(), probe.port_open(port)
    checks = [
        Check("service", "ok" if service else "fail", text("doctor_service"), "" if service else text("doctor_service_fix")),
        Check("libusb", "ok" if probe.libusb() else "fail", text("doctor_libusb")),
        Check("config", "ok" if probe.config else "fail", text("doctor_config"), probe.config_error or ""),
        Check("usb", "ok" if rules else "fail", text("doctor_usb"), "" if rules else text("doctor_usb_fix")),
    ]
    access = getattr(probe, 'usb_access', lambda: None)()
    if rules and access is False:
        checks.append(Check('usb_acl', 'fail', text('doctor_usb_acl'), text('doctor_usb_acl_fix')))
    if listening and not service:
        checks.append(Check('conflict', 'warn', text('doctor_conflict', port=port), text('doctor_conflict_fix')))
    firewall = probe.firewall_active()
    if firewall and probe.firewall_allows(port) is not True:
        ssl_port = probe.config.ssl_port if probe.config else DEFAULT_SSL_PORT
        checks.append(Check("firewall", "warn", text("doctor_firewall", port=port),
                            text(f"doctor_firewall_{firewall}", port=port, ssl_port=ssl_port)))
    else:
        checks.append(Check("firewall", "ok", text("doctor_firewall", port=port)))
    checks.append(Check("port", "ok" if listening else "fail", text("doctor_port", port=port),
                        "" if listening else text("doctor_service_fix")))
    address = probe.announce_address()
    checks.append(Check("mdns", "ok" if address else "warn", text("doctor_mdns", address=address or "-"),
                        "" if address else text("doctor_mdns_fix")))
    return checks + security_checks(probe.config)


EXPIRY_WARNING_DAYS = 30


def security_checks(config: ServerConfig | None, certificate_info=read_certificate) -> list[Check]:
    """SSL certificate and password status; shared by the Windows and Linux reports."""
    if config is None:
        return []
    has_password = bool(config.password_hash or config.device_passwords)
    password = Check("password", "ok", text("doctor_pw_set" if has_password else "doctor_pw_none"))
    if not config.ssl_cert:
        status = "warn" if has_password else "ok"
        return [Check("tls", status, text("doctor_tls_off"), text("doctor_tls_off_pw_fix") if has_password else ""),
                password]
    path = Path(config.ssl_cert)
    if not path.is_file():
        return [Check("tls", "fail", text("doctor_tls_missing"), text("doctor_tls_missing_fix", path=path)), password]
    info = certificate_info(path)
    if info is None:
        return [Check("tls", "warn", text("doctor_tls_unreadable"), text("doctor_tls_unreadable_fix", path=path)),
                password]
    if info.days_left < 0:
        return [Check("tls", "fail", text("doctor_tls_expired"), text("doctor_tls_soon", days=info.days_left)), password]
    if info.days_left < EXPIRY_WARNING_DAYS:
        return [Check("tls", "warn", text("doctor_tls_on", days=info.days_left),
                      text("doctor_tls_soon", days=info.days_left)), password]
    return [Check("tls", "ok", text("doctor_tls_on", days=info.days_left)), password]
