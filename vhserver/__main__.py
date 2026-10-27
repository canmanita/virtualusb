"""Run the VirtualUSB server.

  python -m vhserver                      # share the real USB devices of this machine (libusb)
  python -m vhserver --fake-disk          # expose an emulated RAM disk, for testing without hardware
  vhserver run | install | uninstall | doctor      # packaged Windows build (see docs/WINDOWS-INSTALL.md)
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import logging.handlers
import os
import sys
from pathlib import Path

from .config import ConfigError, load_config, parse_vid_pid
from .netpolicy import AccessPolicy
from .nicknames import NicknameStore
from .paths import config_path, log_path, nicknames_path, state_path
from .security import PasswordPolicy
from .server import VhServer
from .tlsconfig import TlsError

ADMIN_COMMANDS = ("install", "uninstall", "doctor")
SECURITY_COMMANDS = ("password", "tls")
LOG_FORMAT = "%(asctime)s %(levelname)s %(message)s"
LOG_BYTES, LOG_BACKUPS = 1_000_000, 5


def build_backend(args: argparse.Namespace):
    if args.fake_disk:
        from .fakedisk import FakeDiskBackend

        backend = FakeDiskBackend()
        if args.hotplug_demo:
            backend.start_hotplug_demo(args.hotplug_demo)
        return backend
    from .libusb_backend import LibUsbBackend

    binder = direct_opener = None
    if args.windows_bind:
        from .recovery import PendingStore
        from .winusb import WinUsbBinder

        from .winusb_direct import WinUsbDirectOpener

        binder = WinUsbBinder(PendingStore(state_path()))
        direct_opener = WinUsbDirectOpener()
        if not binder.is_admin():
            logging.getLogger("vhserver").warning("--windows-bind needs an elevated (administrator) terminal")
        elif _already_serving(args):
            logging.getLogger("vhserver").warning("port %d already answers: another server is running, "
                                                  "skipping driver recovery", args.port)
        else:
            binder.recover_pending()  # devices a previous run left on WinUSB go back to their own driver
    name_lookup = uplink_check = None
    if sys.platform == "win32":
        from .winnames import lookup as name_lookup
    elif sys.platform.startswith("linux"):
        from .uplink import carries_uplink as uplink_check
        from .linuxnames import lookup as name_lookup
    return LibUsbBackend(share_hubs=args.share_hubs, share_input=args.share_input, ignore=args.ignore,
                         binder=binder, name_lookup=name_lookup, uplink_check=uplink_check,
                         direct_opener=direct_opener)


def _already_serving(args: argparse.Namespace) -> bool:
    from .winsetup import port_listening

    return port_listening(args.port, args.bind)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="VirtualUSB server")
    parser.add_argument("--config", type=Path, default=None, help=f"JSON settings file (default: {config_path()})")
    parser.add_argument("--name", default="VH Clone", help="server name shown by the client")
    parser.add_argument("--port", type=int, default=7575)
    parser.add_argument("--fake-disk", action="store_true", help="expose an emulated RAM disk (for testing)")
    parser.add_argument("--no-mdns", action="store_true", help="do not announce the server via mDNS (Auto-Find)")
    parser.add_argument("--bind", default="0.0.0.0", metavar="ADDRESS", help="address to listen on (default: all)")
    parser.add_argument("--allow", action="append", metavar="CIDR",
                        help="network allowed to connect (repeatable); default: loopback, private and Tailscale ranges")
    parser.add_argument("--windows-bind", action="store_true",
                        help="Windows: switch a device to the WinUSB driver while a client uses it and restore it "
                             "afterwards (needs an administrator terminal)")
    parser.add_argument("--share-hubs", action="store_true", help="also offer USB hubs")
    parser.add_argument("--share-input", "--share-keyboards", dest="share_input", action="store_true",
                        help="also offer boot keyboards and mice (withheld by default: a remote user could read "
                             "keystrokes or take over the pointer)")
    parser.add_argument("--ignore", type=parse_vid_pid, action="append", default=None, metavar="VID:PID",
                        help="hex VID:PID of a device that must never be shared (repeatable)")
    parser.add_argument("--hotplug-demo", type=float, metavar="SECONDS",
                        help="with --fake-disk: unplug/replug the fake disk every SECONDS")
    parser.add_argument("--log-file", type=Path, default=None, help="also write the log to this file (rotated)")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Settings file first, then explicit command line options on top of it."""
    parser = build_parser()
    pre, _ = parser.parse_known_args(argv)
    config = load_config(pre.config or config_path())
    parser.set_defaults(**config.cli_defaults())
    args = parser.parse_args(argv)
    if args.allow is None:  # an option given on the command line replaces the file's list
        args.allow = list(config.allow) or None
    if args.ignore is None:
        args.ignore = list(config.ignore)
    args.server_config = config  # settings without a command line option (passwords, SSL, ...)
    return args


def configure_logging(verbose: bool, log_file: Path | None) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_file is not None:
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            handlers.append(logging.handlers.RotatingFileHandler(log_file, maxBytes=LOG_BYTES, backupCount=LOG_BACKUPS,
                                                                 encoding="utf-8"))
        except OSError as exc:
            print(f"cannot open the log file {log_file}: {exc}", file=sys.stderr)
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, format=LOG_FORMAT, handlers=handlers,
                        force=True)


def build_tls(config):
    """The TLS context for the SSL port, or None when no certificate is configured."""
    if not config.ssl_cert:
        return None
    from .tlsconfig import build_context

    return build_context(Path(config.ssl_cert), Path(config.ssl_key),
                         ca=Path(config.ssl_ca) if config.ssl_ca else None,
                         require_client_cert=config.ssl_use_client_certs)


def security_steps(args: argparse.Namespace) -> list:
    """Optional SSL and password setup requested at install time, reported like the other install steps."""
    from .admincli import main as security_main
    from .messages import text
    from .winsetup import Step

    steps = []
    if args.ssl or args.ssl_only:
        code = security_main(["tls", "enable"] + (["--only"] if args.ssl_only else []))
        steps.append(Step("ssl", code == 0, text("tls_step_ok" if code == 0 else "tls_step_failed")))
    if args.password_file:
        code = security_main(["password", "--from-file", args.password_file])
        steps.append(Step("password", code == 0, text("pw_step_ok" if code == 0 else "pw_step_failed")))
    return steps


_CRASH_LOG = None  # kept open for the life of the process: faulthandler writes to it from a signal-like context


def enable_crash_log(path: Path) -> None:
    """Native crashes (access violations, fatal errors) leave a traceback here instead of vanishing silently."""
    global _CRASH_LOG
    try:
        import faulthandler

        path.parent.mkdir(parents=True, exist_ok=True)
        _CRASH_LOG = open(path, "a", encoding="utf-8")
        faulthandler.enable(file=_CRASH_LOG, all_threads=True)
    except OSError as exc:
        logging.getLogger("vhserver").warning("cannot open the crash log %s: %s", path, exc)


def executable() -> str:
    return sys.executable if getattr(sys, "frozen", False) else str(Path(sys.argv[0]).resolve())


def run_admin_command(command: str, argv: list[str]) -> int:
    from .paths import data_dir

    parser = argparse.ArgumentParser(prog=f"vhserver {command}")
    if command == "install":
        parser.add_argument("--name", default=None, help="server name shown by the clients (default: computer name)")
        parser.add_argument("--port", type=int, default=7575)
        parser.add_argument("--allow-public", action="store_true",
                            help="also open the firewall on networks Windows classifies as Public (not recommended)")
        parser.add_argument("--ssl", action="store_true", help="create certificates and switch the SSL port on")
        parser.add_argument("--ssl-only", action="store_true", help="like --ssl, and switch the unencrypted port off")
        parser.add_argument("--password-file", metavar="PATH", help=argparse.SUPPRESS)
    if command == "uninstall":
        parser.add_argument("--purge", action="store_true", help="also delete configuration and logs")
    args = parser.parse_args(argv)
    if command == "doctor":
        from .doctor import LinuxProbe, SystemProbe, report, run_checks, run_linux_checks

        checks = run_checks(SystemProbe(executable())) if os.name == "nt" else run_linux_checks(LinuxProbe())
        lines, code = report(checks)
        print("\n".join(lines))
        return code
    if os.name != "nt":
        print("[FAIL] install/uninstall are for the Windows build; on Linux use the package manager (apt/dpkg).")
        return 1
    from . import winsetup

    if command == "install":
        from .config import default_name
        from .messages import text

        if not getattr(sys, "frozen", False):
            print(f"[FAIL] {text('need_packaged')}")
            return 1
        try:
            steps = winsetup.install(executable(), data_dir(), name=args.name or default_name(), port=args.port,
                                     allow_public=args.allow_public, security=lambda: security_steps(args))
        finally:
            if args.password_file:  # never leave the installer's password file behind, whatever happened
                Path(args.password_file).unlink(missing_ok=True)
    else:
        from .recovery import PendingStore
        from .winusb import WinUsbBinder

        def recover() -> list[str]:
            return WinUsbBinder(PendingStore(state_path())).recover_pending()

        steps = winsetup.uninstall(data_dir(), purge=args.purge, recover=recover)
    for step in steps:
        print(f"[{' OK ' if step.ok else 'FAIL'}] {step.detail}")
    return 0 if all(step.ok for step in steps) else 1


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in SECURITY_COMMANDS:
        from .admincli import main as security_main

        raise SystemExit(security_main(argv))
    if argv and argv[0] in ADMIN_COMMANDS:
        raise SystemExit(run_admin_command(argv[0], argv[1:]))
    service_mode = bool(argv) and argv[0] == "run"
    if service_mode:
        argv = argv[1:]
    try:
        args = parse_args(argv)
    except ConfigError as exc:
        raise SystemExit(f"configuration error: {exc}") from exc
    configure_logging(args.verbose, args.log_file or (log_path() if service_mode and os.name == "nt" else None))
    if service_mode and os.name == "nt":
        enable_crash_log(log_path().parent / "crash.log")
    policy = AccessPolicy(args.allow) if args.allow else AccessPolicy()
    config = args.server_config
    if config.ssl_cert and args.port == config.ssl_port:
        raise SystemExit(f"--port and ssl_port are both {args.port}")
    try:
        tls = build_tls(config)
    except TlsError as exc:
        raise SystemExit(f"TLS error: {exc}") from exc
    server = VhServer(build_backend(args), name=args.name, port=args.port, bind_host=args.bind, policy=policy,
                      passwords=PasswordPolicy(config.password_hash, dict(config.device_passwords)),
                      nicknames=NicknameStore(nicknames_path()), allow_rename=config.allow_rename,
                      ssl_context=tls, ssl_port=config.ssl_port, allow_plaintext=config.allow_plaintext)
    asyncio.run(server.run(announce=not args.no_mdns))


if __name__ == "__main__":
    main()
