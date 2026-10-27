"""`vhserver password` and `vhserver tls ...`: change the security settings without editing JSON by hand.

Both commands write the configuration file, so they must run as administrator (Windows) or root (Linux); the running
server reads the file at start, so restart it afterwards.
"""
from __future__ import annotations

import argparse
import getpass
import os
import socket
import sys
from pathlib import Path
from typing import Callable

from . import winsetup
from .config import DEFAULT_SSL_PORT, ConfigError, load_config, update_config
from .messages import text
from .paths import config_path, data_dir
from .security import MAX_PASSWORD_BYTES, new_password_hash
from .tlsconfig import TlsError, certificate_info, generate_certificates, generate_client_certificate

MIN_PASSWORD_CHARS = 8
SERVICE_GROUP = "vhserver"
Prompt = Callable[[str], str]


def _say(message: str) -> None:
    print(message)


def _tls_dir() -> Path:
    return data_dir() / "tls"


def _secure_tls_dir(directory: Path | None = None, runner: winsetup.Runner = winsetup.default_runner, *,
                    windows: bool = os.name == "nt") -> bool:
    """Windows: only SYSTEM and administrators may own or read the folder that will hold the CA key (a folder somebody
    else created first is emptied). Elsewhere the 0600 mode of each key file and ``_share_with_service`` apply."""
    if not windows:
        return True
    step = winsetup.secure_data_dir(directory or _tls_dir(), runner)
    if not step.ok:
        _say(step.detail)
    return step.ok


def _share_with_service(paths: list[Path]) -> None:
    """Linux: the unprivileged service user must read the certificate and key, nobody else may read the key."""
    if os.name == "nt":
        return
    try:
        import grp

        gid = grp.getgrnam(SERVICE_GROUP).gr_gid
    except (ImportError, KeyError):
        return
    for path in paths:
        try:
            os.chown(path, -1, gid)
            os.chmod(path, 0o640 if path.suffix == ".key" else 0o644)
        except OSError:
            pass


def _read_password(args: argparse.Namespace, prompt: Prompt) -> str | None:
    if args.from_file:
        source = Path(args.from_file)
        try:
            password = source.read_text(encoding="utf-8-sig").splitlines()[0]  # Inno Setup writes a BOM
        except (OSError, IndexError):
            return None
        finally:
            try:
                source.unlink()  # the installer hands the password over in a file that must not stay behind
            except OSError:
                pass
        return password
    first = prompt(text("pw_prompt"))
    if first != prompt(text("pw_confirm")):
        _say(text("pw_mismatch"))
        return None
    return first


def cmd_password(argv: list[str], prompt: Prompt) -> int:
    parser = argparse.ArgumentParser(prog="vhserver password")
    parser.add_argument("--device", metavar="KEY", help="only for this device, e.g. 346d:5678:SERIAL")
    parser.add_argument("--clear", action="store_true", help="remove the password")
    parser.add_argument("--from-file", metavar="PATH", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    target = args.device or text("pw_all_devices")
    path = config_path()
    try:
        current = load_config(path)
        if args.clear:
            changes = _device_change(current, args.device, None) if args.device else {"password_hash": None}
            update_config(path, changes)
            _say(text("pw_cleared", target=target))
            return 0
        password = _read_password(args, prompt)
        if password is None:
            return 1
        if len(password) < MIN_PASSWORD_CHARS:
            _say(text("pw_short"))
            return 1
        if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
            _say(text("pw_long"))
            return 1
        hashed = new_password_hash(password)
        changes = _device_change(current, args.device, hashed) if args.device else {"password_hash": hashed}
        update_config(path, changes)
    except (PermissionError, ConfigError) as exc:
        _say(text("no_permission") if _is_permission(exc) else text("config_error", error=exc))
        return 1
    _say(text("pw_set", target=target))
    if args.device and "@" in args.device:
        _say(text("pw_port_key"))
    _say(text("restart_hint"))
    return 0


def _is_permission(exc: BaseException) -> bool:
    return isinstance(exc, PermissionError) or isinstance(exc.__cause__, PermissionError)


def _device_change(current, key: str, hashed: str | None) -> dict:
    devices = dict(current.device_passwords)
    if hashed is None:
        devices.pop(key, None)
    else:
        devices[key] = hashed
    return {"device_passwords": devices or None}


def cmd_tls(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="vhserver tls")
    sub = parser.add_subparsers(dest="action", required=True)
    enable = sub.add_parser("enable", help="create certificates and switch the SSL port on")
    enable.add_argument("--only", action="store_true", help="also switch the plain port off")
    enable.add_argument("--with-plain", action="store_true", help="switch the plain port back on")
    enable.add_argument("--address", action="append", default=[], help="IP address to put in the certificate")
    enable.add_argument("--force", action="store_true", help="create new certificates even if they exist")
    sub.add_parser("disable", help="switch the SSL port off (certificates are kept)")
    sub.add_parser("status", help="show whether SSL is on and how long the certificate is valid")
    client = sub.add_parser("client", help="create a client certificate and require client certificates")
    client.add_argument("name")
    args = parser.parse_args(argv)
    try:
        return _tls_action(args)
    except (PermissionError, ConfigError, TlsError) as exc:
        _say(text("no_permission") if _is_permission(exc) else text("config_error", error=exc))
        return 1


def _tls_action(args: argparse.Namespace) -> int:
    path = config_path()
    config = load_config(path)
    if args.action == "status":
        return _tls_status(config)
    if args.action == "disable":
        update_config(path, {"ssl_cert": None, "ssl_key": None, "ssl_ca": None, "ssl_use_client_certs": None,
                             "allow_plaintext": None})
        _say(text("tls_disabled"))
        _say(text("restart_hint"))
        return 0
    if args.action == "client":
        return _tls_client(args, path, config)
    if not _secure_tls_dir():
        return 1
    host = socket.gethostname().split(".")[0]
    files = generate_certificates(_tls_dir(), common_name=config.name, hostnames=[host, "localhost"],
                                  addresses=args.address + ["127.0.0.1"], force=args.force)
    _share_with_service([files.server_cert, files.server_key, files.ca_cert])
    update_config(path, {"ssl_cert": str(files.server_cert), "ssl_key": str(files.server_key),
                         "ssl_ca": str(files.ca_cert), **_plain_change(args)})
    _say(text("tls_enabled", ca=files.ca_cert, port=config.ssl_port))
    if args.only:
        _say(text("tls_plain_off"))
    _say(text("restart_hint"))
    return 0


def _plain_change(args: argparse.Namespace) -> dict:
    """The plain port is only touched when asked: renewing certificates must not undo an earlier --only."""
    if args.only:
        return {"allow_plaintext": False}
    return {"allow_plaintext": None} if args.with_plain else {}


def _tls_client(args: argparse.Namespace, path: Path, config) -> int:
    if not config.ssl_cert:
        _say(text("tls_needs_enable"))
        return 1
    if not _secure_tls_dir():
        return 1
    files = generate_certificates(_tls_dir(), common_name=config.name, hostnames=[], addresses=[])  # existing ones
    cert, key = generate_client_certificate(files, _tls_dir() / "clients", common_name=args.name)
    update_config(path, {"ssl_ca": str(files.ca_cert), "ssl_use_client_certs": True})
    _say(text("tls_client_made", cert=cert, keyfile=key))
    _say(text("restart_hint"))
    return 0


def _tls_status(config) -> int:
    if not config.ssl_cert:
        _say(text("tls_status_off"))
        return 0
    info = certificate_info(Path(config.ssl_cert))
    if info is None:
        _say(text("tls_status_bad", path=config.ssl_cert))
        return 1
    _say(text("tls_status_on", days=info.days_left, port=config.ssl_port, ca=config.ssl_ca or "-"))
    return 0


def main(argv: list[str], prompt: Prompt = getpass.getpass) -> int:
    command, rest = argv[0], argv[1:]
    if command == "password":
        return cmd_password(rest, prompt)
    return cmd_tls(rest)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
