"""Server configuration file (JSON). Command line options override it; unknown keys are rejected so typos show up."""
from __future__ import annotations

import ipaddress
import json
import os
import shutil
import socket
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_PORT = 7575
DEFAULT_SSL_PORT = 7574
MAX_NAME_BYTES = 64  # the protocol carries the server name in a 64 byte UTF-8 field


class ConfigError(ValueError):
    pass


def parse_vid_pid(text: str) -> tuple[int, int]:
    vid, pid = text.split(":")
    return int(vid, 16), int(pid, 16)


def valid_name(name: object) -> bool:
    return isinstance(name, str) and 0 < len(name.encode("utf-8")) <= MAX_NAME_BYTES


def default_name() -> str:
    host = socket.gethostname().split(".")[0].encode("utf-8")[:MAX_NAME_BYTES].decode("utf-8", errors="ignore")
    return host or "VH Clone"


@dataclass(frozen=True)
class ServerConfig:
    name: str = field(default_factory=default_name)
    port: int = DEFAULT_PORT
    bind: str = "0.0.0.0"
    allow: tuple[str, ...] = ()
    ignore: tuple[tuple[int, int], ...] = ()
    share_hubs: bool = False
    share_input: bool = False
    windows_bind: bool = False
    mdns: bool = True
    allow_rename: bool = True
    password_hash: str = ""                               # hash made by `vhserver password`, never the password
    device_passwords: tuple[tuple[str, str], ...] = ()     # (device key, hash) pairs, they win over password_hash
    ssl_cert: str = ""
    ssl_key: str = ""
    ssl_ca: str = ""
    ssl_port: int = DEFAULT_SSL_PORT
    ssl_use_client_certs: bool = False
    allow_plaintext: bool = True

    def cli_defaults(self) -> dict:
        """Scalar values for ``argparse.set_defaults``; the list options (allow, ignore) are merged by the caller so
        that giving one on the command line replaces the file's list instead of extending it."""
        return {"name": self.name, "port": self.port, "bind": self.bind, "share_hubs": self.share_hubs,
                "share_input": self.share_input, "windows_bind": self.windows_bind, "no_mdns": not self.mdns}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ConfigError(message)


def _string_list(key: str, value) -> list[str]:
    _require(isinstance(value, list) and all(isinstance(item, str) for item in value), f"'{key}' must be a list of strings")
    return value


def _check(key: str, value) -> object:
    if key == "name":
        _require(valid_name(value), f"'name' must be 1-{MAX_NAME_BYTES} bytes of UTF-8")
        return value
    if key == "port":
        _require(type(value) is int and 0 < value < 65536, "'port' must be an integer between 1 and 65535")
        return value
    if key == "bind":
        _require(isinstance(value, str), "'bind' must be a string")
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ConfigError(f"'bind' is not an IP address: {value}") from exc
        return value
    if key == "allow":
        networks = _string_list(key, value)
        for item in networks:
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError as exc:
                raise ConfigError(f"'allow' entry is not a network: {item}") from exc
        return tuple(networks)
    if key == "ignore":
        pairs = []
        for item in _string_list(key, value):
            try:
                pairs.append(parse_vid_pid(item))
            except ValueError as exc:
                raise ConfigError(f"'ignore' entry must look like 1d6b:0002, got {item}") from exc
        return tuple(pairs)
    if key == "password_hash":
        _require(isinstance(value, str) and (value == "" or _looks_like_hash(value)),
                 "'password_hash' must be a hash made by 'vhserver password'")
        return value
    if key == "device_passwords":
        _require(isinstance(value, dict) and all(isinstance(k, str) and isinstance(v, str) and _looks_like_hash(v)
                                                 for k, v in value.items()),
                 "'device_passwords' must map device keys to hashes made by 'vhserver password --device'")
        return tuple(sorted(value.items()))
    if key in ("ssl_cert", "ssl_key", "ssl_ca"):
        _require(isinstance(value, str), f"'{key}' must be a file path")
        return value
    if key == "ssl_port":
        _require(type(value) is int and 0 < value < 65536, "'ssl_port' must be an integer between 1 and 65535")
        return value
    _require(isinstance(value, bool), f"'{key}' must be true or false")
    return value


def _looks_like_hash(value: str) -> bool:
    return value.startswith("scrypt$") and value.count("$") == 5


_KEYS = frozenset(ServerConfig.__dataclass_fields__)


def load_config(path: Path) -> ServerConfig:
    """Read the file at ``path``; a missing file means defaults, a damaged one is an error (never guessed)."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ServerConfig()
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path} is not valid JSON: {exc}") from exc
    _require(isinstance(raw, dict), f"{path} must contain a JSON object")
    unknown = sorted(set(raw) - _KEYS)
    _require(not unknown, f"unknown setting(s) in {path}: {', '.join(unknown)}")
    return _build(raw, path)


def _build(raw: dict, source) -> ServerConfig:
    config = ServerConfig(**{key: _check(key, value) for key, value in raw.items()})
    _require(not config.ssl_cert or config.ssl_port != config.port, f"'ssl_port' and 'port' must differ in {source}")
    _require(bool(config.ssl_cert) == bool(config.ssl_key), f"'ssl_cert' and 'ssl_key' go together in {source}")
    _require(config.ssl_cert or config.allow_plaintext, f"'allow_plaintext' cannot be false without 'ssl_cert' in {source}")
    _require(config.ssl_ca or not config.ssl_use_client_certs, f"'ssl_use_client_certs' needs 'ssl_ca' in {source}")
    return config


def update_config(path: Path, changes: dict) -> ServerConfig:
    """Change settings in the file (``None`` removes a key). The result is validated before anything is written."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except (OSError, ValueError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    _require(isinstance(raw, dict), f"{path} must contain a JSON object")
    merged = {**raw, **changes}
    merged = {key: value for key, value in merged.items() if value is not None}
    config = _build_checked(merged, path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_suffix(".tmp")
        temp.write_text(json.dumps(merged, indent=2), encoding="utf-8")
        _keep_permissions(path, temp)
        os.replace(temp, path)
    except OSError as exc:
        raise ConfigError(f"cannot write {path}: {exc}") from exc
    return config


def _keep_permissions(old: Path, new: Path) -> None:
    """The file holds password hashes: a rewrite must not loosen its mode or change its owner/group."""
    if not old.exists():
        return
    shutil.copymode(old, new)
    if os.name != "nt":
        info = old.stat()
        try:
            os.chown(new, info.st_uid, info.st_gid)
        except PermissionError:
            pass  # not root: the new file simply belongs to the caller


def _build_checked(raw: dict, source) -> ServerConfig:
    unknown = sorted(set(raw) - _KEYS)
    _require(not unknown, f"unknown setting(s): {', '.join(unknown)}")
    return _build(raw, source)
