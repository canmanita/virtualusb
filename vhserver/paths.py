"""Where the server keeps its configuration, state and logs."""
from __future__ import annotations

import os
from pathlib import Path

HOME_ENV = "VHSERVER_HOME"
APP_DIR = "VHServer"
SYSTEM_DIR = Path("/etc/vhserver")  # created by the Linux package


def data_dir() -> Path:
    override = os.environ.get(HOME_ENV)
    if override:
        return Path(override)
    if os.name == "nt":
        return Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / APP_DIR
    return SYSTEM_DIR if SYSTEM_DIR.is_dir() else Path.home() / ".vhserver"


def config_path() -> Path:
    return data_dir() / "config.json"


def state_path() -> Path:
    return data_dir() / "state.json"


def state_dir() -> Path:
    """Where the server may write at run time: systemd's StateDirectory on Linux, the data folder elsewhere."""
    systemd = os.environ.get("STATE_DIRECTORY", "").split(":")[0]
    return Path(systemd) if systemd else data_dir()


def nicknames_path() -> Path:
    return state_dir() / "nicknames.json"


def log_path() -> Path:
    return data_dir() / "logs" / "vhserver.log"
