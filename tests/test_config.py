import json

import pytest

from vhserver.config import ConfigError, ServerConfig, load_config, update_config
from vhserver.paths import data_dir
from vhserver.security import new_password_hash


def write(tmp_path, payload):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_missing_file_gives_defaults(tmp_path):
    config = load_config(tmp_path / "absent.json")
    assert config == ServerConfig()
    assert config.port == 7575 and config.mdns and not config.share_input


def test_valid_file_overrides_defaults(tmp_path):
    path = write(tmp_path, {"name": "Lab", "port": 7600, "allow": ["10.0.0.0/8"], "ignore": ["1d6b:0002"],
                            "share_input": True, "windows_bind": True})
    config = load_config(path)
    assert (config.name, config.port, config.allow, config.share_input, config.windows_bind) == \
        ("Lab", 7600, ("10.0.0.0/8",), True, True)
    assert config.ignore == ((0x1D6B, 0x0002),)


@pytest.mark.parametrize("payload", [
    {"prot": 7575},                       # unknown key: a typo must not be silently ignored
    {"port": 0},
    {"port": "7575"},
    {"name": ""},
    {"name": "x" * 65},
    {"name": "é" * 33},                   # 66 bytes in UTF-8: the protocol field is 64 bytes
    {"allow": ["not-a-network"]},
    {"allow": "10.0.0.0/8"},
    {"ignore": ["zzzz:0002"]},
    {"share_input": "yes"},
    {"bind": "999.1.1.1"},
])
def test_invalid_values_are_rejected(tmp_path, payload):
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, payload))


def test_broken_json_is_rejected(tmp_path):
    path = tmp_path / "config.json"
    path.write_text("{oops", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


def test_cli_defaults_mirror_the_config(tmp_path):
    config = load_config(write(tmp_path, {"name": "Lab", "mdns": False}))
    defaults = config.cli_defaults()
    assert defaults["name"] == "Lab" and defaults["no_mdns"] is True
    assert "allow" not in defaults and "ignore" not in defaults


def test_command_line_lists_replace_the_file_lists(tmp_path):
    from vhserver.__main__ import parse_args

    path = write(tmp_path, {"allow": ["10.0.0.0/8"], "ignore": ["1d6b:0002"]})
    from_file = parse_args(["--config", str(path)])
    assert from_file.allow == ["10.0.0.0/8"] and from_file.ignore == [(0x1D6B, 0x0002)]
    override = parse_args(["--config", str(path), "--allow", "192.168.0.0/24", "--ignore", "046d:c07e"])
    assert override.allow == ["192.168.0.0/24"] and override.ignore == [(0x046D, 0xC07E)]


def test_data_dir_honours_override(monkeypatch, tmp_path):
    monkeypatch.setenv("VHSERVER_HOME", str(tmp_path))
    assert data_dir() == tmp_path


def test_security_settings_are_read(tmp_path):
    hashed = new_password_hash("pw")
    config = load_config(write(tmp_path, {
        "password_hash": hashed, "device_passwords": {"346d:5678:SER": hashed}, "allow_rename": False,
        "ssl_cert": "c.pem", "ssl_key": "k.pem", "ssl_ca": "ca.pem", "ssl_port": 7600,
        "ssl_use_client_certs": True, "allow_plaintext": False}))
    assert config.password_hash == hashed and config.device_passwords == (("346d:5678:SER", hashed),)
    assert (config.allow_rename, config.ssl_port, config.ssl_use_client_certs, config.allow_plaintext) ==         (False, 7600, True, False)


@pytest.mark.parametrize("payload", [
    {"password_hash": "hunter2"},                       # a clear password is never accepted in the file
    {"device_passwords": {"k": "hunter2"}},
    {"device_passwords": ["k"]},
    {"ssl_port": 0},
    {"ssl_cert": "c.pem"},                              # certificate without key
    {"ssl_port": 7575, "ssl_cert": "c", "ssl_key": "k"},  # same as the plain port
    {"allow_plaintext": False},                         # nothing left to listen on
    {"ssl_use_client_certs": True, "ssl_cert": "c", "ssl_key": "k"},   # nothing to verify them with
])
def test_inconsistent_security_settings_are_rejected(tmp_path, payload):
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, payload))


def test_update_config_merges_validates_and_writes(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"name": "Lab"}), encoding="utf-8")
    config = update_config(path, {"password_hash": new_password_hash("pw")})
    assert config.name == "Lab" and config.password_hash
    assert json.loads(path.read_text(encoding="utf-8"))["name"] == "Lab"
    update_config(path, {"password_hash": None})            # None removes the key
    assert "password_hash" not in json.loads(path.read_text(encoding="utf-8"))


def test_update_config_refuses_bad_changes_without_touching_the_file(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"name": "Lab"}), encoding="utf-8")
    with pytest.raises(ConfigError):
        update_config(path, {"password_hash": "plain"})
    with pytest.raises(ConfigError):
        update_config(path, {"nope": 1})
    assert json.loads(path.read_text(encoding="utf-8")) == {"name": "Lab"}


def test_update_config_creates_a_missing_file(tmp_path):
    path = tmp_path / "sub" / "config.json"
    assert update_config(path, {"name": "New"}).name == "New" and path.exists()
