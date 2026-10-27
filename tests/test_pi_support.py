"""Raspberry Pi / Debian 12 support: old zeroconf (0.47), password diagnostics, Linux doctor checks."""
import asyncio

import pytest

from test_doctor_linux import Probe
from vhserver import discovery, doctor
from vhserver import protocol as proto


def test_a_zeroconf_without_strict_gets_a_relaxed_name_check_only_while_registering(monkeypatch):
    import sys
    import types

    def strict_checker(type_, *, strict=True):  # what zeroconf 0.47 does with the service type
        if strict and "_ssl_" in type_:
            raise ValueError("Service name (ssl_vhusb) must contain only these characters")
        return type_

    fake = types.ModuleType("fake_zc_names")
    fake.service_type_name = strict_checker
    monkeypatch.setitem(sys.modules, "fake_zc_names", fake)
    monkeypatch.setattr(discovery, "_NAME_CHECKERS", ("fake_zc_names",))
    seen = []

    class LegacyZeroconf:  # the shape of zeroconf 0.47: no `strict` argument
        def __init__(self, **kwargs):
            pass

        async def async_register_service(self, info, ttl=None, allow_name_change=False, cooperating_responders=False):
            seen.append(fake.service_type_name("Hub (SSL)._ssl_vhusb._tcp.local."))  # raises when strict

        async def async_unregister_service(self, info):
            pass

        async def async_close(self):
            pass

    async def scenario():
        d = discovery.Discovery("S", 7575, ssl_port=7574, address_provider=lambda: ["10.0.0.7"],
                                zeroconf_factory=LegacyZeroconf, interval=60)
        await d.start()
        types_ = [i.type for i in d._infos]
        await d.stop()
        return types_

    assert asyncio.run(scenario()) == ["_vhusb._tcp.local.", "_ssl_vhusb._tcp.local."]
    assert len(seen) == 2
    assert fake.service_type_name is strict_checker  # restored for everybody else
    with pytest.raises(ValueError):
        fake.service_type_name("Hub (SSL)._ssl_vhusb._tcp.local.")


def test_accepts_strict_detects_the_argument():
    class New:
        async def async_register_service(self, info, allow_name_change=False, strict=True):
            pass

    class Old:
        async def async_register_service(self, info, ttl=None, allow_name_change=False, cooperating_responders=False):
            pass

    assert discovery._accepts_strict(New()) is True and discovery._accepts_strict(Old()) is False


@pytest.mark.parametrize("payload,expected", [
    (b"4df1d2daca5cf1cecfc38992860fd230", "32 bytes (32 hex digits, lower case)"),
    (b"4DF1D2DACA5CF1CECFC38992860FD230", "32 bytes (32 hex digits, upper case)"),
    (b"4Df1d2daca5cf1cecfc38992860fd230", "32 bytes (32 hex digits, mixed case)"),
    (b"hunter22hunter", "14 bytes (other)"),
    (b"", "0 bytes (other)"),
])
def test_password_diagnostics_describe_the_shape_without_the_value(payload, expected):
    described = proto.describe_password_payload(payload)
    assert described == expected and payload.decode() not in described or payload == b""


def test_the_server_logs_the_shape_of_a_password_message_but_never_its_value(caplog):
    import logging

    from test_access_control import Session, run, set_password

    async def scenario():
        async with Session() as s:
            await set_password(await s.client(), "correct horse battery")

    with caplog.at_level(logging.DEBUG, logger="vhserver"):
        run(scenario())
    lines = [r.getMessage() for r in caplog.records if "password message" in r.getMessage()]
    assert lines and "32 hex digits, lower case" in lines[0]
    assert "correct horse" not in " ".join(r.getMessage() for r in caplog.records)


class RootProbe(Probe):
    usb_acl = True

    def usb_access(self):
        return self.usb_acl


def checks_of(probe):
    return {c.key: c for c in doctor.run_linux_checks(probe)}


def test_service_user_without_write_access_to_plugged_devices_is_reported(monkeypatch):
    monkeypatch.setenv("VHSERVER_LANG", "en")
    probe = RootProbe()
    probe.usb_acl = False
    check = checks_of(probe)["usb_acl"]
    assert check.status == "fail" and "udevadm trigger" in check.fix
    probe.usb_acl = True
    assert "usb_acl" not in checks_of(probe)


def test_another_program_on_the_port_is_reported_as_a_conflict(monkeypatch):
    monkeypatch.setenv("VHSERVER_LANG", "en")
    probe = Probe()
    probe.service = False       # our service is not running...
    probe.listening = True      # ...but something answers on the port: another USB-over-network server
    check = checks_of(probe)["conflict"]
    assert check.status == "warn" and "another port" in check.fix
    probe.service = True
    assert "conflict" not in checks_of(probe)


def test_probes_that_cannot_test_usb_access_just_skip_it():
    assert "usb_acl" not in checks_of(Probe())


def test_the_shipped_example_configuration_is_valid():
    from pathlib import Path

    from vhserver.config import load_config

    config = load_config(Path(__file__).resolve().parent.parent / "docs" / "config.example.json")
    assert config.port == 7575 and config.ssl_port == 7574 and config.ignore == ((0x0529, 0x0003),)
