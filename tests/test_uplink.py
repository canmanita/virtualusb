import os

import pytest

from vhserver import uplink

ROUTE = (
    "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
    "eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
    "eth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
)
IPV6 = ("00000000000000000000000000000000 00 00000000000000000000000000000000 00 "
        "fe80000000000000aaaaaaaaaaaaaaaa 00000400 00000001 00000000 00000003 wlan0\n"
        "00000000000000000000000000000000 00 00000000000000000000000000000000 00 "
        "00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n"
        "fe800000000000000000000000000000 40 00000000000000000000000000000000 00 "
        "00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth9\n")


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_default_route_interfaces_from_ipv4_and_ipv6(tmp_path):
    write(tmp_path / "route", ROUTE)
    write(tmp_path / "ipv6_route", IPV6)
    found = uplink.default_route_interfaces(tmp_path / "route", tmp_path / "ipv6_route")
    assert found == {"eth0", "wlan0"}  # eth9 has a /64 prefix, not a default route


def test_missing_route_files_mean_no_uplink(tmp_path):
    assert uplink.default_route_interfaces(tmp_path / "none", tmp_path / "none6") == set()


def fake_sysfs(mapping):
    return lambda name: set(mapping.get(name, ()))


def test_device_with_the_default_route_interface_is_the_uplink(tmp_path):
    write(tmp_path / "route", ROUTE)
    sysfs = fake_sysfs({"1-1.1": {"eth0"}})  # Raspberry Pi 3 / 4 onboard Ethernet behind the hub
    check = lambda ports: uplink.carries_uplink(1, ports, interfaces_of=sysfs, route=tmp_path / "route",
                                                route6=tmp_path / "x")
    assert check([1, 1]) is True
    assert check([1, 2]) is False  # another device on the same bus


def test_usb_ethernet_that_is_not_the_default_route_may_be_shared(tmp_path):
    write(tmp_path / "route", ROUTE)
    assert uplink.carries_uplink(1, [2], interfaces_of=fake_sysfs({"1-2": {"enx0011"}}), route=tmp_path / "route",
                                 route6=tmp_path / "x") is False


def test_root_hub_paths_and_missing_sysfs_never_block(tmp_path):
    assert uplink.carries_uplink(1, [], interfaces_of=fake_sysfs({})) is False
    assert uplink.sysfs_interfaces("1-3", tmp_path / "missing") == set()


@pytest.mark.skipif(os.name == "nt", reason="sysfs directory names contain ':'")
def test_real_sysfs_layout(tmp_path):
    iface = tmp_path / "1-1.1:1.0" / "net" / "eth0"
    iface.mkdir(parents=True)
    assert uplink.sysfs_interfaces("1-1.1", tmp_path) == {"eth0"}
    assert uplink.sysfs_interfaces("1-1.2", tmp_path) == set()
