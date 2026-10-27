from vhserver import linuxnames


def _make_node(root, bus, ports, vid=0x0930, pid=0x6544, vendor="Kingston", product="DataTraveler 2.0",
                serial="1C1B0DDB0889C3703912302E"):
    node = root / f"{bus}-{'.'.join(str(p) for p in ports)}"
    node.mkdir(parents=True)
    (node / "idVendor").write_text(f"{vid:04x}\n")
    (node / "idProduct").write_text(f"{pid:04x}\n")
    (node / "manufacturer").write_text(f"{vendor}\n")
    (node / "product").write_text(f"{product}\n")
    (node / "serial").write_text(f"{serial}\n")
    return node


def test_names_come_from_the_exact_bus_port_path(tmp_path):
    _make_node(tmp_path, bus=2, ports=(3, 1))
    names = linuxnames.lookup(0x0930, 0x6544, bus=2, ports=(3, 1), root=tmp_path)
    assert names == linuxnames.DeviceNames("Kingston", "DataTraveler 2.0", "1C1B0DDB0889C3703912302E")


def test_a_different_device_now_at_the_same_port_is_not_misattributed(tmp_path):
    """The port that used to hold our device now holds something else (VID:PID mismatch) -- must not hand
    out that other device's name under our device's identity, or the other way around."""
    _make_node(tmp_path, bus=2, ports=(3, 1), vid=0x1111, pid=0x2222, vendor="Other", product="Other Stick")
    names = linuxnames.lookup(0x0930, 0x6544, bus=2, ports=(3, 1), root=tmp_path)
    assert names is None


def test_missing_sysfs_node_gives_nothing(tmp_path):
    assert linuxnames.lookup(0x0930, 0x6544, bus=2, ports=(3, 1), root=tmp_path) is None


def test_no_bus_or_ports_gives_nothing(tmp_path):
    assert linuxnames.lookup(0x0930, 0x6544, bus=None, ports=(3, 1), root=tmp_path) is None
    assert linuxnames.lookup(0x0930, 0x6544, bus=2, ports=(), root=tmp_path) is None


def test_node_with_no_strings_at_all_gives_nothing(tmp_path):
    node = tmp_path / "2-3.1"
    node.mkdir(parents=True)
    (node / "idVendor").write_text("0930\n")
    (node / "idProduct").write_text("6544\n")
    assert linuxnames.lookup(0x0930, 0x6544, bus=2, ports=(3, 1), root=tmp_path) is None


def test_partial_strings_are_still_returned(tmp_path):
    node = tmp_path / "2-3.1"
    node.mkdir(parents=True)
    (node / "idVendor").write_text("0930\n")
    (node / "idProduct").write_text("6544\n")
    (node / "product").write_text("Just A Product Name\n")
    names = linuxnames.lookup(0x0930, 0x6544, bus=2, ports=(3, 1), root=tmp_path)
    assert names == linuxnames.DeviceNames("", "Just A Product Name", "")
