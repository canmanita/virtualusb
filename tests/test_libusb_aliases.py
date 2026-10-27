"""One physical device may be reported under several libusb keys while its driver is being switched."""
from test_libusb_scan_and_cli import FakeDev, make_backend
from vhserver import libusb_backend as lb


def scan(backend, devices, events):
    backend._ctx.devices = devices
    backend._scan(lambda kind, info: events.append((kind, info.device_id)))


def test_a_new_key_during_the_switch_window_is_the_same_device_even_if_the_old_key_is_still_listed():
    backend, events = make_backend(), []
    old = FakeDev(ports=(9,))
    scan(backend, [old], events)
    device_id = events[0][1]
    backend._note_switch(0x1234, 0x5678)                       # the driver of this device is being switched
    new = FakeDev(ports=(1,), address=7)
    scan(backend, [old, new], events)                          # both listed: libusb keeps the stale node while it is open
    assert events == [("add", device_id)]
    assert sorted(backend._keys.values()) == [device_id, device_id]
    assert backend._devices[device_id] is new                  # open() gets the newest object


def test_the_device_survives_the_old_key_disappearing_and_goes_only_when_every_key_is_gone():
    backend, events = make_backend(), []
    old, new = FakeDev(ports=(9,)), FakeDev(ports=(1,), address=7)
    scan(backend, [old], events)
    device_id = events[0][1]
    backend._note_switch(0x1234, 0x5678)
    scan(backend, [old, new], events)
    for _ in range(lb.GRACE_SCANS + 3):
        scan(backend, [new], events)
    assert events == [("add", device_id)] and list(backend._keys.values()) == [device_id]
    for _ in range(lb.GRACE_SCANS):
        scan(backend, [], events)
    assert events == [("add", device_id), ("remove", device_id)]


def test_outside_the_switch_window_a_second_identical_stick_is_a_new_device():
    backend, events = make_backend(), []
    scan(backend, [FakeDev(ports=(9,))], events)
    scan(backend, [FakeDev(ports=(9,)), FakeDev(ports=(1,), address=7)], events)
    assert [kind for kind, _ in events] == ["add", "add"]


def test_the_window_expires(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(lb.time, "monotonic", lambda: now[0])
    backend, events = make_backend(), []
    scan(backend, [FakeDev(ports=(9,))], events)
    backend._note_switch(0x1234, 0x5678)
    now[0] += lb.SWITCH_WINDOW_S + 1
    scan(backend, [FakeDev(ports=(9,)), FakeDev(ports=(1,), address=7)], events)
    assert [kind for kind, _ in events] == ["add", "add"]


def test_two_known_devices_with_the_same_ids_are_never_merged():
    backend, events = make_backend(), []
    scan(backend, [FakeDev(ports=(1,)), FakeDev(ports=(2,), address=3)], events)
    backend._note_switch(0x1234, 0x5678)
    scan(backend, [FakeDev(ports=(1,)), FakeDev(ports=(2,), address=3), FakeDev(ports=(3,), address=4)], events)
    assert [kind for kind, _ in events] == ["add", "add", "add"]


def test_rediscover_accepts_the_device_under_a_different_key_and_remembers_it(monkeypatch):
    monkeypatch.setattr(lb.time, "sleep", lambda s: None)
    backend, events = make_backend(), []
    scan(backend, [FakeDev(ports=(9,))], events)
    device_id = events[0][1]
    old_key = backend._key_of(device_id)
    moved = FakeDev(ports=(1,), address=7)
    backend._ctx.devices = [moved]                              # the old key is gone, the device is listed elsewhere
    assert backend._rediscover(old_key) is moved
    assert backend._keys[backend._key(moved)] == device_id


def test_rediscover_does_not_steal_another_known_device(monkeypatch):
    monkeypatch.setattr(lb.time, "sleep", lambda s: None)
    monkeypatch.setattr(lb, "REDISCOVER_TIMEOUT_S", 0.05)
    backend, events = make_backend(), []
    scan(backend, [FakeDev(ports=(9,)), FakeDev(ports=(8,), address=3)], events)
    first_key = backend._key_of(events[0][1])
    other = FakeDev(ports=(8,), address=3)                       # belongs to the second device, not to the first
    backend._ctx.devices = [other]
    import pytest
    with pytest.raises(OSError):
        backend._rediscover(first_key)


def test_open_and_close_with_a_driver_switch_open_the_window(monkeypatch):
    from test_libusb_scan_and_cli import FakeBinder, scan_once_added
    binder = FakeBinder()
    backend = make_backend(binder=binder)
    dev = FakeDev()
    info = scan_once_added(backend, dev)
    backend._rediscover = lambda key: dev
    handle = backend.open(info.device_id)
    assert backend._in_switch_window(0x1234, 0x5678)
    backend._switch_until.clear()
    handle.close()                                              # the restore flips the port path back as well
    assert backend._in_switch_window(0x1234, 0x5678)


def test_every_listed_device_is_kept_alive_by_the_backend():
    backend = make_backend()
    scan(backend, [FakeDev(ports=(9,)), FakeDev(ports=(2,), address=3)], [])
    assert backend._keepalive.size() == 2
    scan(backend, [FakeDev(ports=(9,))], [])
    assert backend._keepalive.size() == 3
