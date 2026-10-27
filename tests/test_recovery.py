from vhserver.recovery import PendingStore
from vhserver.winusb import WinUsbBinder

ID_A = "USB\\VID_0930&PID_6544\\AAA"
ID_B = "USB\\VID_346D&PID_5678\\BBB"


def test_store_persists_across_instances(tmp_path):
    path = tmp_path / "state.json"
    PendingStore(path).add(ID_A)
    store = PendingStore(path)
    store.add(ID_B)
    store.add(ID_B)  # idempotent
    assert PendingStore(path).all() == [ID_A, ID_B]
    store.remove(ID_A)
    assert PendingStore(path).all() == [ID_B]
    store.remove("never-added")  # no error


def test_corrupt_or_foreign_state_is_ignored(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("{garbage", encoding="utf-8")
    assert PendingStore(path).all() == []
    path.write_text('{"pending": ["ok", 5, null, "USB\\\\VID_0930&PID_6544\\\\AAA"]}', encoding="utf-8")
    assert PendingStore(path).all() == [ID_A]  # only USB instance ids are trusted


def test_non_usb_ids_are_never_stored(tmp_path):
    store = PendingStore(tmp_path / "state.json")
    store.add("ROOT\\SOMETHING\\0000")
    store.add("")
    assert store.all() == []


class Api:
    def __init__(self, service="USBSTOR", ids=(ID_A,)):
        self.service, self.ids = service, ids

    def usb_nodes(self):
        from vhserver.winusb import UsbNode
        return [UsbNode(i, 0x0930, 0x6544, i.rsplit("\\", 1)[1], self.service, 9) for i in self.ids]

    def install_winusb(self, instance_id):
        pass


class Pnputil:
    """Records pnputil calls; ``fail_remove`` makes /remove-device fail."""
    def __init__(self, fail_remove=False):
        self.calls, self.fail_remove = [], fail_remove

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        code = 1 if self.fail_remove and cmd[1] == "/remove-device" else 0
        return type("R", (), {"returncode": code, "stdout": ""})()


def make_binder(store, monkeypatch, api=None, pnputil=None):
    binder = WinUsbBinder.__new__(WinUsbBinder)
    binder._api, binder._store = api or Api(), store
    monkeypatch.setattr(WinUsbBinder, "is_admin", staticmethod(lambda: True))
    monkeypatch.setattr("vhserver.winusb.subprocess.run", pnputil or Pnputil())
    return binder


def test_binder_records_the_switch_and_forgets_it_after_restore(tmp_path, monkeypatch):
    store = PendingStore(tmp_path / "state.json")
    pnputil = Pnputil()
    binder = make_binder(store, monkeypatch, pnputil=pnputil)
    assert binder.prepare(0x0930, 0x6544, "AAA", 9) == ID_A
    assert store.all() == [ID_A]  # survives a crash of the server
    assert binder.restore(ID_A) is True
    assert store.all() == [] and ["pnputil", "/remove-device", ID_A] in pnputil.calls


def test_failed_removal_keeps_the_record_for_the_next_attempt(tmp_path, monkeypatch):
    store = PendingStore(tmp_path / "state.json")
    store.add(ID_A)
    binder = make_binder(store, monkeypatch, pnputil=Pnputil(fail_remove=True))
    assert binder.restore(ID_A) is False
    assert store.all() == [ID_A]


def test_recover_pending_restores_devices_still_on_winusb(tmp_path, monkeypatch):
    store = PendingStore(tmp_path / "state.json")
    store.add(ID_A)
    store.add(ID_B)
    binder = make_binder(store, monkeypatch, api=Api(service="WinUSB", ids=(ID_A, ID_B)))
    assert binder.recover_pending() == [ID_A, ID_B]
    assert store.all() == []


def test_recover_pending_ignores_devices_not_on_winusb(tmp_path, monkeypatch):
    """A tampered state file must not make the server remove a healthy device."""
    store = PendingStore(tmp_path / "state.json")
    store.add(ID_A)   # present but owned by usbstor: leave alone
    store.add(ID_B)   # not present at all
    pnputil = Pnputil()
    binder = make_binder(store, monkeypatch, api=Api(service="USBSTOR", ids=(ID_A,)), pnputil=pnputil)
    assert binder.recover_pending() == []
    assert store.all() == [] and pnputil.calls == []


def test_failed_recovery_is_retried_later(tmp_path, monkeypatch):
    store = PendingStore(tmp_path / "state.json")
    store.add(ID_A)
    binder = make_binder(store, monkeypatch, api=Api(service="WinUSB"), pnputil=Pnputil(fail_remove=True))
    assert binder.recover_pending() == [] and store.all() == [ID_A]


def test_non_list_pending_value_is_ignored(tmp_path):
    path = tmp_path / "state.json"
    for payload in ('{"pending": 5}', '{"pending": null}', "[1, 2]", '{"pending": {"a": 1}}'):
        path.write_text(payload, encoding="utf-8")
        assert PendingStore(path).all() == []
