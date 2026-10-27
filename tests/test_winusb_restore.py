"""Restore like the stock server: null driver, then the best driver, on the same device node (no remove-device)."""
import pytest

from vhserver.recovery import PendingStore
from vhserver.winusb import WinUsbBinder, WinUsbError

BS = chr(92)
ID = "USB" + BS + "VID_0930&PID_6544" + BS + "AAA"


class Api:
    def __init__(self, fail_on=None):
        self.calls, self.fail_on = [], fail_on

    def install_best_driver(self, instance_id, null_driver=False):
        self.calls.append((instance_id, null_driver))
        if self.fail_on is not None and null_driver == self.fail_on:
            raise WinUsbError("DiInstallDevice failed")


class Run:
    def __init__(self, fail_remove=False):
        self.calls, self.fail_remove = [], fail_remove

    def __call__(self, cmd, **kwargs):
        self.calls.append(cmd)
        code = 1 if self.fail_remove and cmd[1] == "/remove-device" else 0
        return type("R", (), {"returncode": code, "stdout": ""})()


def make(monkeypatch, tmp_path, api, run):
    binder = WinUsbBinder.__new__(WinUsbBinder)
    binder._api, binder._store = api, PendingStore(tmp_path / "state.json")
    binder._store.add(ID)
    monkeypatch.setattr("vhserver.winusb.subprocess.run", run)
    monkeypatch.setattr("vhserver.winusb.time.sleep", lambda s: None)
    return binder


def test_restore_reinstalls_the_best_driver_on_the_same_node_without_removing_it(monkeypatch, tmp_path):
    api, run = Api(), Run()
    binder = make(monkeypatch, tmp_path, api, run)
    assert binder.restore(ID) is True
    assert api.calls == [(ID, True), (ID, False)]       # null driver first, then the best match
    assert run.calls == [] and binder._store.all() == []  # no pnputil, so no ghost device nodes


@pytest.mark.parametrize("failing_step", [True, False])
def test_if_the_driver_reinstall_fails_it_falls_back_to_remove_and_rescan(monkeypatch, tmp_path, failing_step):
    api, run = Api(fail_on=failing_step), Run()
    binder = make(monkeypatch, tmp_path, api, run)
    assert binder.restore(ID) is True
    assert run.calls == [["pnputil", "/remove-device", ID], ["pnputil", "/scan-devices"]]
    assert binder._store.all() == []


def test_the_record_stays_when_both_ways_fail(monkeypatch, tmp_path):
    binder = make(monkeypatch, tmp_path, Api(fail_on=True), Run(fail_remove=True))
    assert binder.restore(ID) is False
    assert binder._store.all() == [ID]
