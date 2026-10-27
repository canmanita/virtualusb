"""Found testing a real USB stick: a quick unplug/replug within the grace period leaves a stale libusb
device wrapper that, when finally dropped by DeviceKeepalive up to 60s later, can hit an already-torn-down
native structure on Windows. ctypes converts the resulting access violation into an OSError raised from
CPython's weakref finalizer machinery (sys.unraisablehook), which we can't try/except around -- so this is
filtered at the hook instead. Only that exact, known-benign shape is filtered; everything else still gets
the default (visible) traceback, since a different unraisable exception could be a real new problem."""
import sys
from types import SimpleNamespace

import vhserver.libusb_backend as lb


def _traceback(filename: str, inner_filename: str | None = None):
    """A minimal fake traceback: one frame at `filename`, chained to one at `inner_filename` if given."""
    inner = None
    if inner_filename is not None:
        inner = SimpleNamespace(tb_frame=SimpleNamespace(f_code=SimpleNamespace(co_filename=inner_filename)),
                                 tb_next=None)
    return SimpleNamespace(tb_frame=SimpleNamespace(f_code=SimpleNamespace(co_filename=filename)), tb_next=inner)


def _args(exc_type, exc_value, tb):
    return SimpleNamespace(exc_type=exc_type, exc_value=exc_value, exc_traceback=tb, err_msg=None, object=None)


def test_the_known_benign_access_violation_is_filtered(monkeypatch, caplog):
    calls = []
    monkeypatch.setattr(sys, "unraisablehook", lambda args: calls.append(args))
    lb._install_unraisable_filter()  # wraps whatever monkeypatch just set as the "default"

    usb1_path = f"C:{lb.os.sep}site-packages{lb.os.sep}usb1{lb.os.sep}__init__.py"
    tb = _traceback("weakref.py", usb1_path)
    args = _args(OSError, OSError("exception: access violation writing 0x0000000000000000"), tb)

    import logging
    with caplog.at_level(logging.WARNING, logger="vhserver.libusb"):
        sys.unraisablehook(args)

    assert calls == []  # never reached the real default hook
    assert any("harmless" in r.message for r in caplog.records)


def test_the_bare_frozen_build_path_is_also_filtered(monkeypatch, caplog):
    """A PyInstaller-frozen vhserver.exe reports frames as a bare "usb1\\__init__.py" with no directory in
    front of it (a synthetic path, not a real filesystem one) -- this exact case is what slipped through
    live testing of the real packaged installer: the first version of this filter required a path
    separator before "usb1", which a leading component never has."""
    calls = []
    monkeypatch.setattr(sys, "unraisablehook", lambda args: calls.append(args))
    lb._install_unraisable_filter()

    bare_path = f"usb1{lb.os.sep}__init__.py"
    tb = _traceback("weakref.py", bare_path)
    args = _args(OSError, OSError("exception: access violation writing 0x0000000000000000"), tb)

    import logging
    with caplog.at_level(logging.WARNING, logger="vhserver.libusb"):
        sys.unraisablehook(args)

    assert calls == []
    assert any("harmless" in r.message for r in caplog.records)


def test_a_different_exception_still_reaches_the_default_hook(monkeypatch):
    calls = []
    monkeypatch.setattr(sys, "unraisablehook", lambda args: calls.append(args))
    lb._install_unraisable_filter()

    tb = _traceback("weakref.py", "some_other_module.py")
    args = _args(ValueError, ValueError("something unrelated"), tb)
    sys.unraisablehook(args)

    assert calls == [args]  # passed straight through, unfiltered


def test_an_access_violation_outside_usb1_still_reaches_the_default_hook(monkeypatch):
    """Same exception type and message, but not actually inside usb1's close/finalize path -- must not be
    silently swallowed just because the text happens to match."""
    calls = []
    monkeypatch.setattr(sys, "unraisablehook", lambda args: calls.append(args))
    lb._install_unraisable_filter()

    tb = _traceback("weakref.py", "unrelated_module.py")
    args = _args(OSError, OSError("exception: access violation writing 0x0000000000000000"), tb)
    sys.unraisablehook(args)

    assert calls == [args]
