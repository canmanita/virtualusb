"""libusb device wrappers must never be freed on the event loop thread: the native unref can block on Windows."""
import gc
import threading
import weakref

from vhserver.keepalive import DeviceKeepalive


class Dev:
    freed_on = []

    def __del__(self):
        Dev.freed_on.append(threading.current_thread().name)


class Clock:
    now = 100.0

    def __call__(self):
        return self.now


def test_held_devices_survive_the_caller_dropping_them_and_are_freed_only_by_release():
    Dev.freed_on.clear()
    clock = Clock()
    keep = DeviceKeepalive(keep_s=60, clock=clock)
    device = Dev()
    probe = weakref.ref(device)
    keep.hold([device])
    del device                      # the loop thread lets go of its reference...
    gc.collect()
    assert probe() is not None and Dev.freed_on == []   # ...but nothing is freed there

    clock.now += 59
    assert keep.release_old() == 0
    clock.now += 2
    worker = threading.Thread(target=keep.release_old, name="usb-poll-test")
    worker.start()
    worker.join()
    assert Dev.freed_on == ["usb-poll-test"]            # freed on the thread that is allowed to block


def test_the_box_is_bounded():
    keep = DeviceKeepalive(keep_s=3600, clock=Clock(), max_items=10)
    keep.hold([Dev() for _ in range(25)])
    assert keep.release_old() == 15 and keep.size() == 10


def test_holding_nothing_is_fine():
    keep = DeviceKeepalive()
    keep.hold([])
    assert keep.release_old() == 0 and keep.size() == 0
