import os

import pytest

from vhserver import winnames

USB = "SYSTEM\\CurrentControlSet\\Enum\\USB"
STOR = "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR"


class FakeRegistry:
    def __init__(self, tree):
        self.tree = tree

    def subkeys(self, path):
        return list(self.tree.get(path, []))


KINGSTON = FakeRegistry({
    f"{USB}\\VID_0930&PID_6544": ["1C1B0DDB0889C3703912302E"],
    STOR: ["Disk&Ven_Kingston&Prod_DataTraveler_2.0&Rev_1.00"],
    f"{STOR}\\Disk&Ven_Kingston&Prod_DataTraveler_2.0&Rev_1.00": ["1C1B0DDB0889C3703912302E&0"],
})


def test_vendor_product_and_serial_come_from_the_registry():
    names = winnames.lookup(0x0930, 0x6544, KINGSTON)
    assert names == winnames.StorageNames("Kingston", "DataTraveler 2.0", "1C1B0DDB0889C3703912302E")


def test_generated_instance_ids_do_not_become_serials():
    registry = FakeRegistry({
        f"{USB}\\VID_0930&PID_6544": ["5&2d6b8c1&0&4"],
        STOR: ["Disk&Ven_Generic&Prod_Flash_Disk&Rev_8.07"],
        f"{STOR}\\Disk&Ven_Generic&Prod_Flash_Disk&Rev_8.07": ["5&2d6b8c1&0&4&0"],
    })
    names = winnames.lookup(0x0930, 0x6544, registry)
    assert names == winnames.StorageNames("Generic", "Flash Disk", "")


def test_two_identical_devices_are_ambiguous_and_give_nothing():
    registry = FakeRegistry({f"{USB}\\VID_0930&PID_6544": ["AAA", "BBB"], STOR: []})
    assert winnames.lookup(0x0930, 0x6544, registry) is None


def test_two_genuinely_different_products_sharing_a_vid_pid_are_ambiguous():
    registry = FakeRegistry({
        f"{USB}\\VID_0930&PID_6544": ["AAA", "BBB"],
        STOR: ["Disk&Ven_Kingston&Prod_DataTraveler_2.0&Rev_1.00", "Disk&Ven_Generic&Prod_Flash_Disk&Rev_8.07"],
        f"{STOR}\\Disk&Ven_Kingston&Prod_DataTraveler_2.0&Rev_1.00": ["AAA&0"],
        f"{STOR}\\Disk&Ven_Generic&Prod_Flash_Disk&Rev_8.07": ["BBB&0"],
    })
    assert winnames.lookup(0x0930, 0x6544, registry) is None


def test_ghost_instances_from_past_driver_switches_do_not_block_the_real_match():
    """A stick re-plugged (or driver-switched) several times leaves extra Enum\\USB instances that never
    resolve to anything under USBSTOR -- only the one that is actually the live disk should matter."""
    registry = FakeRegistry({
        f"{USB}\\VID_0930&PID_6544": ["2&3b7c36a2&0&1", "1C1B0DDB0889C3703912302E", "2&3b7c36a2&0&2"],
        STOR: ["Disk&Ven_Kingston&Prod_DataTraveler_2.0&Rev_1.00"],
        f"{STOR}\\Disk&Ven_Kingston&Prod_DataTraveler_2.0&Rev_1.00": ["1C1B0DDB0889C3703912302E&0"],
    })
    names = winnames.lookup(0x0930, 0x6544, registry)
    assert names == winnames.StorageNames("Kingston", "DataTraveler 2.0", "1C1B0DDB0889C3703912302E")


def test_two_different_sticks_of_the_same_model_give_the_name_but_not_a_wrong_serial():
    """Two distinct physical units of the same model have both been seen under this VID:PID at different
    times. Nothing here says which one is live right now, so handing out either one's serial would let the
    wrong device's password/identity be used -- the name alone is still safe to show."""
    registry = FakeRegistry({
        f"{USB}\\VID_0930&PID_6544": ["AAA", "BBB"],
        STOR: ["Disk&Ven_Kingston&Prod_DataTraveler_2.0&Rev_1.00"],
        f"{STOR}\\Disk&Ven_Kingston&Prod_DataTraveler_2.0&Rev_1.00": ["AAA&0", "BBB&0"],
    })
    names = winnames.lookup(0x0930, 0x6544, registry)
    assert names == winnames.StorageNames("Kingston", "DataTraveler 2.0", "")


def test_unknown_device_or_non_storage_gives_nothing():
    assert winnames.lookup(0x1111, 0x2222, KINGSTON) is None
    only_usb = FakeRegistry({f"{USB}\\VID_0930&PID_6544": ["AAA"]})
    assert winnames.lookup(0x0930, 0x6544, only_usb) is None


@pytest.mark.parametrize("key,expected", [
    ("Disk&Ven_Kingston&Prod_DataTraveler_2.0&Rev_1.00", ("Kingston", "DataTraveler 2.0")),
    ("CdRom&Ven_Gen&Prod_Virtual_CD&Rev_1.0", ("Gen", "Virtual CD")),
    ("Disk&Prod_OnlyProduct", ("", "OnlyProduct")),
    ("Garbage", None),
])
def test_usbstor_key_parsing(key, expected):
    assert winnames.parse_usbstor_key(key) == expected


@pytest.mark.skipif(os.name != "nt", reason="winreg is Windows only")
def test_real_registry_lookup_does_not_crash_for_a_missing_device():
    assert winnames.lookup(0xFFFF, 0xFFFE) is None
