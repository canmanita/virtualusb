import json

import pytest

from vhserver.nicknames import NicknameStore, clean_nickname, device_key
from vhserver.security import (FailureLimiter, PasswordPolicy, hash_password, new_password_hash, verify_password,
                               verify_supplied, wire_secret)


def test_hash_is_salted_and_verifiable():
    first, second = hash_password("correct horse"), hash_password("correct horse")
    assert first != second and first.startswith("scrypt$")
    assert verify_password("correct horse", first) and verify_password("correct horse", second)
    assert not verify_password("correct horsf", first)
    assert not verify_password("", first)


@pytest.mark.parametrize("stored", ["", "plain", "scrypt$x$y", "scrypt$16384$8$1$!!$!!", "md5$1$2$3$4$5",
                                    "scrypt$999999999$8$1$AAAA$AAAA"])
def test_malformed_or_hostile_hashes_never_verify(stored):
    assert verify_password("anything", stored) is False


def test_policy_prefers_the_device_hash_over_the_global_one():
    global_hash, device_hash = hash_password("global"), hash_password("device")
    policy = PasswordPolicy(global_hash, {"1234:5678:SER": device_hash})
    assert policy.hash_for("1234:5678:SER") == device_hash
    assert policy.hash_for("aaaa:bbbb:OTHER") == global_hash
    assert PasswordPolicy(None, {}).hash_for("1234:5678:SER") is None
    assert PasswordPolicy(None, {}).is_open and not policy.is_open


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_limiter_blocks_after_repeated_failures_and_recovers():
    clock = Clock()
    limiter = FailureLimiter(max_failures=3, window_s=60, lockout_s=120, clock=clock)
    assert limiter.blocked("10.0.0.5") == 0
    for _ in range(3):
        limiter.record_failure("10.0.0.5")
    assert limiter.blocked("10.0.0.5") > 0
    assert limiter.blocked("10.0.0.6") == 0  # per address
    clock.now += 121
    assert limiter.blocked("10.0.0.5") == 0


def test_failures_outside_the_window_do_not_add_up():
    clock = Clock()
    limiter = FailureLimiter(max_failures=3, window_s=60, lockout_s=120, clock=clock)
    for _ in range(2):
        limiter.record_failure("a")
    clock.now += 61
    limiter.record_failure("a")
    assert limiter.blocked("a") == 0


def test_limiter_does_not_grow_without_bound():
    limiter = FailureLimiter(max_failures=3, window_s=60, lockout_s=60, clock=Clock(), max_tracked=50)
    for i in range(500):
        limiter.record_failure(f"10.0.{i // 250}.{i % 250}")
    assert limiter.tracked() <= 50


def test_device_key_uses_the_serial_or_falls_back_to_the_port():
    assert device_key(0x346D, 0x5678, "SER1", 3) == "346d:5678:SER1"
    assert device_key(0x346D, 0x5678, "", 3) == "346d:5678@3"


def test_nickname_cleaning():
    assert clean_nickname("  Backup stick ") == "Backup stick"
    assert clean_nickname("a\x00b\tc\n") == "abc"
    assert clean_nickname("x" * 100) == "x" * 63
    assert len(clean_nickname("é" * 50).encode("utf-8")) <= 63


def test_store_roundtrip_and_removal(tmp_path):
    path = tmp_path / "nicknames.json"
    store = NicknameStore(path)
    assert store.get("346d:5678:SER1") == ""
    store.set("346d:5678:SER1", "Backup")
    assert NicknameStore(path).get("346d:5678:SER1") == "Backup"
    store.set("346d:5678:SER1", "   ")  # an empty name removes the nickname
    assert NicknameStore(path).get("346d:5678:SER1") == ""


def test_store_survives_corrupt_files_and_foreign_content(tmp_path):
    path = tmp_path / "nicknames.json"
    path.write_text("{oops", encoding="utf-8")
    assert NicknameStore(path).get("x") == ""
    path.write_text(json.dumps({"nicknames": {"ok": "Fine", "bad": 5, "long": "y" * 500}}), encoding="utf-8")
    store = NicknameStore(path)
    assert store.get("ok") == "Fine" and store.get("bad") == "" and len(store.get("long")) == 63


def test_store_without_a_path_keeps_names_in_memory():
    store = NicknameStore(None)
    store.set("k", "Name")
    assert store.get("k") == "Name"


def test_wire_secret_is_the_md5_the_stock_client_sends():
    assert wire_secret("hunter22hunter") == "4df1d2daca5cf1cecfc38992860fd230"  # observed with client 6.0.3


def test_supplied_values_are_checked_as_hash_or_plain_password():
    stored = new_password_hash("hunter22hunter")
    assert verify_supplied("4df1d2daca5cf1cecfc38992860fd230", stored)   # what the stock client sends
    assert verify_supplied("hunter22hunter", stored)                       # a client that does not hash
    assert not verify_supplied("4df1d2daca5cf1cecfc38992860fd231", stored)
    assert not verify_supplied("hunter22huntes", stored)
    assert not verify_supplied("", stored)


def test_the_wire_value_is_accepted_in_capital_letters_too():
    stored = new_password_hash("hunter22hunter")
    assert verify_supplied("4DF1D2DACA5CF1CECFC38992860FD230", stored)
    assert verify_supplied("4Df1D2daCA5cf1cecfC38992860fd230", stored)
    assert not verify_supplied("4DF1D2DACA5CF1CECFC38992860FD231", stored)
