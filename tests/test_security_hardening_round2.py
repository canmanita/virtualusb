"""Findings of the automated security review: pre-created data folder, unprotected TLS folder, lockout bypass."""
import asyncio
from types import SimpleNamespace

import pytest

from test_access_control import Clock, Session, run
from test_winsetup import EXE, FakeRunner
from vhserver import admincli, winsetup
from vhserver.admincli import _secure_tls_dir  # bound before the autouse fixture replaces it
from vhserver.config import load_config
from vhserver.security import FailureLimiter, PasswordPolicy, limiter_key, new_password_hash

ATTACKER_SID = "S-1-5-21-1111-2222-3333-1001"


class OwnerRunner(FakeRunner):
    """Answers the two PowerShell folder checks (owner of the folder, owner of everything inside) and records the rest."""

    def __init__(self, owner_sid, fail_on=(), tree="OK"):
        super().__init__(fail_on)
        self.owner_sid, self.tree = owner_sid, tree

    def __call__(self, args):
        result = super().__call__(args)
        joined = " ".join(args)
        if "TREECHECK" in joined:
            return SimpleNamespace(returncode=result.returncode, stdout=self.tree + "\n")
        if "Get-Acl" in joined:
            return SimpleNamespace(returncode=result.returncode, stdout=self.owner_sid + "\n")
        return result


def install(tmp_path, runner):
    return winsetup.install(EXE, tmp_path, name="Lab", port=7600, allow_public=False, runner=runner,
                            is_admin=lambda: True, port_check=lambda port, host=None: True, wait=lambda: None)


# ---- 1. a data folder somebody else created first ---------------------------------------------------------------
def test_config_planted_in_a_folder_owned_by_a_user_is_discarded(tmp_path):
    (tmp_path / "config.json").write_text('{"name": "Planted", "port": 1234, "password_hash": "x"}', encoding="utf-8")
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / "nick.json").write_text("{}", encoding="utf-8")
    steps = install(tmp_path, OwnerRunner(ATTACKER_SID))
    assert all(step.ok for step in steps)
    config = load_config(tmp_path / "config.json")
    assert (config.name, config.port) == ("Lab", 7600) and not (tmp_path / "state").exists()


def test_the_folder_is_locked_down_before_its_contents_are_discarded(tmp_path):
    (tmp_path / "config.json").write_text("{}", encoding="utf-8")
    seen = []

    class Spy(OwnerRunner):
        def __call__(self, args):
            if "/inheritance:r" in args:
                seen.append((tmp_path / "config.json").exists())  # still there: the ACL comes first
            return super().__call__(args)

    install(tmp_path, Spy(ATTACKER_SID))
    assert seen == [True]


def test_entries_planted_inside_an_administrator_owned_folder_are_discarded(tmp_path):
    (tmp_path / "config.json").write_text('{"name": "Planted", "port": 1234}', encoding="utf-8")
    install(tmp_path, OwnerRunner(winsetup.ADMINS_SID, tree="BAD"))
    assert load_config(tmp_path / "config.json").name == "Lab"


def test_a_tree_check_that_fails_is_not_trusted(tmp_path):
    (tmp_path / "config.json").write_text('{"name": "Planted", "port": 1234}', encoding="utf-8")
    install(tmp_path, OwnerRunner(winsetup.ADMINS_SID, tree="", fail_on=["TREECHECK"]))
    assert load_config(tmp_path / "config.json").name == "Lab"


def test_nothing_is_changed_recursively_before_the_contents_are_checked(tmp_path):
    (tmp_path / "config.json").write_text("{}", encoding="utf-8")
    runner = OwnerRunner(winsetup.ADMINS_SID)
    install(tmp_path, runner)
    calls = runner.joined()
    check = next(i for i, c in enumerate(calls) if "TREECHECK" in c)
    recursive = [i for i, c in enumerate(calls) if c.startswith("icacls") and " /T" in c]
    assert recursive and min(recursive) > check
    assert all(" /L" in calls[i] for i in recursive)  # act on links themselves, never follow them


@pytest.mark.parametrize("sid", [winsetup.SYSTEM_SID, winsetup.ADMINS_SID])
def test_config_in_a_folder_owned_by_system_or_administrators_is_kept(tmp_path, sid):
    (tmp_path / "config.json").write_text('{"name": "Mine", "port": 7777}', encoding="utf-8")
    install(tmp_path, OwnerRunner(sid))
    assert load_config(tmp_path / "config.json").name == "Mine"


def test_an_owner_that_cannot_be_determined_is_not_trusted(tmp_path):
    (tmp_path / "config.json").write_text('{"name": "Planted", "port": 1234}', encoding="utf-8")
    install(tmp_path, OwnerRunner("not a sid"))
    assert load_config(tmp_path / "config.json").name == "Lab"


def test_a_junction_planted_in_the_folder_is_removed_without_following_it(tmp_path, monkeypatch):
    target = tmp_path / "elsewhere"
    target.mkdir()
    (target / "keep.txt").write_text("x", encoding="utf-8")
    data = tmp_path / "data"
    data.mkdir()
    link = data / "link"
    link.mkdir()  # stands in for a junction
    removed = []
    monkeypatch.setattr(winsetup, "is_reparse_point", lambda p: p == link or p.name == "link")
    monkeypatch.setattr(winsetup.os, "rmdir", lambda p: removed.append(p))
    install(data, OwnerRunner(ATTACKER_SID))
    assert str(link) in map(str, removed) and (target / "keep.txt").exists()


def test_a_fresh_folder_needs_no_owner_check(tmp_path):
    runner = OwnerRunner(ATTACKER_SID)
    install(tmp_path / "new", runner)
    assert not any("Get-Acl" in call for call in runner.joined())


# ---- 2. the CA key folder ---------------------------------------------------------------------------------------
def test_the_tls_folder_is_locked_down_on_windows(tmp_path):
    runner = OwnerRunner(winsetup.ADMINS_SID)
    assert _secure_tls_dir(tmp_path / "tls", runner, windows=True) is True
    joined = runner.joined()
    assert any("/setowner" in c for c in joined) and any("/inheritance:r" in c for c in joined)


def test_the_tls_folder_is_refused_when_it_cannot_be_secured(tmp_path):
    assert _secure_tls_dir(tmp_path, OwnerRunner(winsetup.ADMINS_SID, fail_on=["/setowner"]), windows=True) is False


def test_other_platforms_leave_the_tls_folder_to_the_file_modes(tmp_path):
    runner = OwnerRunner(ATTACKER_SID)
    assert _secure_tls_dir(tmp_path, runner, windows=False) is True and runner.calls == []


def test_tls_enable_stops_before_writing_keys_when_the_folder_is_unsafe(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("VHSERVER_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("VHSERVER_LANG", "en")
    monkeypatch.setattr(admincli, "_secure_tls_dir", lambda *a, **k: False)
    assert admincli.main(["tls", "enable"]) == 1
    assert not (tmp_path / "home" / "tls" / "ca.key").exists()


# ---- 3. lockout keyed on the address a client can rotate ---------------------------------------------------------
def test_ipv6_addresses_of_one_network_share_a_key():
    assert limiter_key("2001:db8:1:2::1") == limiter_key("2001:db8:1:2:ffff:ffff:ffff:ffff")
    assert limiter_key("2001:db8:1:2::1") != limiter_key("2001:db8:1:3::1")


def test_ipv4_and_mapped_ipv4_keep_the_exact_address():
    assert limiter_key("10.0.0.5") == "10.0.0.5" != limiter_key("10.0.0.6")
    assert limiter_key("::ffff:10.0.0.5") == "10.0.0.5"
    assert limiter_key("not-an-ip") == "not-an-ip"


def test_active_lockouts_survive_a_full_table():
    clock = Clock()
    limiter = FailureLimiter(max_failures=1, window_s=60, lockout_s=60, clock=clock, max_tracked=5)
    for i in range(20):
        limiter.record_failure(f"10.0.0.{i}")
    assert all(limiter.blocked(f"10.0.0.{i}") > 0 for i in range(20))
    clock.now += 61
    limiter.record_failure("10.9.9.9")
    assert limiter.tracked() <= 5  # expired lockouts are what gets purged


def fake_connection(ip, password):
    return SimpleNamespace(peer_ip=ip, conn_id=1, passwords={7: password})


def test_rotating_addresses_inside_one_ipv6_network_does_not_reset_the_lockout():
    async def scenario():
        limiter = FailureLimiter(max_failures=3, window_s=60, lockout_s=60)
        async with Session(passwords=PasswordPolicy(new_password_hash("pw")), limiter=limiter) as s:
            entry = s.server.devices[7]
            for i in range(3):
                assert not await s.server._authorized(fake_connection(f"2001:db8:0:1::{i + 1}", "bad"), entry)
            return await s.server._authorized(fake_connection("2001:db8:0:1::99", "pw"), entry)

    assert run(scenario()) is False

