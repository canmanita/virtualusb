import pytest

from vhserver import admincli


@pytest.fixture(autouse=True)
def no_real_acl_changes(monkeypatch):
    """``tls enable`` locks its folder with icacls on Windows; tests must not touch the real ACLs of temp folders."""
    monkeypatch.setattr(admincli, "_secure_tls_dir", lambda *args, **kwargs: True)
