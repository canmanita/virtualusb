import pytest

from vhserver.netpolicy import AccessPolicy


@pytest.mark.parametrize("addr", ["127.0.0.1", "192.168.0.182", "10.1.2.3", "172.20.0.9", "100.112.122.6",
                                  "169.254.1.1", "::1", "fe80::1%eth0", "::ffff:192.168.1.5"])
def test_default_policy_accepts_private_and_loopback(addr):
    assert AccessPolicy().permits(addr)


@pytest.mark.parametrize("addr", ["8.8.8.8", "1.1.1.1", "172.32.0.1", "2001:db8::1", "not-an-ip", ""])
def test_default_policy_rejects_public_and_garbage(addr):
    assert not AccessPolicy().permits(addr)


def test_custom_allow_list_replaces_defaults():
    policy = AccessPolicy(["203.0.113.0/24"])
    assert policy.permits("203.0.113.9") and not policy.permits("192.168.0.1")
