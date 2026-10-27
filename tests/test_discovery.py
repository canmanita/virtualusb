import asyncio

import pytest

from vhserver.discovery import Discovery


class FakeZeroconf:
    instances: list = []

    def __init__(self, ip_version=None, interfaces=None):
        self.interfaces = interfaces
        self.registered, self.unregistered, self.closed = [], [], False
        FakeZeroconf.instances.append(self)

    async def async_register_service(self, info, allow_name_change=False, strict=True):
        assert strict is False, "the stock service type _ssl_vhusb is only accepted in non-strict mode"
        self.registered.append(info)

    async def async_unregister_service(self, info):
        self.unregistered.append(info)

    async def async_close(self):
        self.closed = True


class Network:
    """A scripted network: tests change ``addresses`` the way plugging a cable would."""
    def __init__(self, addresses):
        self.addresses = list(addresses)

    def __call__(self):
        return list(self.addresses)


@pytest.fixture(autouse=True)
def fresh_instances():
    FakeZeroconf.instances = []


def make(network, interval=0.01):
    return Discovery("SERIAL", 7575, address_provider=network, zeroconf_factory=FakeZeroconf, interval=interval)


async def settle(seconds=0.1):
    await asyncio.sleep(seconds)


def test_announces_the_current_address_once_when_nothing_changes():
    async def scenario():
        discovery = make(Network(["192.168.0.182"]))
        await discovery.start()
        await settle()
        await discovery.stop()

    asyncio.run(scenario())
    assert len(FakeZeroconf.instances) == 1
    first = FakeZeroconf.instances[0]
    assert first.interfaces == ["192.168.0.182"] and first.closed and first.unregistered


def test_a_changed_address_is_announced_again_and_the_old_announcement_withdrawn():
    async def scenario():
        network = Network(["192.168.0.182"])
        discovery = make(network)
        await discovery.start()
        network.addresses = ["10.0.0.7"]
        await settle()
        await discovery.stop()

    asyncio.run(scenario())
    old, new = FakeZeroconf.instances
    assert old.closed and old.unregistered and new.interfaces == ["10.0.0.7"]
    assert new.registered[0].parsed_addresses() == ["10.0.0.7"]


def test_server_started_without_a_network_announces_when_one_appears():
    async def scenario():
        network = Network([])
        discovery = make(network)
        await discovery.start()
        assert FakeZeroconf.instances == []  # nothing to announce yet
        network.addresses = ["192.168.0.182"]
        await settle()
        await discovery.stop()

    asyncio.run(scenario())
    assert len(FakeZeroconf.instances) == 1 and FakeZeroconf.instances[0].interfaces == ["192.168.0.182"]


def test_losing_the_network_withdraws_the_announcement():
    async def scenario():
        network = Network(["192.168.0.182"])
        discovery = make(network)
        await discovery.start()
        network.addresses = []
        await settle()
        await discovery.stop()

    asyncio.run(scenario())
    assert len(FakeZeroconf.instances) == 1 and FakeZeroconf.instances[0].closed


def test_a_failed_reannounce_is_retried_on_the_next_check():
    class Flaky(FakeZeroconf):
        failures = 1

        async def async_register_service(self, info, allow_name_change=False, strict=True):
            if len(FakeZeroconf.instances) > 1 and Flaky.failures:
                Flaky.failures -= 1
                raise OSError("interface not ready")
            await super().async_register_service(info, allow_name_change, strict)

    async def scenario():
        network = Network(["192.168.0.182"])
        discovery = Discovery("SERIAL", 7575, address_provider=network, zeroconf_factory=Flaky, interval=0.01)
        await discovery.start()
        network.addresses = ["10.0.0.7"]
        await settle(0.2)
        await discovery.stop()

    asyncio.run(scenario())
    assert FakeZeroconf.instances[-1].registered, "the announcement must succeed on a later attempt"
    assert FakeZeroconf.instances[-1].interfaces == ["10.0.0.7"]


def test_stop_without_start_is_harmless():
    asyncio.run(make(Network([])).stop())


def test_ssl_service_is_announced_next_to_the_plain_one():
    async def scenario():
        discovery = Discovery("SERIAL", 7575, ssl_port=7574, address_provider=Network(["192.168.0.182"]),
                              zeroconf_factory=FakeZeroconf, interval=0.01)
        await discovery.start()
        await discovery.stop()

    asyncio.run(scenario())
    registered = FakeZeroconf.instances[0].registered
    assert sorted((i.type, i.port) for i in registered) == [("_ssl_vhusb._tcp.local.", 7574),
                                                           ("_vhusb._tcp.local.", 7575)]
    assert len(FakeZeroconf.instances[0].unregistered) == 2
    names = {i.type: i.name for i in registered}
    assert names["_ssl_vhusb._tcp.local."] == "VH Clone (SSL)._ssl_vhusb._tcp.local."  # as the stock server
    assert names["_vhusb._tcp.local."] == "VH Clone._vhusb._tcp.local."


def test_plaintext_can_be_left_out_of_the_announcement():
    async def scenario():
        discovery = Discovery("SERIAL", 7575, ssl_port=7574, plain=False, address_provider=Network(["192.168.0.182"]),
                              zeroconf_factory=FakeZeroconf, interval=0.01)
        await discovery.start()
        await discovery.stop()

    asyncio.run(scenario())
    assert [i.type for i in FakeZeroconf.instances[0].registered] == ["_ssl_vhusb._tcp.local."]


class OldZeroconf(FakeZeroconf):
    """zeroconf 0.47 (Debian 12): no ``strict`` argument, and the underscore in _ssl_vhusb is refused."""

    async def async_register_service(self, info, ttl=None, allow_name_change=False, cooperating_responders=False):
        if info.type.startswith("_ssl_"):
            raise ValueError("Service name (ssl_vhusb) must contain only these characters")
        self.registered.append(info)


def test_old_zeroconf_still_announces_the_plain_service_when_ssl_cannot_be_registered():
    async def scenario():
        discovery = Discovery("SERIAL", 7575, ssl_port=7574, address_provider=Network(["192.168.0.182"]),
                              zeroconf_factory=OldZeroconf, interval=0.01)
        await discovery.start()
        announced = [i.type for i in discovery._infos]
        await discovery.stop()
        return announced

    assert asyncio.run(scenario()) == ["_vhusb._tcp.local."]


def test_nothing_announced_at_all_is_retried_not_forgotten():
    class Refuses(FakeZeroconf):
        attempts = 0

        async def async_register_service(self, info, allow_name_change=False, strict=True):
            Refuses.attempts += 1
            if Refuses.attempts <= 2:
                raise OSError("no multicast yet")
            self.registered.append(info)

    async def scenario():
        discovery = Discovery("SERIAL", 7575, address_provider=Network(["192.168.0.182"]), zeroconf_factory=Refuses,
                              interval=0.01)
        await discovery.start()
        await asyncio.sleep(0.2)
        announced = len(discovery._infos)
        await discovery.stop()
        return announced

    assert asyncio.run(scenario()) == 1
