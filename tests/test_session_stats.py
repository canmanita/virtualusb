import logging

from test_access_control import Session, bind, run
from test_server_integration import cbw
from vhserver import protocol as proto
from vhserver.sessionstats import SessionStats
from vhserver.wire import Message


def test_summary_separates_server_time_from_everything_else():
    stats = SessionStats(started=100.0)
    stats.record(control=True, inbound=True, nbytes=18, service_s=0.004, wait_s=0.001)
    stats.record(control=False, inbound=False, nbytes=31, service_s=0.002, wait_s=0.0)
    stats.record(control=False, inbound=True, nbytes=4096, service_s=1.5, wait_s=0.01)
    text = stats.summary(now=130.0)
    assert "30 s" in text and "3 transfers" in text and "1 control" in text
    assert "4114 bytes in" in text and "31 bytes out" in text
    assert "mean 502 ms" in text and "max 1500 ms" in text      # (4 + 2 + 1500) / 3 = 502 ms
    assert "1 slower than 1 s" in text


def test_empty_session_has_no_summary():
    assert SessionStats(started=1.0).summary(now=2.0) == ""


def test_the_server_logs_one_summary_when_a_device_is_released(caplog):
    async def scenario():
        async with Session() as s:
            client = await s.client()
            assert await bind(client) == proto.BIND_OK
            await client.control(7, bytes([0x80, 6, 0, 1, 0, 0, 0x40, 0]))
            await client.bulk(7, 0x01, 31, cbw(1, 36, True, bytes([0x12, 0, 0, 0, 36, 0])))
            await client.bulk(7, 0x82, 36)
            await client.send(Message(proto.C_UNBIND, device=7))
            await client.expect(proto.S_UNBIND_DONE)

    with caplog.at_level(logging.INFO, logger="vhserver"):
        run(scenario())
    lines = [r.getMessage() for r in caplog.records if "transfers" in r.getMessage()]
    assert len(lines) == 1 and "device 7" in lines[0] and "3 transfers" in lines[0] and "1 control" in lines[0]
