import asyncio
import logging
import threading
import time

from vhserver.watchdog import LoopWatchdog, format_thread_stacks


def run_loop_with_block(block_for, **options):
    """Run an event loop whose only job is to block (like a stuck synchronous call) while the watchdog watches."""
    exits = []
    holder = {}

    async def scenario():
        loop = asyncio.get_running_loop()
        dog = LoopWatchdog(loop, interval=0.02, exit_fn=exits.append, **options)
        dog.start()
        await asyncio.sleep(0.1)       # healthy beats first
        time.sleep(block_for)          # the loop is blocked here, exactly what the watchdog must notice
        await asyncio.sleep(0.1)
        holder["dog"] = dog
        dog.stop()

    asyncio.run(scenario())
    return exits


def test_a_healthy_loop_is_left_alone(caplog):
    with caplog.at_level(logging.ERROR, logger="vhserver.watchdog"):
        exits = run_loop_with_block(0.0, warn_after=0.3, exit_after=0.6)
    assert exits == [] and not caplog.records


def test_a_stalled_loop_logs_every_thread_stack(caplog):
    with caplog.at_level(logging.ERROR, logger="vhserver.watchdog"):
        exits = run_loop_with_block(0.35, warn_after=0.15, exit_after=30)
    text = "\n".join(record.getMessage() for record in caplog.records)
    assert exits == [] and "event loop stalled" in text and "time.sleep" in text and "MainThread" in text


def test_a_loop_stalled_for_too_long_ends_the_process_so_it_is_restarted(caplog):
    with caplog.at_level(logging.CRITICAL, logger="vhserver.watchdog"):
        exits = run_loop_with_block(0.5, warn_after=0.1, exit_after=0.25)
    assert exits == [70]


def test_recovery_re_arms_the_warning(caplog):
    with caplog.at_level(logging.ERROR, logger="vhserver.watchdog"):
        run_loop_with_block(0.3, warn_after=0.1, exit_after=30)
        run_loop_with_block(0.3, warn_after=0.1, exit_after=30)
    assert sum("event loop stalled" in r.getMessage() for r in caplog.records) == 2


def test_stack_report_names_the_threads():
    ready, release = threading.Event(), threading.Event()

    def worker():
        ready.set()
        release.wait(5)

    thread = threading.Thread(target=worker, name="usb-poll-test", daemon=True)
    thread.start()
    ready.wait(2)
    report = format_thread_stacks()
    release.set()
    assert "usb-poll-test" in report and "worker" in report
