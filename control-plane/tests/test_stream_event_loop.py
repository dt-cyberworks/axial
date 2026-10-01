"""TC-PIPE-020 (GitHub issue #49): the live audit stream never does database work
on the event loop, and a poll that cannot get a connection does not end it."""

from __future__ import annotations

import asyncio
import datetime as dt
import time
import uuid

from sqlalchemy.exc import TimeoutError as PoolTimeoutError

from app.api import stream

ENGAGEMENT = uuid.uuid4()


def _poll(gen):
    return asyncio.ensure_future(gen.__anext__())


def test_a_slow_database_poll_does_not_block_the_event_loop(monkeypatch):
    """The failure mode of #49: a synchronous checkout that waits for the pool
    froze the whole server, including the requests that would free a connection.
    With the poll in a worker thread the loop keeps running while it waits."""
    def slow_fetch(*args):
        time.sleep(0.6)
        return []

    monkeypatch.setattr(stream, "_fetch_rows", slow_fetch)

    async def scenario() -> int:
        ticks = 0

        async def ticker():
            nonlocal ticks
            while True:
                await asyncio.sleep(0.01)
                ticks += 1

        gen = stream._event_stream(ENGAGEMENT, None, None, True, 10)
        tick_task = asyncio.ensure_future(ticker())
        poll = _poll(gen)
        await asyncio.sleep(0.5)
        tick_task.cancel()
        poll.cancel()
        await asyncio.gather(tick_task, poll, return_exceptions=True)
        await gen.aclose()
        return ticks

    ticks = asyncio.run(scenario())
    assert ticks >= 25, f"the event loop only ticked {ticks} times while a poll was waiting"


def test_a_poll_that_cannot_get_a_connection_is_skipped_and_the_history_is_still_sent(monkeypatch):
    monkeypatch.setattr(stream, "_POLL_INTERVAL_SECONDS", 0.01)
    now = dt.datetime.now(dt.timezone.utc)
    calls = []

    def flaky_fetch(engagement_id, action_set, scan_run_id, last_ts, first_poll, limit):
        calls.append(first_poll)
        if len(calls) == 1:
            raise PoolTimeoutError("QueuePool limit reached")
        return [(now, {"ts": now.isoformat(), "action": "tool_call"})]

    monkeypatch.setattr(stream, "_fetch_rows", flaky_fetch)

    async def scenario():
        gen = stream._event_stream(ENGAGEMENT, None, None, True, 10)
        event = await asyncio.wait_for(gen.__anext__(), timeout=5)
        await gen.aclose()
        return event

    event = asyncio.run(scenario())
    assert event["event"] == "audit_entry"
    assert calls[:2] == [True, True], "history is still owed after a skipped first poll"


def test_the_stream_only_follows_rows_newer_than_the_last_one_it_sent(monkeypatch):
    monkeypatch.setattr(stream, "_POLL_INTERVAL_SECONDS", 0.01)
    t1 = dt.datetime.now(dt.timezone.utc)
    seen = []

    def fetch(engagement_id, action_set, scan_run_id, last_ts, first_poll, limit):
        seen.append(last_ts)
        return [(t1, {"n": 1})] if len(seen) == 1 else []

    monkeypatch.setattr(stream, "_fetch_rows", fetch)

    async def scenario():
        gen = stream._event_stream(ENGAGEMENT, None, None, True, 10)
        await asyncio.wait_for(gen.__anext__(), timeout=5)
        nxt = asyncio.ensure_future(gen.__anext__())
        await asyncio.sleep(0.1)
        nxt.cancel()
        await asyncio.gather(nxt, return_exceptions=True)
        await gen.aclose()

    asyncio.run(scenario())
    assert seen[0] is None and seen[1] == t1
