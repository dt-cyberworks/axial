"""TC-PIPE-019 (GitHub issue #49): the proxy's audit events are committed in
batches, yet no request is forwarded before its audit record exists and a failed
batch denies every request waiting on it (fail closed, REQ-EGRESS-003)."""

from __future__ import annotations

import asyncio
import io
import threading
import time
import urllib.error

import pytest

from app import audit_client, proxy
from app.audit_client import AuditBatcher

E1 = "00000000-0000-0000-0000-000000000001"
E2 = "00000000-0000-0000-0000-000000000002"


class Recorder:
    """A blocking `send` that records every batch and can be slowed or failed."""

    def __init__(self, delay: float = 0.0, fail_first: int = 0):
        self.batches: list[tuple[str, list[dict]]] = []
        self.delay = delay
        self.fail_first = fail_first
        self.lock = threading.Lock()

    def __call__(self, engagement_id, events):
        if self.delay:
            time.sleep(self.delay)
        with self.lock:
            if self.fail_first > 0:
                self.fail_first -= 1
                raise OSError("control plane unavailable")
            self.batches.append((engagement_id, list(events)))


def _event(i):
    return ("ALLOW", "in_scope", {"i": str(i)})


def test_an_idle_event_is_sent_at_once_not_after_a_timer():
    rec = Recorder()

    async def scenario():
        batcher = AuditBatcher(rec)
        started = time.monotonic()
        await batcher.submit(E1, *_event(0))
        return time.monotonic() - started

    assert asyncio.run(scenario()) < 0.2
    assert [len(events) for _, events in rec.batches] == [1]


def test_events_arriving_during_a_send_go_out_together_and_each_exactly_once():
    rec = Recorder(delay=0.15)

    async def scenario():
        batcher = AuditBatcher(rec, max_batch=100)
        await asyncio.gather(*(batcher.submit(E1, *_event(i)) for i in range(60)))

    asyncio.run(scenario())
    sizes = [len(events) for _, events in rec.batches]
    assert sum(sizes) == 60
    assert len(sizes) <= 3, f"60 concurrent events took {len(sizes)} requests"
    sent = [e["payload"]["i"] for _, events in rec.batches for e in events]
    assert sorted(sent, key=int) == [str(i) for i in range(60)], "every event exactly once"
    assert sent == [str(i) for i in range(60)], "arrival order is kept"


def test_a_batch_never_exceeds_max_batch():
    rec = Recorder(delay=0.05)

    async def scenario():
        batcher = AuditBatcher(rec, max_batch=25)
        await asyncio.gather(*(batcher.submit(E1, *_event(i)) for i in range(120)))

    asyncio.run(scenario())
    assert max(len(events) for _, events in rec.batches) <= 25
    assert sum(len(events) for _, events in rec.batches) == 120


def test_events_of_different_engagements_are_never_mixed():
    rec = Recorder(delay=0.05)

    async def scenario():
        batcher = AuditBatcher(rec)
        await asyncio.gather(*(batcher.submit(E1 if i % 2 else E2, *_event(i)) for i in range(40)))

    asyncio.run(scenario())
    for engagement_id, events in rec.batches:
        parity = 1 if engagement_id == E1 else 0
        assert all(int(e["payload"]["i"]) % 2 == parity for e in events)


def test_negative_a_request_is_not_released_before_its_batch_is_committed():
    release = threading.Event()
    sent = []

    def send(engagement_id, events):
        release.wait(timeout=5)
        sent.append(len(events))

    async def scenario():
        batcher = AuditBatcher(send)
        waiter = asyncio.ensure_future(batcher.submit(E1, *_event(0)))
        await asyncio.sleep(0.2)
        still_waiting = not waiter.done()
        release.set()
        await waiter
        return still_waiting

    assert asyncio.run(scenario()), "submit returned before the control plane had committed the event"
    assert sent == [1]


def test_negative_a_failed_batch_fails_every_request_waiting_on_it_and_later_ones_recover():
    rec = Recorder(delay=0.1, fail_first=1)

    async def scenario():
        batcher = AuditBatcher(rec, max_batch=100)
        first = asyncio.ensure_future(batcher.submit(E1, *_event(0)))
        await asyncio.sleep(0.02)
        queued = [asyncio.ensure_future(batcher.submit(E1, *_event(i))) for i in range(1, 6)]
        results = await asyncio.gather(first, *queued, return_exceptions=True)
        later = await asyncio.gather(batcher.submit(E1, *_event(99)), return_exceptions=True)
        return results, later

    results, later = asyncio.run(scenario())
    assert isinstance(results[0], OSError), "the request whose batch failed must see the failure"
    assert all(r is None for r in results[1:]), "the batch after it succeeded"
    assert later == [None], "the batcher keeps working after a failure"
    assert sum(len(events) for _, events in rec.batches) == 5 + 1, "nothing was silently dropped or duplicated"


def test_negative_every_waiter_of_a_failed_batch_is_denied_with_503():
    class Writer:
        def __init__(self):
            self.data = b""

        def write(self, data):
            self.data += data

        async def drain(self):
            return None

        def close(self):
            return None

        async def wait_closed(self):
            return None

    def unavailable(engagement_id, events):
        raise OSError("control plane unavailable")

    async def scenario():
        original = proxy.submit_audit_batch
        proxy.submit_audit_batch = unavailable
        try:
            writers = [Writer() for _ in range(8)]
            results = await asyncio.gather(*(proxy._submit_audit_or_deny(w, E1, "ALLOW", "ok", {}) for w in writers))
        finally:
            proxy.submit_audit_batch = original
        return writers, results

    writers, results = asyncio.run(scenario())
    assert results == [False] * 8
    assert all(b"HTTP/1.1 503" in w.data and b"audit_unavailable" in w.data for w in writers)


def test_the_batcher_can_be_used_from_several_event_loops():
    rec = Recorder()
    batcher = AuditBatcher(rec, max_inflight=1)
    for n in range(3):
        asyncio.run(asyncio.wait_for(batcher.submit(E1, *_event(n)), timeout=5))
    assert sum(len(events) for _, events in rec.batches) == 3


# --- the client ----------------------------------------------------------------------

class _Created:
    status = 201

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _http_error(code):
    return urllib.error.HTTPError("http://x", code, "err", {}, io.BytesIO(b""))


def test_the_batch_client_posts_the_events_with_the_internal_token(monkeypatch):
    seen = {}

    def fake_open(request, timeout):
        seen["request"], seen["timeout"] = request, timeout
        return _Created()

    monkeypatch.setattr(audit_client.urllib.request, "urlopen", fake_open)
    audit_client.submit_audit_batch(E1, [{"decision": "DENY", "reason": "x", "payload": {}}])
    request = seen["request"]
    assert request.full_url.endswith(f"/internal/engagements/{E1}/proxy-audit/batch")
    assert request.get_header("X-asm-internal-token")
    assert b'"events"' in request.data and seen["timeout"] == 5


def test_the_batch_client_retries_only_a_503_because_nothing_was_written(monkeypatch):
    monkeypatch.setattr(audit_client, "_BATCH_BACKOFF_SECONDS", 0)
    calls = []

    def flaky(request, timeout):
        calls.append(1)
        if len(calls) < 3:
            raise _http_error(503)
        return _Created()

    monkeypatch.setattr(audit_client.urllib.request, "urlopen", flaky)
    audit_client.submit_audit_batch(E1, [{"decision": "ALLOW", "reason": "x", "payload": {}}])
    assert len(calls) == 3


@pytest.mark.parametrize("failure", [_http_error(500), _http_error(404), urllib.error.URLError("timed out"), TimeoutError()])
def test_negative_the_batch_client_never_retries_a_failure_that_may_have_committed(monkeypatch, failure):
    monkeypatch.setattr(audit_client, "_BATCH_BACKOFF_SECONDS", 0)
    calls = []

    def fail(request, timeout):
        calls.append(1)
        raise failure

    monkeypatch.setattr(audit_client.urllib.request, "urlopen", fail)
    with pytest.raises(Exception):
        audit_client.submit_audit_batch(E1, [{"decision": "ALLOW", "reason": "x", "payload": {}}])
    assert len(calls) == 1, "a retry here could write the same audit event twice"


def test_negative_the_batch_client_gives_up_after_three_503s(monkeypatch):
    monkeypatch.setattr(audit_client, "_BATCH_BACKOFF_SECONDS", 0)
    calls = []

    def busy(request, timeout):
        calls.append(1)
        raise _http_error(503)

    monkeypatch.setattr(audit_client.urllib.request, "urlopen", busy)
    with pytest.raises(urllib.error.HTTPError):
        audit_client.submit_audit_batch(E1, [{"decision": "ALLOW", "reason": "x", "payload": {}}])
    assert len(calls) == 3


def test_negative_a_non_201_answer_is_a_failure(monkeypatch):
    class Ok200(_Created):
        status = 200

    monkeypatch.setattr(audit_client.urllib.request, "urlopen", lambda request, timeout: Ok200())
    with pytest.raises(RuntimeError):
        audit_client.submit_audit_batch(E1, [{"decision": "ALLOW", "reason": "x", "payload": {}}])
