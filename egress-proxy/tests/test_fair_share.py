"""REQ-EGRESS-012/013 (GitHub #81 step 4): no engagement can starve another of the proxy's slots, and a busy destination
slows requests down instead of failing them.

Seen on int (2026-10-20): the proxy had one pool of 64 client slots for every engagement and refused a request for lack of
a slot before it knew whose request it was. These tests drive the real `handle_client` with many connections at once."""

from __future__ import annotations

import asyncio
import os

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://x:x@localhost:5432/x")

from app import proxy  # noqa: E402
from app.fair_share import DestinationGate, FairShare  # noqa: E402

ENG_A = "019649b8-0000-7000-8000-00000000000a"
ENG_B = "019649b8-0000-7000-8000-00000000000b"
ENG_C = "019649b8-0000-7000-8000-00000000000c"


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


# --- FairShare -------------------------------------------------------------------------------------------------------

def _share(**over):
    args = dict(total=64, reserve=8, min_share=4, window_s=30.0, clock=Clock())
    args.update(over)
    return FairShare(**args)


def test_a_lone_engagement_may_use_every_slot_except_the_reserve():
    share = _share()
    assert share.limit_for(ENG_A) == 56
    assert [share.try_acquire(ENG_A) for _ in range(60)].count(True) == 56
    share.release(ENG_A)
    assert share.try_acquire(ENG_A) is True and share.try_acquire(ENG_A) is False


def test_a_second_engagement_halves_the_share_and_the_first_drains_to_it():
    share = _share()
    for _ in range(56):
        assert share.try_acquire(ENG_A)
    assert share.try_acquire(ENG_B) is True              # B appears: k = 2, each share is 32
    assert share.limit_for(ENG_A) == share.limit_for(ENG_B) == 32
    assert share.try_acquire(ENG_A) is False             # A holds 56, over its new share
    for _ in range(25):
        share.release(ENG_A)                             # 31 left
    assert share.try_acquire(ENG_A) is True and share.try_acquire(ENG_A) is False


def test_the_share_never_falls_below_the_minimum():
    share = _share()
    engagements = [f"019649b8-0000-7000-8000-{i:012d}" for i in range(40)]
    for e in engagements:
        assert share.try_acquire(e)
    assert share.limit_for(engagements[0]) == 4          # 64 // 40 = 1, raised to the minimum


def test_an_engagement_that_has_gone_quiet_stops_counting_after_the_window():
    clock = Clock()
    share = _share(clock=clock)
    assert share.try_acquire(ENG_B)
    share.release(ENG_B)
    assert share.limit_for(ENG_A) == 32                  # B was seen a moment ago
    clock.now += 31
    assert share.limit_for(ENG_A) == 56                  # B has not been seen for longer than the window


def test_counts_return_to_zero_and_a_stray_release_cannot_make_them_negative():
    share = _share()
    share.try_acquire(ENG_A)
    share.release(ENG_A)
    share.release(ENG_A)
    share.release(ENG_C)
    assert share.in_flight == {}


@pytest.mark.parametrize("total, reserve", [(64, 64), (64, 100), (1, 5), (10, 0)])
def test_the_reserve_never_leaves_an_engagement_without_a_slot(total, reserve):
    share = _share(total=total, reserve=reserve)
    assert share.limit_for(ENG_A) >= 1 and share.try_acquire(ENG_A) is True


# --- DestinationGate -------------------------------------------------------------------------------------------------

def test_a_gate_that_is_off_never_waits_and_keeps_no_state():
    async def scenario():
        gate = DestinationGate(0, 5)
        assert [await gate.acquire("a.example") for _ in range(50)] == [True] * 50
        gate.release("a.example")
        return gate

    gate = asyncio.run(scenario())
    assert gate.enabled is False and gate._semaphores == {} and gate._users == {}


def test_requests_to_one_host_never_exceed_the_cap_and_a_waiting_one_is_served_when_one_ends():
    async def scenario():
        gate = DestinationGate(2, 5)
        peak, running, order = 0, 0, []

        async def one(i):
            nonlocal peak, running
            assert await gate.acquire("Host.Example.")
            running += 1
            peak = max(peak, running)
            order.append(i)
            await asyncio.sleep(0.05)
            running -= 1
            gate.release("host.example")

        await asyncio.gather(*(one(i) for i in range(8)))
        return gate, peak, order

    gate, peak, order = asyncio.run(scenario())
    assert peak == 2 and sorted(order) == list(range(8))
    assert gate._semaphores == {} and gate._users == {}, "nothing is left behind once everything ended"


def test_a_busy_host_does_not_slow_down_another():
    async def scenario():
        gate = DestinationGate(1, 0.3)
        assert await gate.acquire("busy.example")
        started = asyncio.get_running_loop().time()
        assert await gate.acquire("other.example")
        return asyncio.get_running_loop().time() - started

    assert asyncio.run(scenario()) < 0.2


def test_negative_a_request_that_waits_too_long_is_refused_and_leaves_nothing_behind():
    async def scenario():
        gate = DestinationGate(1, 0.2)
        assert await gate.acquire("a.example")
        assert await gate.acquire("a.example") is False
        assert gate.in_use("a.example") == 1
        gate.release("a.example")
        return gate

    gate = asyncio.run(scenario())
    assert gate._semaphores == {} and gate._users == {}


def test_negative_a_request_cancelled_while_waiting_leaves_nothing_behind():
    async def scenario():
        gate = DestinationGate(1, 30)
        assert await gate.acquire("a.example")
        waiter = asyncio.ensure_future(gate.acquire("a.example"))
        await asyncio.sleep(0.05)
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        gate.release("a.example")
        return gate

    gate = asyncio.run(scenario())
    assert gate._semaphores == {} and gate._users == {}


# --- the real handler under contention -------------------------------------------------------------------------------

class _Writer:
    def __init__(self):
        self.data = b""

    def write(self, data):
        self.data += data

    async def drain(self):
        return None

    def close(self):
        pass

    def get_extra_info(self, _name):
        return None


class _Reader:
    def __init__(self, engagement, host="host.example.com"):
        self._lines = [f"CONNECT {host}:443 HTTP/1.1\r\n".encode(), f"X-ASM-Engagement-Id: {engagement}\r\n".encode(), b"\r\n"]

    async def readline(self):
        return self._lines.pop(0) if self._lines else b""


class _Remote:
    pass


@pytest.fixture()
def pool(monkeypatch):
    """The real handler with the pool, the fair share and the destination gate fresh, and a tunnel that stays open until
    `hold` is set. Returns (hold, state) where state.active counts tunnels that are currently open."""
    hold = asyncio.Event
    state = type("State", (), {"active": 0, "peak": 0, "per_host": {}, "peak_per_host": {}})()

    async def fake_evaluate(eid, host, path, port):
        return True, "allow"

    async def fake_submit(_w, eid, decision, why, payload):
        return True

    async def fake_open(host, port):
        return _Remote(), _Writer()

    monkeypatch.setattr(proxy, "evaluate", fake_evaluate)
    monkeypatch.setattr(proxy, "vet_target_host", lambda host, port: host)
    monkeypatch.setattr(proxy, "load_engagement", lambda eid: {"id": eid, "source": "own_domain"})
    monkeypatch.setattr(proxy, "_submit_audit_or_deny", fake_submit)
    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    monkeypatch.setattr(proxy, "DEFAULT_ENGAGEMENT_ID", None)
    monkeypatch.setattr(proxy, "REQUIRE_TOKEN", False)
    proxy._concurrency_in_flight.clear()
    return state


def _install(monkeypatch, state, hold, *, total=64, reserve=8, dest_limit=0, dest_wait=0.3):
    async def fake_relay(*_a, **_k):
        state.active += 1
        state.peak = max(state.peak, state.active)
        try:
            await hold.wait()
        finally:
            state.active -= 1

    monkeypatch.setattr(proxy, "_relay", fake_relay)
    monkeypatch.setattr(proxy, "_CLIENT_SLOTS", asyncio.Semaphore(total))
    monkeypatch.setattr(proxy, "_FAIR_SHARE", FairShare(total, reserve, 4, 30.0))
    monkeypatch.setattr(proxy, "_DESTINATIONS", DestinationGate(dest_limit, dest_wait))


async def _open(engagement, host="host.example.com"):
    writer = _Writer()
    task = asyncio.ensure_future(proxy.handle_client(_Reader(engagement, host), writer))
    return task, writer


def _refusals(writers):
    out = {}
    for w in writers:
        if w.data.startswith(b"HTTP/1.1 503"):
            reason = w.data.split(b"\r\n\r\n", 1)[1].decode()
            out[reason] = out.get(reason, 0) + 1
    return out


def test_contention_one_engagement_saturating_the_proxy_cannot_starve_another(pool, monkeypatch):
    async def scenario():
        hold = asyncio.Event()
        _install(monkeypatch, pool, hold)
        a = [await _open(ENG_A) for _ in range(200)]
        await asyncio.sleep(0.3)
        a_open, a_refused = pool.active, _refusals([w for _, w in a])
        b = [await _open(ENG_B) for _ in range(20)]
        await asyncio.sleep(0.3)
        b_open_total = pool.active
        b_refused = _refusals([w for _, w in b])
        in_flight = dict(proxy._FAIR_SHARE.in_flight)
        hold.set()
        await asyncio.gather(*(t for t, _ in a + b))
        return a_open, a_refused, b_open_total, b_refused, in_flight

    a_open, a_refused, b_open_total, b_refused, in_flight = asyncio.run(scenario())
    assert a_open == 56, "A alone is capped at the pool minus the reserve"
    assert a_refused == {"engagement_share_exhausted": 144}
    assert b_open_total - a_open >= 8, "B still gets the reserve while A is saturating"
    assert set(b_refused) <= {"proxy_capacity_exhausted"}, "B is never refused for A's share, only for the physical pool"
    assert in_flight[ENG_A] == 56 and in_flight[ENG_B] >= 8
    assert proxy._FAIR_SHARE.in_flight == {} and proxy._CLIENT_SLOTS._value == 64, "every slot came back"


def test_contention_once_the_first_engagement_drains_the_second_gets_its_full_share(pool, monkeypatch):
    async def scenario():
        hold_a, hold_b = asyncio.Event(), asyncio.Event()
        gates = {ENG_A: hold_a, ENG_B: hold_b}

        async def relay(reader, writer, *_a, **_k):
            pool.active += 1
            try:
                await gates[reader.engagement].wait()
            finally:
                pool.active -= 1

        _install(monkeypatch, pool, hold_a)
        monkeypatch.setattr(proxy, "_relay", lambda reader, writer, *a, **k: relay(reader, writer))
        a = [await _open_tagged(ENG_A) for _ in range(56)]
        await asyncio.sleep(0.2)
        hold_a.set()                                    # A's tunnels end
        await asyncio.gather(*(t for t, _ in a))
        b = [await _open_tagged(ENG_B) for _ in range(40)]
        await asyncio.sleep(0.3)
        admitted = pool.active
        hold_b.set()
        await asyncio.gather(*(t for t, _ in b))
        return admitted

    class _TaggedReader(_Reader):
        def __init__(self, engagement):
            super().__init__(engagement)
            self.engagement = engagement

    async def _open_tagged(engagement):
        writer = _Writer()
        task = asyncio.ensure_future(proxy.handle_client(_TaggedReader(engagement), writer))
        return task, writer

    # B alone (A is within the window, so k = 2): each share is 32
    assert asyncio.run(scenario()) == 32


def test_contention_a_refused_request_gives_its_socket_back_at_once(pool, monkeypatch):
    async def scenario():
        hold = asyncio.Event()
        _install(monkeypatch, pool, hold)
        a = [await _open(ENG_A) for _ in range(100)]
        await asyncio.sleep(0.3)
        free_while_a_saturates = proxy._CLIENT_SLOTS._value
        hold.set()
        await asyncio.gather(*(t for t, _ in a))
        return free_while_a_saturates

    assert asyncio.run(scenario()) == 8, "only A's 56 admitted requests hold a socket; its refused ones did not keep theirs"


def test_negative_a_request_that_fails_after_admission_still_returns_its_slots(pool, monkeypatch):
    async def boom(host, port):
        raise OSError("connection refused")

    async def scenario():
        hold = asyncio.Event()
        _install(monkeypatch, pool, hold, dest_limit=2)
        monkeypatch.setattr(asyncio, "open_connection", boom)
        tasks = [await _open(ENG_A) for _ in range(20)]
        await asyncio.gather(*(t for t, _ in tasks))

    asyncio.run(scenario())
    assert proxy._FAIR_SHARE.in_flight == {} and proxy._CLIENT_SLOTS._value == 64
    assert proxy._DESTINATIONS._semaphores == {} and proxy._DESTINATIONS._users == {}


def test_the_destination_cap_slows_requests_down_and_a_slow_one_is_refused_destination_busy(pool, monkeypatch):
    async def scenario():
        hold = asyncio.Event()
        _install(monkeypatch, pool, hold, dest_limit=3, dest_wait=0.4)
        first = [await _open(ENG_A) for _ in range(3)]
        await asyncio.sleep(0.15)
        waiting = [await _open(ENG_B) for _ in range(2)]             # same host, other engagement: they wait
        other_host = await _open(ENG_B, host="other.example.com")    # another host: not slowed
        await asyncio.sleep(0.15)
        mid = (pool.active, _refusals([w for _, w in waiting]))
        await asyncio.sleep(0.5)                                      # the wait is over, nothing finished
        late = _refusals([w for _, w in waiting])
        hold.set()
        await asyncio.gather(*(t for t, _ in first + waiting + [other_host]))
        return mid, late

    (active_mid, refused_mid), refused_late = asyncio.run(scenario())
    assert active_mid == 4, "three to the capped host plus one to the other host; the two others are waiting"
    assert refused_mid == {}, "waiting is not failing"
    assert refused_late == {"destination_busy": 2}
    assert proxy._DESTINATIONS._semaphores == {} and proxy._FAIR_SHARE.in_flight == {}


def test_a_waiting_request_is_served_when_one_to_that_host_ends(pool, monkeypatch):
    async def scenario():
        gates = [asyncio.Event() for _ in range(2)]
        order = []
        _install(monkeypatch, pool, asyncio.Event(), dest_limit=1, dest_wait=5)

        async def relay(*_a, **_k):
            idx = len(order)
            order.append(idx)
            await gates[idx].wait()

        monkeypatch.setattr(proxy, "_relay", relay)
        one = await _open(ENG_A)
        await asyncio.sleep(0.1)
        two = await _open(ENG_A)
        await asyncio.sleep(0.1)
        before = len(order)
        gates[0].set()
        await asyncio.sleep(0.2)
        after = len(order)
        gates[1].set()
        await asyncio.gather(one[0], two[0])
        return before, after

    assert asyncio.run(scenario()) == (1, 2)


def test_negative_with_the_cap_off_nothing_waits(pool, monkeypatch):
    async def scenario():
        hold = asyncio.Event()
        _install(monkeypatch, pool, hold, dest_limit=0)
        tasks = [await _open(ENG_A) for _ in range(30)]
        await asyncio.sleep(0.2)
        active = pool.active
        hold.set()
        await asyncio.gather(*(t for t, _ in tasks))
        return active

    assert asyncio.run(scenario()) == 30


def test_a_proxy_bound_to_one_engagement_is_unchanged_and_shares_with_nobody(pool, monkeypatch):
    async def scenario():
        hold = asyncio.Event()
        _install(monkeypatch, pool, hold)
        monkeypatch.setattr(proxy, "DEFAULT_ENGAGEMENT_ID", ENG_A)
        tasks = [await _open(ENG_B) for _ in range(100)]     # the header names B, the bound engagement wins
        await asyncio.sleep(0.3)
        held = dict(proxy._FAIR_SHARE.in_flight)
        hold.set()
        await asyncio.gather(*(t for t, _ in tasks))
        return held

    held = asyncio.run(scenario())
    assert set(held) == {ENG_A} and held[ENG_A] == 56
