"""Fair use of the proxy's client slots (REQ-EGRESS-012/013, GitHub #81 step 4).

The proxy has one pool of client slots for every engagement. Once it knows whose request it is, this module decides
whether that engagement may take another, and optionally how many requests may be in flight to one destination.
Single-threaded asyncio: every method is a plain synchronous read-modify-write with no `await` inside, so no lock is needed.
"""

from __future__ import annotations

import asyncio
import time
from typing import Callable


class FairShare:
    """Each active engagement gets a share of `total` slots; a lone engagement keeps `reserve` free for a newcomer."""

    def __init__(self, total: int, reserve: int, min_share: int, window_s: float, clock: Callable[[], float] = time.monotonic):
        self.total = max(1, int(total))
        self.reserve = max(0, min(int(reserve), self.total - 1))
        self.min_share = max(1, int(min_share))
        self.window_s = float(window_s)
        self._clock = clock
        self.in_flight: dict[str, int] = {}
        self._last_seen: dict[str, float] = {}

    def _active(self, including: str) -> int:
        now = self._clock()
        recent = {e for e, seen in self._last_seen.items() if now - seen <= self.window_s}
        recent.update(e for e, n in self.in_flight.items() if n > 0)
        recent.add(including)
        for gone in [e for e in self._last_seen if e not in recent]:
            del self._last_seen[gone]
        return len(recent)

    def limit_for(self, engagement_id: str) -> int:
        k = self._active(engagement_id)
        if k <= 1:
            return max(1, self.total - self.reserve)
        return max(self.min_share, self.total // k)

    def try_acquire(self, engagement_id: str) -> bool:
        limit = self.limit_for(engagement_id)
        self._last_seen[engagement_id] = self._clock()
        if self.in_flight.get(engagement_id, 0) >= limit:
            return False
        self.in_flight[engagement_id] = self.in_flight.get(engagement_id, 0) + 1
        return True

    def release(self, engagement_id: str) -> None:
        left = self.in_flight.get(engagement_id, 0) - 1
        if left > 0:
            self.in_flight[engagement_id] = left
        else:
            self.in_flight.pop(engagement_id, None)


class DestinationGate:
    """At most `limit` requests in flight to one destination host, across engagements; the rest wait a bounded time."""

    def __init__(self, limit: int, wait_s: float):
        self.limit = max(0, int(limit))
        self.wait_s = float(wait_s)
        self._semaphores: dict[str, asyncio.Semaphore] = {}
        self._users: dict[str, int] = {}

    @property
    def enabled(self) -> bool:
        return self.limit > 0

    async def acquire(self, host: str) -> bool:
        """True once the caller holds a place for `host` (release it with `release`); False when none became free in time.
        With the gate off it returns True at once and `release` does nothing."""
        if not self.enabled:
            return True
        key = host.lower().rstrip(".")
        semaphore = self._semaphores.setdefault(key, asyncio.Semaphore(self.limit))
        self._users[key] = self._users.get(key, 0) + 1   # counted while waiting, so the entry is not dropped under a waiter
        try:
            await asyncio.wait_for(semaphore.acquire(), timeout=self.wait_s)
        except asyncio.TimeoutError:
            self._forget(key)
            return False
        except BaseException:
            self._forget(key)   # cancelled while waiting (the client went away): leave nothing behind
            raise
        return True

    def release(self, host: str) -> None:
        if not self.enabled:
            return
        key = host.lower().rstrip(".")
        semaphore = self._semaphores.get(key)
        if semaphore is not None:
            semaphore.release()
        self._forget(key)

    def _forget(self, key: str) -> None:
        left = self._users.get(key, 0) - 1
        if left > 0:
            self._users[key] = left
        else:
            self._users.pop(key, None)
            self._semaphores.pop(key, None)

    def in_use(self, host: str) -> int:
        key = host.lower().rstrip(".")
        semaphore = self._semaphores.get(key)
        return 0 if semaphore is None else self.limit - semaphore._value  # noqa: SLF001 - read-only, for tests and logs
