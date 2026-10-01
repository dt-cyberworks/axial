"""Authenticated proxy-to-control-plane audit submission."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)

CONTROL_PLANE_URL = os.environ.get("CONTROL_PLANE_URL", "http://control-plane:8000").rstrip("/")
INTERNAL_API_TOKEN = os.environ.get("INTERNAL_API_TOKEN", "change-me-in-dev")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "development").lower()
if ENVIRONMENT == "production" and INTERNAL_API_TOKEN in {"", "change-me-in-dev"}:
    raise RuntimeError("insecure production configuration: internal_api_token")


def submit_audit(engagement_id: str, decision: str, reason: str, payload: dict) -> None:
    body = json.dumps(
        {
            "decision": decision,
            "reason": reason,
            "payload": payload,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{CONTROL_PLANE_URL}/internal/engagements/{engagement_id}/proxy-audit",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-ASM-Internal-Token": INTERNAL_API_TOKEN,
        },
    )
    with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310 - fixed internal base URL
        if response.status != 201:
            raise RuntimeError(f"audit ingestion returned {response.status}")



# GitHub issue #49: a 503 from the batch endpoint means "no database slot free" and
# is returned BEFORE anything is written, so it is the one failure that is safe to
# retry without risking a duplicated audit record. Any other failure (a timeout may
# have committed) is not retried: the caller denies the requests, fail closed.
_BATCH_ATTEMPTS = 3
_BATCH_BACKOFF_SECONDS = 0.1


def submit_audit_batch(engagement_id: str, events: list[dict]) -> None:
    """Send the audit events of one engagement in one request (one lock, one
    commit on the control plane). All or nothing; raises unless it got a 201."""
    body = json.dumps({"events": events}).encode("utf-8")
    for attempt in range(1, _BATCH_ATTEMPTS + 1):
        request = urllib.request.Request(
            f"{CONTROL_PLANE_URL}/internal/engagements/{engagement_id}/proxy-audit/batch",
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", "X-ASM-Internal-Token": INTERNAL_API_TOKEN},
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310 - fixed internal base URL
                if response.status != 201:
                    raise RuntimeError(f"audit batch ingestion returned {response.status}")
                return
        except urllib.error.HTTPError as exc:
            if exc.code != 503 or attempt == _BATCH_ATTEMPTS:
                raise
            time.sleep(_BATCH_BACKOFF_SECONDS * attempt)


class AuditBatcher:
    """Adaptive group commit for the proxy's audit events (GitHub issue #49).

    The proxy used to send one blocking request to the control plane per proxied
    request - 100+ per second during a scan, each holding a control-plane database
    connection and queueing on the engagement's audit lock. Now the first event of an
    idle engagement is sent at once (no added latency), and events that arrive while
    that send is in flight go out together in the next one (up to `max_batch`).

    Fail-closed is unchanged (REQ-EGRESS-003): `submit` returns only after the event's
    batch was committed, so a request is never forwarded before its audit record
    exists, and when a batch fails every request waiting on it gets the exception
    and is denied. Nothing is dropped silently or sent fire-and-forget.
    """

    def __init__(self, send, *, max_batch: int = 100, max_inflight: int = 4):
        self._send = send  # blocking callable(engagement_id, events); raises on failure
        self._max_batch = max_batch
        self._max_inflight = max_inflight
        self._pending: dict[str, list[tuple[dict, asyncio.Future]]] = {}
        self._draining: set[str] = set()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._slots: asyncio.Semaphore | None = None

    def _limiter(self) -> asyncio.Semaphore:
        loop = asyncio.get_running_loop()
        if self._slots is None or self._loop is not loop:
            self._loop, self._slots = loop, asyncio.Semaphore(self._max_inflight)
        return self._slots

    async def submit(self, engagement_id: str, decision: str, reason: str, payload: dict) -> None:
        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        event = {"decision": decision, "reason": reason, "payload": payload}
        self._pending.setdefault(engagement_id, []).append((event, future))
        if engagement_id not in self._draining:
            self._draining.add(engagement_id)
            loop.create_task(self._drain(engagement_id))
        await future

    async def _drain(self, engagement_id: str) -> None:
        try:
            while self._pending.get(engagement_id):
                queue = self._pending[engagement_id]
                batch = queue[: self._max_batch]
                del queue[: len(batch)]
                try:
                    async with self._limiter():
                        await asyncio.to_thread(self._send, engagement_id, [event for event, _ in batch])
                except BaseException as exc:  # noqa: BLE001 - every waiter must be answered
                    if isinstance(exc, Exception):
                        logger.error("audit batch of %d event(s) for engagement %s failed: %s",
                                     len(batch), engagement_id, exc)
                    for _, future in batch:
                        if not future.done():
                            future.set_exception(exc if isinstance(exc, Exception) else RuntimeError("audit batcher stopped"))
                    if not isinstance(exc, Exception):
                        raise
                else:
                    for _, future in batch:
                        if not future.done():
                            future.set_result(None)
        finally:
            self._draining.discard(engagement_id)
            leftover = self._pending.pop(engagement_id, [])
            for _, future in leftover:  # only reachable when the task was cancelled
                if not future.done():
                    future.set_exception(RuntimeError("audit batcher stopped"))


def reserve_rate_slot(engagement_id: str) -> dict:
    """GitHub issue #40: reserve one slot of the program's max_rps before
    forwarding (reserve first, then act). Raises on any failure; the caller
    denies (fail closed), exactly like a failed audit submission."""
    request = urllib.request.Request(
        f"{CONTROL_PLANE_URL}/internal/engagements/{engagement_id}/rate-reservation",
        data=b"{}",
        method="POST",
        headers={"Content-Type": "application/json", "X-ASM-Internal-Token": INTERNAL_API_TOKEN},
    )
    with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310 - fixed internal base URL
        if response.status != 200:
            raise RuntimeError(f"rate reservation returned {response.status}")
        return json.loads(response.read().decode("utf-8"))
