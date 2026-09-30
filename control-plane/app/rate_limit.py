"""GitHub issue #31 (REQ-IAM-016/017): a per-source-IP rate limit in front of
the unauthenticated login steps, and a client address a client cannot choose.

The per-account lockout (auth_service) protects one account. This limit slows
a single source that spreads guesses across many accounts, or times them to
stay under each account's lockout. It is keyed by source IP only, so it can
never be used to lock a user out from somewhere else.

Counts live in Redis, shared by every control-plane worker and replica. If
Redis is unreachable, a per-process window takes over (still a brake, just
per process) instead of failing open, and Redis is not asked again for a
short while so a dead Redis does not slow every login down.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
from functools import lru_cache

import redis
from fastapi import HTTPException, Request

from app.config import get_settings

logger = logging.getLogger(__name__)

_REDIS_RETRY_AFTER_FAILURE_SECONDS = 30.0
_KEY_PREFIX = "asm:login-rate:"


# --- the client's address ------------------------------------------------------

@lru_cache(maxsize=8)
def _networks(spec: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    nets = []
    for part in spec.split(","):
        part = part.strip()
        if part:
            nets.append(ipaddress.ip_network(part, strict=False))
    return tuple(nets)


def _parse_ip(value: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address((value or "").strip())
    except ValueError:
        return None


def _is_trusted_proxy(value: str | None) -> bool:
    addr = _parse_ip(value)
    return addr is not None and any(addr in net for net in _networks(get_settings().trusted_proxy_cidrs))


def client_ip(request: Request) -> str | None:
    """The address of the client that sent this request.

    `X-Forwarded-For` counts only when the direct peer is a trusted proxy (the
    edge): anyone else could simply write their own header. Behind the edge,
    the nearest forwarded address that is not itself a trusted proxy is the
    client."""
    peer = request.client.host if request.client else None
    forwarded = request.headers.get("x-forwarded-for")
    if not forwarded or not _is_trusted_proxy(peer):
        return peer
    hops = [hop.strip() for hop in forwarded.split(",") if hop.strip()]
    for hop in reversed(hops):
        if _parse_ip(hop) is None:
            return peer  # a malformed hop: do not trust the rest of the chain
        if not _is_trusted_proxy(hop):
            return hop
    return hops[0] if hops else peer


# --- counting ------------------------------------------------------------------

class _LocalWindow:
    """Fixed window per key, for when Redis is unreachable."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._windows: dict[str, tuple[float, int]] = {}

    def hit(self, key: str, window: int) -> tuple[int, int]:
        now = time.monotonic()
        with self._lock:
            if len(self._windows) > 10_000:  # drop expired windows now and then
                self._windows = {k: v for k, v in self._windows.items() if now - v[0] < window}
            start, count = self._windows.get(key, (now, 0))
            if now - start >= window:
                start, count = now, 0
            count += 1
            self._windows[key] = (start, count)
            return count, max(1, int(window - (now - start)))

    def reset(self) -> None:
        with self._lock:
            self._windows.clear()


_local = _LocalWindow()
_redis_client: redis.Redis | None = None
_redis_skip_until = 0.0


def _redis() -> redis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.Redis.from_url(
            get_settings().redis_url, socket_timeout=0.5, socket_connect_timeout=0.5,
        )
    return _redis_client


def _redis_hit(key: str, window: int) -> tuple[int, int]:
    """One atomic MULTI/EXEC: count this attempt, start the window on the first
    one, and read how long the window still runs."""
    pipe = _redis().pipeline(transaction=True)
    pipe.incr(key)
    pipe.expire(key, window, nx=True)
    pipe.ttl(key)
    count, _, ttl = pipe.execute()
    return int(count), int(ttl) if ttl and int(ttl) > 0 else window


def _hit(key: str, window: int) -> tuple[int, int]:
    global _redis_skip_until
    if time.monotonic() >= _redis_skip_until:
        try:
            return _redis_hit(key, window)
        except redis.RedisError as exc:
            _redis_skip_until = time.monotonic() + _REDIS_RETRY_AFTER_FAILURE_SECONDS
            logger.warning("login rate limit: Redis unreachable (%s) - using the per-process window", exc)
    return _local.hit(key, window)


def enforce_login_rate_limit(request: Request) -> None:
    """FastAPI dependency for the unauthenticated login steps: 429 with
    Retry-After once a source address exceeds the configured attempts."""
    settings = get_settings()
    limit, window = settings.login_rate_limit_attempts, settings.login_rate_limit_window_seconds
    if limit <= 0:
        return
    ip = client_ip(request) or "unknown"
    count, retry_after = _hit(_KEY_PREFIX + ip, window)
    if count > limit:
        if count == limit + 1:
            logger.warning("login rate limit reached for %s (%d attempts in %ds)", ip, limit, window)
        raise HTTPException(
            429, "too many sign-in attempts from this address - try again later",
            headers={"Retry-After": str(retry_after)},
        )


def reset_for_tests() -> None:
    """Forget every window and the Redis failure state (tests only)."""
    global _redis_skip_until, _redis_client
    _local.reset()
    _redis_skip_until = 0.0
    _redis_client = None
