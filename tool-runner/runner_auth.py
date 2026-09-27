"""Shared-secret authentication for the HexStrike execution boundary.

REQ-HARDEN-001. The HexStrike server exposes ``/api/command`` (arbitrary
shell execution) and ``/api/tools/*`` on ``0.0.0.0`` and, upstream, has NO
authentication at all. In the Compose topology the runner shares a network
namespace with ``raw-egress-gateway`` and is reachable from the ``runner``,
``egress`` and ``control`` networks - including from the ``egress-proxy``,
which parses untrusted scan-target responses. A single parsing bug there
would otherwise become arbitrary command execution in the offensive runner.

This module is deliberately dependency-free (only the stdlib) so the same
predicate can be unit-tested directly AND injected into the vendored
``hexstrike_server.py`` by ``patch_hexstrike.py`` without importing Flask.

The check is intentionally minimal and fail-closed:
  * ``/health`` is always allowed (the Compose/K8s liveness probe carries no
    secret and reveals nothing).
  * every other path requires a configured token AND a caller-supplied token
    that matches it in constant time.
  * if no token is configured, every non-health request is denied - a
    misconfigured runner must not silently accept unauthenticated commands.
"""

from __future__ import annotations

import hmac
import os

RUNNER_TOKEN_HEADER = "X-ASM-Runner-Token"
_UNAUTHENTICATED_PATHS = frozenset({"/health"})
_DEV_DEFAULT_TOKEN = "runner-change-me-in-dev"


def enforce_production_token(environment: str | None, configured_token: str | None) -> None:
    """Fail closed at startup in production if the runner token is missing or
    still the dev default - a production execution boundary must never run with
    a guessable secret. Mirrors the raw-egress-gateway/egress-proxy startup
    guards. No-op outside production so dev/lab start out of the box."""
    if (environment or "").strip().lower() != "production":
        return
    if not configured_token or configured_token == _DEV_DEFAULT_TOKEN:
        raise RuntimeError("insecure production configuration: runner_api_token")


def is_authorized(path: str, provided_token: str | None, configured_token: str | None) -> bool:
    """Return True iff this request may reach the execution engine.

    ``path`` is the request path (e.g. ``/api/command``). ``provided_token``
    is the caller-supplied secret (``X-ASM-Runner-Token`` header, may be
    ``None``). ``configured_token`` is the runner's own ``RUNNER_API_TOKEN``.
    """
    if path in _UNAUTHENTICATED_PATHS:
        return True
    if not configured_token or not provided_token:
        return False
    return hmac.compare_digest(str(provided_token), str(configured_token))


# Executed when the patched hexstrike_server.py imports this module: refuse to
# start an insecure production execution boundary (REQ-HARDEN-001).
enforce_production_token(os.environ.get("ENVIRONMENT"), os.environ.get("RUNNER_API_TOKEN"))
