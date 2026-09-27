"""Shared-secret authentication for the raw-egress gateway's internal API.

GitHub issue #22. The reservation endpoints (/v1/reservations/acquire,
/v1/reservations/release) accepted unauthenticated requests: any peer that
can reach port 8765 could exhaust every raw-scanning slot with fresh UUIDs,
or release another run's reservation with only a guessed/observed
scan_run_id. The lease endpoints below them ARE protected - they require an
HMAC-signed lease_token, the control plane's actual authority to emit
packets - but the reservation layer had no equivalent check at all.

Mirrors tool-runner/runner_auth.py's shape exactly (same fail-closed
contract, same reasoning): dependency-free (stdlib only) so it is directly
unit-testable, /health stays open for the Compose/K8s liveness probe, every
other path requires a configured token AND a caller-supplied token matching
it in constant time, and a MISSING configured token denies everything
non-health rather than silently accepting unauthenticated requests.
"""

from __future__ import annotations

import hmac
import os

RAW_EGRESS_TOKEN_HEADER = "X-ASM-RawEgress-Token"
_UNAUTHENTICATED_PATHS = frozenset({"/health"})
_DEV_DEFAULT_TOKEN = "raw-egress-api-change-me-in-dev"


def enforce_production_token(environment: str | None, configured_token: str | None) -> None:
    """Fail closed at startup in production if the token is missing or still
    the dev default. Mirrors tool-runner/runner_auth.py's own guard and this
    module's sibling RAW_EGRESS_SIGNING_SECRET guard in app/main.py - a
    different secret (that one signs lease payloads; this one authenticates
    the caller) with the same fail-closed contract. No-op outside
    production so dev/lab start out of the box."""
    if (environment or "").strip().lower() != "production":
        return
    if not configured_token or configured_token == _DEV_DEFAULT_TOKEN:
        raise RuntimeError("insecure production configuration: raw_egress_api_token")


def is_authorized(path: str, provided_token: str | None, configured_token: str | None) -> bool:
    """Return True iff this request may reach the gateway's reservation/lease
    API. `path` is the request path (e.g. "/v1/reservations/acquire").
    `provided_token` is the caller-supplied secret (RAW_EGRESS_TOKEN_HEADER,
    may be None). `configured_token` is this gateway's own
    RAW_EGRESS_API_TOKEN."""
    if path in _UNAUTHENTICATED_PATHS:
        return True
    if not configured_token or not provided_token:
        return False
    return hmac.compare_digest(str(provided_token), str(configured_token))
