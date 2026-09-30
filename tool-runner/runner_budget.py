"""Per-request time budget for the HexStrike execution boundary (REQ-PIPE-007).

Upstream HexStrike kills every command at a fixed 300 s. That cap decided how
much one scan step could do (a nuclei selection had to be cut into pieces just
to fit under it). The worker now declares a budget per check and the runner
enforces it, bounded by a hard maximum a request can never raise.

Stdlib only, like runner_auth.py, so the rule is unit-testable without Flask
and is injected into the vendored server by patch_hexstrike.py.
"""

from __future__ import annotations

BUDGET_HEADER = "X-ASM-Timeout-Seconds"
HARD_MAX_SECONDS = 1800


def command_timeout(requested: str | int | None, default_seconds: int) -> int:
    """The time budget to enforce for one command.

    A missing, malformed or non-positive request gets the runner default; a
    request above the hard maximum is clamped to it (never refused, never
    honoured beyond it). The default itself is also bounded, so a misconfigured
    default cannot exceed the maximum either.
    """
    default = max(1, min(int(default_seconds), HARD_MAX_SECONDS))
    if requested is None:
        return default
    try:
        seconds = int(str(requested).strip())
    except (TypeError, ValueError):
        return default
    if seconds <= 0:
        return default
    return min(seconds, HARD_MAX_SECONDS)
