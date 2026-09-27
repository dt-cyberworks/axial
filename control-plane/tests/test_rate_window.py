"""GitHub issue #19: a fixed 1-second window cannot express "less than 1
request per second" - max(1, int(max_rps)) alone let any max_rps < 1
silently permit up to 1 req/s (2x-5x over the configured limit)."""

from __future__ import annotations

import pytest

from app.gateway.authorize import _effective_rate_window


#: GitHub issue #19's acceptance table - kept as ONE literal both this file
#: and egress-proxy/tests/test_rate_and_concurrency.py parametrize against,
#: so the two independently-maintained copies (control-plane's gateway and
#: the egress-proxy - deliberately duplicated, not a shared import, same
#: defense-in-depth reasoning as _matches_host's own cross-reference) are
#: pinned to agree on every value, not just individually self-consistent.
RATE_WINDOW_CASES = [
    (0.2, 5), (0.5, 2), (1.0, 1.0), (1.5, 1.0), (2.5, 1.0), (7.0, 1.0),
]


@pytest.mark.parametrize("max_rps,expected_window", RATE_WINDOW_CASES)
def test_effective_rate_window_widens_only_below_one(max_rps, expected_window):
    assert _effective_rate_window(max_rps) == expected_window
