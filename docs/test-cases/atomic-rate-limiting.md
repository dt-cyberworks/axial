---
title: Atomic rate limiting verification
status: ready
risk: R3
owner: security-engineering
---

# Atomic Rate Limiting Verification

Verifies REQ-RATE-005 in [`../requirements/scan-rate-policy.md`](../requirements/scan-rate-policy.md).
These tests need a real PostgreSQL (`TEST_DATABASE_URL`): the guarantee is a
database lock, which a mock cannot show.

## TC-RATE-005: Slots are reserved before the call goes ahead

Requirements:

- REQ-RATE-005

Automated tests:

- `control-plane/tests/integration/test_rate_reservation.py`
- `control-plane/tests/integration/test_gateway_fractional_rate.py`
- `egress-proxy/tests/test_rate_and_concurrency.py`
- `egress-proxy/tests/test_bounty_ident_header_optional.py`
- `egress-proxy/tests/test_port_scope.py`

Objective:

Prove concurrent callers cannot exceed the limit on either path, that calls
which do not go ahead give their slot back, and that the proxy fails closed.

Expected results:

- `test_negative_concurrent_gateway_calls_never_exceed_the_limit` - N simultaneous `authorize()` calls, exactly one `ALLOW` at 0.2 rps.
- `test_negative_concurrent_reservations_never_exceed_the_limit` and `test_negative_concurrent_proxy_reservations_never_exceed_the_limit` - a barrier releases all threads at once; granted slots never exceed the threshold.
- `test_negative_a_call_that_hits_the_budget_gives_its_slot_back`, `test_negative_a_call_that_waits_for_approval_gives_its_slot_back`.
- `test_negative_the_proxy_endpoint_refuses_without_a_bounty_program`, `test_engagements_are_counted_separately`, `test_gateway_and_proxy_paths_have_their_own_counter`.
- `test_gateway_fractional_rate.py` - issue #19's widened windows against the reservation primitive.
- Proxy tests: no reserved slot means no forwarding; an unreachable control plane fails closed.

## Live verification (2026-10-01, dev and int)

The gateway path is exercised by every real scan: within the last hour of the dev scans of
2026-09-30/10-01 the gateway wrote 41 `rate_reservation` rows (path `gateway`), and on int 26 during
the UAT scan journey; those scans completed normally with the reservation in front of each call
(older rows are purged by the reservation itself after an hour, so the counts are a floor).

Not exercised live: the proxy path, which only applies to bug-bounty engagements. None exists on
dev or int, so the atomicity of that path rests on the barrier-synchronized concurrent tests
above, which is the acceptance criterion of GitHub issue #40. A live check would need a bug-bounty
engagement with a program policy and is left to the first real use.
