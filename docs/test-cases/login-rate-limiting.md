---
title: Login rate limiting verification
status: ready
risk: R3
owner: security-engineering
---

# Login Rate Limiting Verification

Verifies [`../requirements/login-rate-limiting.md`](../requirements/login-rate-limiting.md).
The Redis test runs against a real Redis when `TEST_REDIS_URL` is set (it was,
on 2026-09-29, with a throwaway `redis:7-alpine`); without it the test is
skipped and the fallback path is still tested.

## TC-IAM-016: Per-address throttling of the login steps

Requirements:

- REQ-IAM-016

Automated tests:

- `control-plane/tests/integration/test_login_rate_limit.py`
- `frontend/tests/console_information_architecture.test.mjs`

Objective:

Prove one address is throttled across accounts and steps, without affecting
other addresses or any account's lockout, with and without Redis.

Expected results:

- `test_negative_a_burst_from_one_address_is_throttled_across_many_accounts` - `429`, `Retry-After` 1-300.
- `test_a_different_address_is_not_affected` - the same account signs in from another address.
- `test_negative_the_throttle_does_not_lock_the_account` - `failed_password_count` stays 0.
- `test_every_login_step_counts_against_the_same_address`, `test_signed_in_requests_are_not_limited`.
- `test_without_redis_the_per_process_window_still_throttles_and_redis_is_not_retried`, `test_with_redis_the_count_is_shared_between_processes`.
- The login page maps `429` to its own message.

## TC-IAM-017: Client address

Requirements:

- REQ-IAM-017

Automated tests:

- `control-plane/tests/integration/test_login_rate_limit.py`

Objective:

Prove the client address can only come from a trusted proxy.

Expected results:

- `test_negative_a_direct_client_cannot_pick_its_own_address`, `test_behind_the_edge_each_forwarded_client_has_its_own_window`.
- `test_client_ip` - eight header/peer combinations, including chains, trusted hops, and a malformed hop.

## Live verification (2026-10-01, dev stack)

Only our own platform was exercised (no scan, no target). The source address was simulated with
`X-Forwarded-For` from localhost, a trusted peer (REQ-IAM-017), and a nonexistent account was used
so that no real account's lockout counter moved. Thirty-five login attempts from one address: the
first 30 answered `401`, attempts 31 to 35 answered `429` with `Retry-After: 298`; the next attempt
from a different address answered `401`, unaffected. The throttle also persisted across a second
run inside the same window (the first attempt of that run was already `429`).
