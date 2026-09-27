---
title: Authentication and authorization verification
status: ready
risk: R4
owner: security-engineering
---

# Authentication and Authorization Verification

Verifies [`../requirements/authentication-and-authorization.md`](../requirements/authentication-and-authorization.md).

## TC-IAM-002: Individual accounts replace the shared operator token

Requirements:

- REQ-IAM-002

Automated tests:

- `control-plane/tests/test_passwords.py`
- `control-plane/tests/integration/test_auth_flows.py`
- `control-plane/tests/integration/test_engagement_ownership_http.py`
- `control-plane/tests/test_production_config.py`

Objective:

Verify passwords are Argon2id-hashed (never stored/comparable raw), the
legacy shared token is rejected in production configuration, and an
authenticated request via a real per-user session succeeds through the
actual HTTP routing layer.

Expected results:

- `hash_secret`/`verify_secret` round-trip correctly and never expose the
  raw value; a malformed hash fails closed, not with an exception.
- `Settings(environment="production", ...)` without a real
  `mfa_encryption_key` raises a validation error.
- An HTTP request with no credentials against a public route returns 401; a
  request with a valid per-user session token succeeds.

## TC-IAM-003: Login requires a password and a mandatory TOTP second factor

Requirements:

- REQ-IAM-003

Automated tests:

- `control-plane/tests/test_mfa.py`
- `control-plane/tests/integration/test_auth_flows.py`

Objective:

Verify no session is ever issued from a password alone, TOTP verification
follows RFC 6238 with clock-skew tolerance and single-use-per-step replay
protection, and wrong-password/unknown-email/wrong-code all fail the same
generic way.

Expected results:

- `authenticate_password` returns a next-step status, never a session.
- `verify_code` accepts the current step and one step of skew, rejects a
  malformed code, and rejects replay of an already-used step.
- `authenticate_password` raises the same `AuthError` for an unknown email
  and for a wrong password.
- A full login (password -> MFA verify) yields a session that
  `resolve_session` recognizes.

## TC-IAM-004: MFA enrollment is mandatory before first use, self-service to reset

Requirements:

- REQ-IAM-004

Automated tests:

- `control-plane/tests/test_mfa.py`
- `control-plane/tests/integration/test_auth_flows.py`

Objective:

Verify a fresh invited account must set its password and confirm TOTP
enrollment before any session exists, backup codes are issued exactly once
and are single-use, secrets are encrypted at rest (decryptable only via the
app's key), re-enrollment requires the current password and replaces the
prior secret/codes, and an admin can force a reset without the user's
password.

Expected results:

- The full first-login flow (temp password -> set password -> enroll ->
  confirm) ends with a valid session and 10 unique backup codes.
- A backup code works once; a second use of the same code fails.
- `start_mfa_reenrollment` rejects a wrong current password; a correct one
  replaces the stored (encrypted) secret.
- `admin_reset_mfa` clears the secret/confirmation/backup codes and revokes
  all of that user's sessions.

## TC-IAM-005: Sessions are server-side, revocable, and time-bounded

Requirements:

- REQ-IAM-005

Automated tests:

- `control-plane/tests/test_sessions.py`
- `control-plane/tests/integration/test_auth_flows.py`

Objective:

Verify only a hash of the session token is ever stored, an expired or
revoked session is rejected, logout revokes immediately, and disabling a
user revokes all of their active sessions.

Expected results:

- `hash_token` is deterministic but never equals the raw token; two
  generated tokens/hashes never collide in a test run.
- A session past `expires_at` is rejected by `resolve_session`.
- `revoke_session_by_token` makes the session unresolvable immediately.
- `revoke_all_sessions` (triggered by admin-disable) invalidates every
  active session for that user.

## TC-IAM-006: Brute-force protection on both factors

Requirements:

- REQ-IAM-006

Automated tests:

- `control-plane/tests/integration/test_auth_flows.py`

Objective:

Verify repeated failed password attempts lock the account (even the correct
password is then rejected until the lockout expires), a successful login
resets the failure counter, and repeated failed MFA attempts against one
challenge kill it after a bounded number of tries.

Expected results:

- After `LOCKOUT_THRESHOLD` failed password attempts, `locked_until` is set
  in the future and even the correct password is rejected.
- A subsequent successful login resets `failed_password_count` to 0.
- After `MAX_CHALLENGE_ATTEMPTS` failed MFA attempts, the same challenge
  rejects even a subsequently-correct code.

## TC-IAM-007: Per-user engagement ownership with admin oversight

Requirements:

- REQ-IAM-007

Automated tests:

- `control-plane/tests/integration/test_engagement_ownership_http.py`

Objective:

Verify ownership enforcement at the real HTTP routing layer (not just
direct function calls): an operator can only reach their own engagement, a
non-owner gets 404 (not 403), an admin can reach and list every engagement,
`GET /engagements` is scoped to the caller unless admin, and a
client-supplied `owner_user_id` on create is always overridden by the
caller's own identity.

Expected results:

- `GET /engagements/{id}` as the owner: 200. As a different non-admin
  user: 404. As an admin: 200.
- `GET /engagements` as an operator returns only that operator's own
  engagements; as an admin, all of them.
- `POST /engagements` with a spoofed `owner_user_id` in the body still
  persists `owner_user_id` as the authenticated caller's id.

## TC-IAM-008: Admin-only user management, invite-only provisioning

Requirements:

- REQ-IAM-008

Automated tests:

- `control-plane/tests/integration/test_admin_users.py`
- `control-plane/tests/integration/test_engagement_ownership_http.py`

Objective:

Verify only an admin can create/list/update accounts, a new account starts
`invited` with `must_change_password=true` and a one-time temporary
password, duplicate emails and invalid roles are rejected, disabling a user
revokes their sessions, and a non-admin is refused at the HTTP layer
(`/admin/*`).

Expected results:

- `create_user` returns a temporary password of sufficient length; the
  stored account is `invited`/`must_change_password=true`.
- A duplicate email returns 409; an invalid role returns 422.
- `update_user(status="disabled")` revokes the target's active sessions.
- `GET /admin/users` returns 403 for a non-admin session, 200 for an admin
  session.

## TC-IAM-009: Tamper-evident audit trail for account/security events

Requirements:

- REQ-IAM-009

Automated tests:

- `control-plane/tests/integration/test_account_audit_chain.py`

Objective:

Verify `account_audit_log` forms one unbroken, tamper-evident global chain
under concurrent appends (mirroring the existing per-engagement audit-chain
test), and that its writer function has no parameter through which a raw
credential could be logged.

Expected results:

- 16 concurrent appends form exactly one chain from the genesis
  (`prev_hash=None`) through all 16 rows, no duplicates, no breaks.
- `append_account_audit_log`'s signature has no `password`/`code`/`token`
  parameter.

## TC-IAM-011: Safe migration off the shared token

Requirements:

- REQ-IAM-011

Automated tests:

- `control-plane/tests/integration/conftest.py` (schema/migration application)
- `control-plane/scripts/bootstrap_admin.py` (manual/staged verification)

Objective:

Verify the migration applies cleanly (exercised by every integration test
in this suite, which rebuilds the schema from the full migration set
including `0016_authentication.sql`), and the bootstrap script creates
exactly one admin account per email and is safe to re-run.

Expected results:

- The full integration suite (258 tests) passes against a schema built from
  all migrations in order, including the new auth tables and
  `engagement.owner_user_id`.
- Running `bootstrap_admin.py` twice with the same `INITIAL_ADMIN_EMAIL`
  creates the account once and no-ops on the second run (verified manually
  during rollout per the architecture doc's §9 plan).
