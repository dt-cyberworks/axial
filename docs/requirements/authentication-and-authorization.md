---
title: Authentication and authorization (multi-user, MFA-protected login)
status: draft
risk: R4
owner: security-engineering
---

# Authentication and Authorization

Today the operator console (and every public API route) is protected by a
single shared secret (`operator_api_token`), compared against a static
`.env` value. There are no individual accounts, no second factor, and no
per-user data boundary — anyone holding the one token has full access to
everything. This document defines a real multi-user login system so the
console can be deployed on a public-internet VPS (e.g. IONOS) and still be
safe: individual accounts, mandatory TOTP MFA, and per-user engagement
ownership with an admin oversight role.

This extends
[`REQ-IAM-001`](minimum-safe-operation.md) (`minimum-safe-operation.md`),
which explicitly scoped itself to "a single trusted operator... does not
claim multi-tenant readiness. RBAC, workload identity, and runner-bound
dispatch artifacts remain required before expanding the operating model" —
this document is that expansion. REQ-IAM-001's own acceptance criteria
(every public endpoint requires authentication, `/health` stays open,
internal endpoints keep their separate credential, actor identity is
server-derived, failures are audited) remain true throughout; nothing here
weakens them, it replaces *who* the credential represents.

**Risk class: R4** (`docs/engineering/sdlc.md` §2: "new active capability,
widened egress, destructive potential" — this introduces the primary human
authentication boundary for an internet-facing deployment). Requires
explicit human authorization, security review, negative tests, and staged
rollout. Decided with the user 2026-07-27: TOTP as the MFA factor,
per-user engagement ownership with an admin role, admin-invited-only
provisioning (no public self-registration).

Tests must verify these requirements directly. Do not weaken tests to match
implementation; update implementation when it violates this document.

---

## REQ-IAM-002: Individual accounts replace the shared operator token

Context: `require_operator` (`app/security.py`) accepts any caller who
presents the one configured `operator_api_token`, via Bearer header,
`X-ASM-Operator-Token`, or the `asm_operator_session` cookie (which today
literally *is* the shared token). No caller identity is recorded beyond the
generic string `"operator"`.

Acceptance criteria:
- A new `app_user` record represents one individual: unique email, password
  hash (Argon2id — OWASP-recommended, memory-hard), display name, role
  (`admin` | `operator`), status (`invited` | `active` | `disabled`),
  `must_change_password` flag, timestamps.
- Passwords are never stored or logged in plaintext; the raw password never
  appears in any audit payload.
- In `environment=production`, the shared `operator_api_token` path is
  rejected outright (fails closed) — only individual accounts authenticate.
  In non-production environments it remains available as a dev/test
  convenience (mirrors the existing `ENVIRONMENT == "production"` guard
  pattern already used for `internal_api_token`/`scope_signing_secret`),
  so existing local dev workflows and the automated test suite are not
  broken by this change.
- Every subsequent authenticated action's audit trail records the acting
  user's id/email, not the generic string `"operator"`.

## REQ-IAM-003: Login requires a password and a mandatory TOTP second factor

Acceptance criteria:
- `POST /auth/login` with email+password never returns a usable session by
  itself. On success it returns a short-lived, single-use login challenge
  (5 minute expiry) whose state is either "MFA verification required"
  (account already enrolled) or "MFA enrollment required" (first login).
- A session is issued ONLY after a valid TOTP code (or a valid unused
  backup code) is presented against that specific challenge via
  `POST /auth/login/mfa`. There is no path that yields a session from a
  password alone.
- TOTP verification uses the standard 30-second-step, 6-digit algorithm
  (RFC 6238) with a ±1 step clock-skew tolerance and rejects code reuse
  within the same step (prevents immediate replay).
- An invalid password, invalid/expired challenge, or invalid TOTP code
  returns a generic failure (does not reveal which factor was wrong, does
  not reveal whether the email exists).
- Wrong password and wrong TOTP code are audited as distinct failure
  reasons internally (for lockout/investigation) even though the caller
  only sees a generic error.

## REQ-IAM-004: MFA enrollment is mandatory before first use, self-service to reset

Acceptance criteria:
- A newly invited account cannot obtain a session until it has (a) set its
  own password, replacing the admin-issued temporary one, and (b)
  confirmed TOTP enrollment by entering one valid code generated from the
  provisioned secret.
- The TOTP secret is generated server-side, encrypted at rest (separate
  encryption key from the database credentials — a compromised DB dump
  alone must not yield usable secrets), and shown to the user exactly once
  as both a `otpauth://` URI (rendered as a QR code client-side) and the
  raw secret (manual entry fallback).
- On enrollment confirmation, exactly one set of one-time backup codes
  (10 codes) is generated, shown once, and stored only as salted hashes
  (never recoverable, only re-generatable — which invalidates the old set).
- A logged-in user can re-enroll MFA (e.g. new phone) after re-authenticating
  with their current password; re-enrollment invalidates the previous
  secret and backup codes immediately.
- An admin can force-reset a user's MFA (clears the secret and backup
  codes, sets the account back to "enrollment required") for lost-device
  recovery, without needing that user's password. This is audited as a
  privileged action.

## REQ-IAM-005: Sessions are server-side, revocable, and time-bounded

Context: today's `asm_operator_session` cookie value is the shared secret
itself — it cannot be individually revoked and never expires.

Acceptance criteria:
- A session is an opaque, high-entropy random token; only its salted hash
  is stored server-side (`user_session` table), mirroring how passwords
  and backup codes are handled — a database read alone does not yield a
  usable session token.
- Sessions carry a sliding idle expiry (12 hours of inactivity) and a hard
  absolute maximum lifetime (7 days), whichever comes first.
- `POST /auth/logout` revokes the presented session immediately.
- A user can list and revoke their own other active sessions
  (`GET /auth/sessions`, `DELETE /auth/sessions/{id}`); an admin can revoke
  any user's sessions (e.g. after a suspected compromise or role change).
- Disabling a user (`status=disabled`) immediately revokes all of that
  user's active sessions.

## REQ-IAM-006: Brute-force protection on both factors

Acceptance criteria:
- Repeated failed password attempts for one account trigger an increasing
  lockout (progressive backoff, e.g. locked for 30 seconds after 5
  failures, doubling up to a capped window) independent of source IP —
  the account itself is the throttled resource, not just the IP (a
  distributed attacker must not bypass this by rotating IPs).
- Repeated failed TOTP/backup-code attempts against a single login
  challenge invalidate that challenge after a small fixed number of
  attempts (5), forcing the caller back to `POST /auth/login`.
- Lockout state and every failed attempt are recorded in the account
  security audit trail (REQ-IAM-009) with enough detail to investigate an
  attack, without ever recording the attempted password/TOTP value itself.

## REQ-IAM-007: Per-user engagement ownership with admin oversight

Acceptance criteria:
- `engagement.owner_user_id` (not null after migration) records who
  created/owns it.
- An `operator`-role user can list, view, and manage (start scans, edit
  scope, etc.) only engagements they own; any attempt to access another
  user's engagement by id returns 404 (not 403 — existence is not
  disclosed to a non-owner).
- An `admin`-role user can list, view, and manage every engagement
  regardless of owner, and can reassign an engagement's owner.
- Creating an engagement sets `owner_user_id` to the creating user
  automatically; it cannot be supplied by the client.
- This ownership boundary is enforced independently of, and in addition
  to, the existing Scope Gateway — it answers "may this human see/manage
  this engagement at all," never "may this tool call run" (unchanged,
  still the Gateway's sole responsibility).

## REQ-IAM-008: Admin-only user management, invite-only provisioning

Acceptance criteria:
- There is no public account-creation endpoint. Only an authenticated
  `admin` can create an account (`POST /admin/users`): email, display
  name, role. The response includes a one-time temporary password (shown
  once, for the admin to relay out-of-band — no email/SMTP dependency in
  this iteration) and the account is created in `invited` status with
  `must_change_password=true`.
- An admin can list users, change a user's role, disable/re-enable a
  user, and force-reset their password or MFA.
- Accounts are never hard-deleted (disable only) — preserves referential
  integrity for `owner_user_id` and audit history, consistent with the
  append-only philosophy already used for audit records.
- The very first admin account is created by an operator-run bootstrap
  step (env-configured email + auto-generated one-time password printed
  once to the deploy log), not by any application code path reachable at
  runtime — there is no "first user becomes admin" implicit rule.

## REQ-IAM-009: Tamper-evident audit trail for account/security events

Context: the existing `audit_log` table is hash-chained per-engagement
(`app/gateway/audit.py`) and is not a fit for events that have no
engagement (login, MFA, user management) — that chain's legal-evidence
semantics must not be diluted or restructured.

Acceptance criteria:
- A new, separately hash-chained `account_audit_log` (same tamper-evident
  `row_hash = sha256(prev_hash || canonical_json(row))` construction, one
  global chain) records: login success/failure (with factor-level
  failure reason), MFA enrollment/reset, password changes, session
  creation/revocation, lockouts, and every admin user-management action.
- No entry in this trail ever contains a raw password, TOTP code, backup
  code, or session token — only hashes/booleans/metadata (ip, user agent,
  user id, action, outcome).
- This trail is viewable by admins in the console (read-only).

## REQ-IAM-010: Production deployment is TLS-terminated and single-origin

Context: today control-plane's port 8000 is published directly with no TLS,
and the frontend is only ever run via the Vite dev server — there is no
production build/serving story at all, which is a hard blocker for exposing
this on a public VPS regardless of the login work above.

Acceptance criteria:
- A reverse-proxy edge service (Caddy, automatic Let's Encrypt HTTPS from a
  configured domain name) is the only container with a published port in
  the production deployment profile; control-plane's port is no longer
  published to the host.
- The frontend is served as a static production build (`vite build`
  output) by the edge service; API calls go to the same origin (no CORS
  needed in production).
- The edge service proxies only the public API route prefixes
  (`/auth`, `/engagements`, `/approvals`, `/settings`, `/tools`) to
  control-plane. `/internal/*` is never reachable through the edge — it
  stays reachable only from the cluster-internal network, exactly as its
  existing docstring already requires; this is enforced at the proxy
  config layer as defense-in-depth alongside the existing
  `require_internal_token` check.
- All cookies (`session`) are set `Secure; HttpOnly; SameSite=Strict` in
  production.

## REQ-IAM-011: Safe migration off the shared token

Acceptance criteria:
- A migration adds the new tables/columns without breaking any existing
  engagement data; every existing engagement is backfilled to be owned by
  the bootstrap admin account created during rollout.
- Rollout order is documented and followed: deploy the new auth system
  disabled-by-default in a way that doesn't yet enforce it → create the
  bootstrap admin and any needed team accounts → verify login/MFA
  end-to-end → flip enforcement on (production guard from REQ-IAM-002) →
  retire the shared token from any production configuration.
- This document and its test cases are the record of that migration; no
  separate manual runbook is required beyond what's written here plus the
  architecture doc's deployment section.
