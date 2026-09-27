# Authentication and Authorization — Architecture

Implements [`../requirements/authentication-and-authorization.md`](../requirements/authentication-and-authorization.md)
(REQ-IAM-002..011). One row per requirement is called out inline below.

## 1. Where this sits relative to existing boundaries

This adds exactly one new boundary — "which authenticated human, if any, may
use the console" — layered *above* the two boundaries that already exist and
are completely unchanged:

```
Browser
  │  1. NEW: human auth (this doc) — who are you, are you allowed in at all
  ▼
control-plane public API (engagements, settings, approvals, tools, auth)
  │  2. EXISTING: per-user ownership check (this doc, REQ-IAM-007) — is this
  │     YOUR engagement (or are you admin)
  ▼
  3. EXISTING, untouched: Scope Gateway (authorize.py) — is THIS SPECIFIC
     tool call in scope, ever the deciding voice on active operations
  ▼
worker → tool-runner → egress-proxy (also untouched)
```

`/internal/*` (worker↔control-plane) keeps its own separate
`require_internal_token` machine credential — that is not a human boundary
and is out of scope here.

## 2. Data model

New tables (migration `NNNN_authentication.sql`, idempotent):

```sql
CREATE TYPE user_role AS ENUM ('admin', 'operator');
CREATE TYPE user_status AS ENUM ('invited', 'active', 'disabled');

CREATE TABLE app_user (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,           -- Argon2id
    role user_role NOT NULL DEFAULT 'operator',
    status user_status NOT NULL DEFAULT 'invited',
    must_change_password BOOLEAN NOT NULL DEFAULT true,
    totp_secret_encrypted BYTEA,           -- NULL until enrolled
    totp_confirmed_at TIMESTAMPTZ,
    failed_password_count INT NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    created_by_user_id UUID REFERENCES app_user(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ
);

CREATE TABLE user_backup_code (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES app_user(id),
    code_hash TEXT NOT NULL,               -- Argon2id, same as passwords
    used_at TIMESTAMPTZ
);

CREATE TABLE login_challenge (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES app_user(id),
    purpose TEXT NOT NULL,                 -- 'mfa_verify' | 'mfa_enroll'
    attempts INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);

CREATE TABLE user_session (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES app_user(id),
    token_hash TEXT NOT NULL UNIQUE,       -- sha256 of the opaque bearer value
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,       -- absolute cap, 7 days from creation
    revoked_at TIMESTAMPTZ
);

CREATE TABLE account_audit_log (            -- separate global hash chain, REQ-IAM-009
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ts TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_user_id UUID REFERENCES app_user(id),   -- NULL for pre-auth failures (unknown email)
    action TEXT NOT NULL,
    outcome TEXT NOT NULL,                  -- 'success' | 'failure'
    ip_address TEXT,
    user_agent TEXT,
    payload JSONB NOT NULL DEFAULT '{}',
    prev_hash TEXT,
    row_hash TEXT NOT NULL
);

ALTER TABLE engagement ADD COLUMN owner_user_id UUID REFERENCES app_user(id);
-- backfilled to the bootstrap admin in the same migration, then set NOT NULL
```

`account_audit_log` mirrors `app/gateway/audit.py`'s
`row_hash = sha256(prev_hash || canonical_json(row))` construction exactly,
but with a single fixed advisory-lock key (one global chain, not
per-engagement) since these events have no engagement. Implemented as a
sibling module `app/gateway/account_audit.py` — the existing
`append_audit_log` is not touched or generalized (its per-engagement legal
-evidence semantics stay exactly as they are).

Password hashes, backup-code hashes, and session token hashes all use the
same Argon2id primitive (`argon2-cffi`, new dependency). `totp_secret_encrypted`
uses Fernet symmetric encryption (`cryptography`, new dependency) with a key
from a new `MFA_ENCRYPTION_KEY` setting (same treatment as
`scope_signing_secret`/`internal_api_token`: required, non-default in
production, guarded the same way).

## 3. Request flows

### 3.1 First login for a new (invited) account

```
1. Admin: POST /admin/users {email, display_name, role}
   -> app_user(status=invited, must_change_password=true), temp password
      returned ONCE in the response for the admin to relay out-of-band.
2. User: POST /auth/login {email, temp password}
   -> password correct, but must_change_password=true
   -> 200 {status: "must_change_password", challenge_id}
3. User: POST /auth/password/set-first {challenge_id, new_password}
   -> updates password_hash, must_change_password=false
   -> since totp_confirmed_at is still NULL: 200 {status: "mfa_enrollment_required", challenge_id}
4. User: POST /auth/mfa/enroll {challenge_id}
   -> generates + encrypts totp_secret, returns {secret, otpauth_uri}
      (frontend renders otpauth_uri as a QR code client-side)
5. User: POST /auth/mfa/enroll/confirm {challenge_id, code}
   -> verifies code against the pending secret; on success:
      totp_confirmed_at=now(), generates 10 backup codes (returned ONCE),
      creates the user_session, sets the session cookie, returns {backup_codes, session}
```

### 3.2 Normal login (already enrolled)

```
1. POST /auth/login {email, password}
   -> password correct, must_change_password=false, totp_confirmed_at set
   -> 200 {status: "mfa_required", challenge_id}
2. POST /auth/login/mfa {challenge_id, code}   (code = TOTP or an unused backup code)
   -> verifies; on success creates user_session, sets cookie, returns session
   -> on failure: challenge.attempts += 1; at 5 attempts the challenge is
      consumed (dead) and the caller must restart from step 1
```

Every response in both flows is intentionally uniform in shape/timing
regardless of *which* check failed (wrong password vs. unknown email vs.
wrong code) — REQ-IAM-003's "does not reveal which factor was wrong."

### 3.3 Admin-forced MFA reset (lost device)

```
POST /admin/users/{id}/reset-mfa   (admin only)
  -> clears totp_secret_encrypted, totp_confirmed_at, all backup codes
  -> revokes all of that user's active sessions
  -> next login of that user re-enters the enrollment flow (§3.1 step 4)
  -> account_audit_log: action=mfa_reset, actor=admin, payload={target_user_id}
```

## 4. Session transport (keeps today's dual-channel shape)

The current frontend already uses two channels for a reason: `fetch()` calls
carry a `Bearer` token from `sessionStorage` (immune to CSRF — cross-site
requests can't set custom headers), while `EventSource` (SSE) cannot send
custom headers at all and instead relies on a cookie
(`bootstrapBrowserSession` in `api/client.ts`). This design keeps that exact
shape, just backed by a real per-user session instead of the shared token:

- `POST /auth/login/mfa` (and the enrollment-confirm equivalent) returns the
  raw session token once in the JSON body. The frontend stores it in
  `sessionStorage` (as `asm_session_token`, replacing today's
  `asm_operator_token`) and sends it as `Authorization: Bearer <token>` on
  every API call — unchanged mechanism in `api/client.ts`, new value.
- The same request also sets a `session` cookie
  (`HttpOnly; Secure (prod); SameSite=Strict`) carrying the same raw token,
  scoped narrowly to SSE (`GET /engagements/{id}/stream`) — mirrors today's
  `bootstrapBrowserSession`/`asm_operator_session` exactly, just derived
  from the real session instead of the shared secret.
- Every authenticated request resolves the presented raw token by hashing it
  and looking up `user_session.token_hash` — never compares raw tokens,
  never stores one. Expired/revoked sessions fail closed (401).
- `require_user` (replaces `require_operator` as the dependency on
  `public_router`) does this resolution and attaches the `User` to request
  state; `require_admin` additionally checks `role == "admin"`.

## 5. Per-engagement ownership enforcement (REQ-IAM-007)

A single reusable dependency, used everywhere an `engagement_id` path param
already appears (`engagements.py`, `stream.py`, `findings.py`, and anywhere
else that takes one):

```python
def require_engagement_access(
    engagement_id: uuid.UUID,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> Engagement:
    eng = db.get(Engagement, engagement_id)
    if eng is None or (user.role != "admin" and eng.owner_user_id != user.id):
        raise HTTPException(404)  # never 403 — existence isn't disclosed
    return eng
```

Handlers that currently do `_get_engagement_or_404(db, engagement_id)` switch
to `Depends(require_engagement_access)`, which both replaces that lookup and
enforces ownership in one place — not a scattered per-handler check. List
endpoints (`GET /engagements`) filter by `owner_user_id == user.id` unless
`user.role == "admin"`. `POST /engagements` ignores any client-supplied
owner field and always sets `owner_user_id = user.id`.

## 6. GUI design

New routes (React Router, mirroring existing page structure):

| Route | Screen | Notes |
|---|---|---|
| `/login` | Email + password | On success routes to `/login/mfa`, `/login/mfa-enroll`, or `/login/set-password` based on the challenge status returned. |
| `/login/mfa` | 6-digit code entry (+ "use a backup code" link) | |
| `/login/mfa-enroll` | QR code (client-rendered from `otpauth_uri`) + manual secret + code confirm | Shows the 10 backup codes once on success, with a "I've saved these" confirm before continuing. |
| `/login/set-password` | New password form | Only reached when `must_change_password` is true. |
| `/account` | Current user's profile | Change password, re-enroll MFA (re-auth required), list/revoke own sessions. |
| `/admin/users` | Admin only | Table of users (email, role, status, last login), invite new user, change role, disable/enable, reset password, reset MFA. Reuses the existing `data-table`/`form-panel` styles already in `styles.css`. |
| `/admin/audit` | Admin only | Read-only view of `account_audit_log`, same visual language as the existing engagement Audit page. |

Existing pages change minimally:
- `Overview`/engagement list: no longer shows every engagement to every
  operator — shows the caller's own (admins see all, with an "owner" column
  added so they can tell whose is whose).
- Top nav gains the current user's name/email and a "Log out" action;
  `/admin/*` links appear only for admin-role users.
- `api/client.ts`: `bootstrapBrowserSession`/token-storage key renamed as
  described in §4; a 401 anywhere now redirects to `/login` instead of the
  current `window.prompt` fallback (that prompt existed only because the
  shared token had no real login page to redirect to).

## 7. Production deployment topology (REQ-IAM-010)

New `edge` service (Caddy) added to `docker-compose.yml` under a
`production` profile, alongside the existing services (none of which change
their internal networking):

```
Internet
  │ :443 (only published port in the production profile)
  ▼
Caddy (edge container)
  - automatic HTTPS (Let's Encrypt) for the configured domain
  - serves frontend/dist (vite build output) for everything else
  - reverse-proxies /auth, /engagements, /approvals, /settings, /tools
    to control-plane:8000 (same 'edge' docker network already defined)
  - does NOT route /internal/* anywhere (control-plane's own network
    placement already makes it unreachable from here; this is stated
    explicitly in the Caddyfile as defense-in-depth, not the only control)
```

`docker-compose.yml`'s existing `control-plane` port publish (`"8000:8000"`)
is removed from the production profile (stays published in the default/dev
profile for local `curl`/Playwright workflows exactly as used throughout
this project's own development). Local dev is otherwise unaffected — this
is additive (a new profile), not a rework of the dev path.

## 8. Threat model summary (R4 review artifact)

| Threat | Mitigation |
|---|---|
| Credential stuffing against exposed login | Argon2id hashing, progressive per-account lockout (REQ-IAM-006), generic error responses |
| Stolen DB dump | Passwords/backup codes/session tokens are hashed, never stored raw; TOTP secrets are encrypted with a key that is not in the database |
| Session token theft (XSS) | Same residual risk as today's Bearer-token-in-sessionStorage model — out of scope for this pass; mitigated in depth by short idle expiry (12h) and full revocability (REQ-IAM-005), not by this change alone |
| CSRF | Bearer-header auth for all state-changing calls is not automatically attachable cross-site; the SSE cookie is `SameSite=Strict` and read-only (`GET`) |
| One compromised account seeing all data | Per-user ownership (REQ-IAM-007) bounds the blast radius to that user's own engagements unless the compromised account is itself an admin |
| Lost phone / lost admin access | Backup codes (self-service) + admin-forced MFA reset (REQ-IAM-004); first-admin bootstrap is infra-level, not an app code path (REQ-IAM-008) |
| Public route to `/internal/*` | Unchanged: `require_internal_token` plus, in production, the edge proxy simply never routes there |

## 9. Rollout plan (REQ-IAM-011)

1. Ship migration + backend (auth disabled from the caller's perspective
   until an admin exists — `require_user` still fails closed, so there is
   no window where the app is reachable without login; "disabled" here
   means "not yet in production traffic," not "open").
2. Bootstrap the first admin: a `make bootstrap-admin` target (or
   equivalent one-shot script) reads `INITIAL_ADMIN_EMAIL` from the
   environment, creates the account with a random temporary password
   printed once to stdout/deploy log, and exits — no HTTP endpoint for
   this exists.
3. Operator (johannes) logs in as that admin, completes MFA enrollment,
   creates accounts for any other team members.
4. Verify end-to-end on the dev/staging profile: login, MFA, per-user
   engagement visibility, admin oversight, session revocation, lockout.
5. Deploy the `production` profile (Caddy + domain + TLS) to the VPS.
6. Confirm `ENVIRONMENT=production` rejects the legacy shared-token path
   (REQ-IAM-002) and remove `operator_api_token` from any production
   `.env`.
7. Existing engagement rows are backfilled to the bootstrap admin in the
   migration itself (step 1) — reassign ownership afterward via
   `/admin/users` → engagement transfer if they should belong to someone
   else.
