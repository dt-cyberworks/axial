---
title: Cookie-only browser sessions and CSRF defence
status: implemented
risk: R3
owner: security-engineering
---

# Cookie-Only Browser Sessions and CSRF Defence

GitHub issue #41 (split from #26). The session cookie is `Secure`, `HttpOnly`
and `SameSite=Strict`, but the same raw token was also returned in the body of
every session-issuing `/auth/*` response and kept in `sessionStorage`. Any
script running in the page (an XSS payload, a compromised dependency, a
browser extension) could read it, so `HttpOnly` protected nothing: the stored
token was a complete credential on its own.

Going cookie-only makes the credential ambient, so the same change adds an
explicit CSRF defence for state-changing requests.

**Risk class: R3** (authentication and session handling). Negative tests and a
human security review are required.

**Security review:** approved by johannes (project/security owner) on
2026-09-29 ("I approve all changes"), after the negative tests and the
mutation checks listed in the linked test cases. Live verification on the
dev stack was owed at deploy time; it is recorded in the test case (2026-10-01).

Tests must verify these requirements directly. Do not weaken tests to match
implementation; update implementation when it violates this document.

## REQ-IAM-018: The session token never reaches JavaScript

Acceptance criteria:

- No `/auth/*` response body carries a session token: not the sign-in
  responses, not `change-password`, not `mfa/reenroll/confirm`. The token
  travels only in the `HttpOnly` `Set-Cookie` header.
- [Negative test] This is asserted generically: every route under `/auth`
  that declares a response model is checked so a new endpoint cannot bring a
  token field back.
- The console keeps no credential in `sessionStorage` or `localStorage`, and
  removes a token left there by an earlier version.
- The console authenticates `fetch()`, file downloads and the live event
  stream the same way: with the cookie, sent by the browser.
- Password change and MFA re-enrollment still rotate the caller's session; the
  browser carries the new cookie automatically and the caller stays signed in.

## REQ-IAM-019: State-changing requests authenticated by the cookie need proof of origin

Acceptance criteria:

- A `POST`, `PUT`, `PATCH` or `DELETE` that is authenticated only by the
  session cookie must carry the header `X-Requested-With: asm-console`. Without
  it the request is rejected with `403` before the handler runs. A cross-site
  page cannot add a custom header without a CORS preflight, which the API
  refuses.
- If the request has an `Origin` header (or, without one, a `Referer`), its
  host must be the host the request was sent to or a configured trusted origin
  (`CSRF_TRUSTED_ORIGINS`, default `http://localhost:5173` for the dev
  console). Any other origin is rejected with `403`, even with the header.
- [Negative test] A cookie-authenticated state-changing request from a foreign
  `Origin`, from a foreign `Referer`, and without the custom header is
  rejected, and nothing is changed.
- Safe methods (`GET`, `HEAD`, `OPTIONS`) are not affected, so the event
  stream and downloads work unchanged.
- A request authenticated by an `Authorization` header (non-browser clients,
  the UAT harness) is not ambient and is exempt: a browser never attaches that
  header by itself.
- Signing out with only the cookie follows the same rules.
- Regression: engagement create/update/delete, admin routes, account changes
  and the event stream work through the console with the cookie alone.
