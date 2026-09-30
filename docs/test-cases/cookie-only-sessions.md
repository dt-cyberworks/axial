---
title: Cookie-only sessions verification
status: ready
risk: R3
owner: security-engineering
---

# Cookie-Only Sessions Verification

Verifies [`../requirements/cookie-only-sessions.md`](../requirements/cookie-only-sessions.md).

## TC-IAM-018: The session token never reaches JavaScript

Requirements:

- REQ-IAM-018

Automated tests:

- `control-plane/tests/integration/test_cookie_only_sessions.py`
- `frontend/tests/cookie_only_sessions_requirements.test.mjs`

Objective:

Prove no `/auth/*` body carries a token, the console stores no credential, and
rotation keeps the browser signed in.

Expected results:

- `test_negative_no_auth_response_model_has_a_token_field` - generic check over the `/auth` routes.
- `test_sign_in_sets_the_cookie_and_returns_no_token`, `test_change_password_rotates_the_cookie_and_returns_no_token`.
- The console source has no `sessionStorage`/`localStorage` credential access and no `Authorization` header for `fetch()`.
- The UAT golden path (`uat/`) signs in and uses the console with the cookie alone.
- Playwright: after sign-in both web storages are empty of credentials.

## TC-IAM-019: CSRF defence

Requirements:

- REQ-IAM-019

Automated tests:

- `control-plane/tests/integration/test_cookie_only_sessions.py`

Objective:

Prove a cookie-authenticated state-changing request is refused without proof
of origin and accepted with it.

Expected results:

- `test_negative_cookie_post_without_the_custom_header_is_rejected` - `403`, nothing changed.
- `test_negative_cookie_post_from_a_foreign_origin_is_rejected`, `test_negative_cookie_post_with_a_foreign_referer_is_rejected`.
- `test_same_origin_cookie_post_with_the_header_is_accepted`, `test_trusted_dev_origin_is_accepted`.
- `test_safe_methods_need_no_header`, `test_bearer_authenticated_requests_are_exempt`.
- `test_cookie_sign_out_follows_the_same_rules`.
