---
title: Admin-only global settings and owner-first approval decisions verification
status: ready
risk: R3
owner: security-engineering
---

# Admin-Only Global Settings Verification

Verifies [`../requirements/global-settings-authorization.md`](../requirements/global-settings-authorization.md).
All cases run through the real FastAPI routing (TestClient + real sessions),
because router-level dependencies do not run when handlers are called
directly. Against the code before the fix, 23 of these 35 tests fail.

## TC-IAM-013: Operators cannot reach global settings

Requirements:

- REQ-IAM-013

Automated tests:

- `control-plane/tests/integration/test_global_settings_authorization.py`

Objective:

Prove every settings endpoint is admin-only for reads and writes, and that
the concrete attack — redirecting the LLM endpoint — fails.

Expected results:

- `test_negative_operator_cannot_read_global_settings` and `test_negative_operator_cannot_write_global_settings` - `403` for all eight endpoints.
- `test_negative_operator_cannot_redirect_the_llm_endpoint` - `403`, stored base URL, model, and key unchanged.
- `test_settings_without_credentials_is_401`.
- `test_admin_can_read_and_write_global_settings`.

## TC-IAM-014: Approval decisions reveal nothing to non-owners

Requirements:

- REQ-IAM-014

Automated tests:

- `control-plane/tests/integration/test_global_settings_authorization.py`

Objective:

Prove a non-owner cannot learn or change anything about another user's
approval.

Expected results:

- `test_negative_non_owner_gets_404_whatever_the_approval_state` - `404` for requested, approved, and rejected approvals, for approve and reject.
- `test_negative_non_owner_cannot_mark_an_approval_expired` - state stays `requested`.
- `test_owner_still_gets_409_for_an_already_decided_approval`.

## TC-IAM-015: Admin reset lifts the lockout

Requirements:

- REQ-IAM-015

Automated tests:

- `control-plane/tests/integration/test_global_settings_authorization.py`

Objective:

Prove the temporary password from an admin reset works for a locked-out
user.

Expected results:

- `test_admin_password_reset_lifts_the_lockout` - counter `0`, no lock, and the temporary password authenticates (next step `set_password`).
