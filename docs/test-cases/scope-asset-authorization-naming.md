---
title: Scope-asset authorization attestation naming verification
status: ready
risk: R2
owner: product-engineering
---

# Scope-Asset Authorization Attestation Naming Verification

## TC-AUTHNAME-001: Activation enforcement is unchanged after the rename

Requirements:

- REQ-AUTHNAME-001

Automated tests:

- `control-plane/tests/integration/test_gateway_lab.py`
- `control-plane/tests/integration/test_scope_overlap_activation.py`
- `control-plane/tests/integration/test_dns_materialization.py`
- `control-plane/tests/integration/conftest.py`

Objective:

Prove the rename from `ownership_verified`/`ownership_method` to
`authorization_verified`/`authorization_method` (model, schema, migration,
API path/handler, frontend) changed no enforcement behavior: an
`own_domain`/`customer` engagement still cannot activate while any
actively-allowed scope asset lacks an attested authorization basis,
regardless of what that basis is (ownership, contract, bounty program, or a
target's own public invitation to be tested, e.g. a pentest-practice
platform).

Expected results:

- Every existing fixture/test that previously set `ownership_verified=True`
  to build an activatable engagement still builds one, using
  `authorization_verified=True`.
- Activation still fails for an actively-allowed asset with
  `authorization_verified=False`, with the same "authorization ... not
  attested" error semantics as before.
- `POST /engagements/{id}/scope-assets/{asset_id}/verify-authorization`
  (renamed from `.../verify-ownership`) still sets the attestation and
  records the same `scope_authorization_attested` audit action.
- No `ownership_*` field or path remains reachable anywhere in the API,
  frontend, or worker/lab/UAT scripts.
