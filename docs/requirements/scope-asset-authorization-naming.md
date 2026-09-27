---
title: Scope-asset attestation is named for authorization, not ownership
status: implemented
risk: R2
owner: product-engineering
---

# Scope-Asset Attestation Naming: Authorization, Not Ownership

## Context

The `scope_asset.ownership_verified`/`ownership_method` fields (and the
`POST /engagements/{id}/scope-assets/{asset_id}/verify-ownership` endpoint)
gate whether an `own_domain`/`customer` engagement may activate for active
scanning against a given allow-scope asset. The name is a legacy artifact:
what the checklist actually requires — and what the endpoint's own docstring,
audit-log `action` (`scope_authorization_attested`), and error message
already said before this change — is that the operator has attested a valid
basis to actively test the asset, not that they literally own the domain.

**Clarified by johannes (2026-07-29):** authorization can rest on several
different bases — a truly owned domain, a signed customer/bug-bounty
authorization, or (as with `pentest-ground.com`, a public penetration-testing
practice platform) the target's own public invitation to be scanned.
"Ownership" was never the actual requirement; "authorized to scan" always
was. The field name should say that.

**Risk class: R2** — this is a rename plus documentation/comment correction
across persistence, API, frontend, tests, and fixtures. No enforcement logic
changes: activation still requires an attestation for every actively-allowed
`own_domain`/`customer` scope asset, exactly as before; only the vocabulary
changes, everywhere it appears, so no stale "ownership" language survives to
mislead a future reader about what is actually being attested.

## REQ-AUTHNAME-001: The attestation is named and worded as authorization, not ownership

Acceptance criteria:

- `scope_asset.ownership_verified` is renamed to `authorization_verified`;
  `scope_asset.ownership_method` is renamed to `authorization_method` (model,
  schema, migration renaming the existing columns in place — no data loss).
- `POST /engagements/{id}/scope-assets/{asset_id}/verify-ownership` is
  renamed to `.../verify-authorization`; the handler function and its
  request schema (`ScopeOwnershipVerificationCreate`) are renamed to match.
- The activation checklist's enforcement is unchanged: an `own_domain`/
  `customer` engagement still cannot activate while any actively-allowed
  scope asset lacks `authorization_verified=true`.
- Every reference across frontend (`client.ts`, the engagement wizard and
  detail pages), tests, `lab/seed_lab_engagement.py`, `uat/scan_journey.py`,
  and prose docs (`docs/data-model.md`, `docs/legal.md`) uses the renamed
  fields/endpoint - no dangling `ownership_*` reference remains outside this
  document's own historical Context section.
- Existing scope-asset rows retain their true/false value and method text
  across the rename (a plain column rename, not a data migration).

Security invariants:

- The Scope Gateway (`authorize.py`) does not reference this field before or
  after the rename - it was never part of the deterministic per-call
  authorization path, only the engagement-activation legal checklist.
- No `bug_bounty`-source engagement's authorization path (its bounty-program
  policy check) is affected; this field only ever gated `own_domain`/
  `customer` sources.
