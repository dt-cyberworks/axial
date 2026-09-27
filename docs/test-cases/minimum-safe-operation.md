---
title: Minimum safe operation verification
status: ready
risk: R4
owner: security-engineering
---

# Minimum safe operation verification

## TC-CONFIG-001: Production rejects development secrets

Requirements:

- REQ-CONFIG-001

Automated tests:

- `control-plane/tests/test_production_config.py`

Objective:

Verify production startup validation while retaining an explicit development
mode.

Expected results:

- Insecure production configuration is rejected.
- Secure injected configuration is accepted.

## TC-IAM-001: Public API requires the operator credential

Requirements:

- REQ-IAM-001

Automated tests:

- `control-plane/tests/test_operator_auth.py`

Objective:

Verify health, public, and internal authentication boundaries.

Expected results:

- Public requests without the operator credential receive `401`.
- Health remains reachable and internal credentials are not operator identity.

## TC-AUDIT-001: Proxy events enter the serialized control-plane chain

Requirements:

- REQ-AUDIT-001
- REQ-AUDIT-002

Automated tests:

- `control-plane/tests/integration/test_audit_serialization.py`
- `egress-proxy/tests/test_audit_client.py`

Objective:

Verify controlled ingestion, fail-closed submission, and concurrent chain
integrity.

Expected results:

- The proxy performs no audit-table insert.
- Concurrent events form one verifiable chain.

## TC-APPROVAL-004: Approved call is claimed and reauthorized once

Requirements:

- REQ-APPROVAL-004

Automated tests:

- `control-plane/tests/integration/test_manual_approval_http.py`
- `worker/tests/test_agent.py`

Objective:

Verify exact-call binding, current-policy reauthorization, atomic claiming, and
terminal execution state.

Expected results:

- One claimant receives the exact approved call.
- Scope or window changes deny the claim.
- A second claimant and reused approval cannot dispatch.
- Success and failure become `consumed` and `execution_failed`.

