---
title: Engagement-defined TCP scan port range
status: implemented
risk: R4
owner: security-engineering
---

# Engagement-defined TCP scan port range

## REQ-SCAN-013: Engagement creation bounds TCP discovery to one authorized range

The operator shall be able to restrict Nmap TCP discovery for an engagement to
one inclusive port or one inclusive contiguous port range.

Acceptance criteria:

- Engagement creation accepts an inclusive first and last TCP port from 1
  through 65535; equal values represent a single port and the default remains
  `1-65535`.
- The API rejects reversed, zero, oversized, or otherwise malformed ranges and
  permits scan-envelope changes only while the engagement is in draft state.
- The control plane derives the lease port envelope from persisted engagement
  state; neither the UI, worker, nor LLM can widen it during a run.
- Nmap discovery uses exactly the leased range, and service detection receives
  only open ports from that range.
- The creation UI explains the default, validates the range, and shows the
  selected TCP envelope in its authorization review.
- Positive and negative tests prove a single port, a range, the default, and
  denial of out-of-range/widened calls.
- The engagement **edit** page also exposes the current TCP port range and
  UDP discovery toggle (not only the creation wizard): editable while the
  engagement is in draft, shown read-only with an explanatory note otherwise
  — surfacing the backend's existing draft-only 409 gate rather than hiding
  these fields from the edit surface entirely.

Value and context:

- Customers can authorize a narrow target-facing scan envelope without giving
  permission for an unnecessary full-range TCP scan.

Open questions and dependencies:

- Multiple disjoint TCP ranges are deliberately outside this item.

Implementation authorization:

- Explicitly authorized by the repository owner in the 2026-07-26 request to
  create and implement this backlog item; normal R4 review/release gates remain.

Backlog decision log:

- 2026-07-26 — requested by the repository owner and promoted in the same
  change for implementation as one inclusive contiguous range.

Security invariants:

- Persisted control-plane state is authoritative; the signed lease and kernel
  egress rule must use the same exact port envelope.
