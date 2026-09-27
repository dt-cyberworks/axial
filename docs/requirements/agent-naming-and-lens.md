---
title: Vector Agent naming and Lens explanations
status: implemented
risk: R2
owner: product-engineering
---

# Agent Naming and Lens Explanation Requirements

The product has two operator-facing agents with distinct jobs:

- **Vector Agent** finds and validates attack paths. It proposes scoped checks and every proposal is still gated by the Scope Gateway.
- **Lens Agent** explains an existing finding and its impact. It receives the recorded finding evidence and returns a customer-understandable explanation and remediation guidance.

## REQ-AGENT-001: Agent terminology is consistent in UI and documentation

The autonomous attack-path agent must be named Vector Agent wherever the operator sees it. Existing internal phase names such as `agent` may remain for database enum and audit compatibility.

Acceptance criteria:

- Engagement creation/edit screens refer to `Vector Agent` for autonomous proposals.
- Live scan, audit, results, and settings screens refer to `Vector Agent` where they describe the attack-path validator.
- Operator-facing frontend source must not use third-party branded agent naming.
- Product documentation must consistently use Agent terminology.

## REQ-LENS-001: Results page can request a Lens Agent explanation for a finding

When an operator expands a finding on the Results page, the UI must make it possible to ask Lens Agent to explain the finding.

Acceptance criteria:

- The expanded finding row includes `Lens Agent analysis`.
- The UI calls a backend Lens endpoint for the selected finding.
- The Lens output is shown in the expanded finding detail alongside the target, service, and evidence.

## REQ-LENS-002: Lens Agent uses finding evidence and caches the explanation

The backend must provide a Lens endpoint that sends the finding context to the configured LLM provider and caches the response in the finding evidence.

Acceptance criteria:

- The endpoint is `POST /engagements/{engagement_id}/findings/{finding_id}/lens-explanation`.
- The Lens prompt includes the finding title, target, service context, severity, confidence, CVE/risk fields, and structured evidence.
- The response is stored in `finding.evidence["lens_agent"]` and returned on later requests without another provider call.
- Lens success and provider/config failures are audit logged with actor `lens_agent`.

## REQ-LENS-003: Lens Agent output is clearly formatted

Lens output must be presented as readable analysis, not as raw Markdown or cached JSON. The Results page should format the standard Lens sections, lists, bold labels, and inline code so operators can scan the explanation quickly.

Acceptance criteria:

- The Results page parses Lens Markdown into structured blocks before rendering.
- The standard Lens headings `What it is`, `Where it was found`, `Why it matters`, and `What to do` render as headings, not inline text.
- Bold Markdown labels and inline code render with distinct typography.
- Ordered and unordered remediation steps render as lists.
- The cached `lens_agent` evidence object is not shown as a raw Evidence card.
