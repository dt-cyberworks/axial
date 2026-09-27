# Rules of Engagement & Scope Authorization Document

Fillable template for ASM / security-testing engagements. Connects contract ⇄
data model ⇄ Scope Gateway.

Version 1.0 · Companion document to Architecture v2.1 & Deployment v1.0

> [!NOTE]
> **How this template works.** Each section maps directly to a field in the
> data model (Ch. 2 of the Technical Architecture). The grey italic
> `↳ Data field:` line under each entry shows which DB column it fills — so
> the signed document becomes machine-readable scope for the gateway.
> Highlighted fields are to be filled in. Sections marked ⚖ are legally
> binding and a precondition for the engagement to transition to `active`.

## 1. Type of engagement (`source`)

Determines the authorization source, the applicable rules, and which further
sections must be filled in.

- [ ] `lab` — isolated test environment (no third-party systems; sections 5–7 do not apply)
- [ ] `own_domain` — your own assets (ownership proof in section 4)
- [ ] `bug_bounty` — an authorized program (section 6 additionally mandatory)
- [ ] `customer` — a commissioning customer (section 3 signature mandatory)

↳ Data field: `engagement.source`

> [!IMPORTANT]
> **⚖ LEGALLY BINDING — `source` determines the authorization source.**
> `customer` requires a signature (section 3). `bug_bounty` requires a valid,
> linked program with an accepted platform policy (section 6). `own_domain`
> requires proof of ownership (section 4). `lab` requires no external
> authorization, but may run only in an isolated environment.

## 2. Engagement & parties

| Field | |
|---|---|
| Engagement title: | |

↳ Data field: `engagement.title`

| Field | |
|---|---|
| Customer / client (name, address): | |

↳ Data field: `engagement.customer_id` → `customer`

| Field | |
|---|---|
| Performing party (service operator): | |

| Field | |
|---|---|
| Customer's emergency contact (name, 24/7 phone, email): | **Mandatory for all active tests** |

↳ Data field: `engagement.emergency_contact`

### 2.1 Test window

| | Date / time | Data field |
|---|---|---|
| Start | | `engagement.authorized_from` |
| End | | `engagement.authorized_until` |

> [!IMPORTANT]
> **⚖ LEGALLY BINDING — the time window is hard-enforced.** The Scope
> Gateway and the egress proxy reject every active tool call when the
> current time falls outside `[authorized_from, authorized_until]` —
> regardless of any other authorization. Tests outside this window are not
> authorized.

## 3. Authorization & signature (`source = customer`)

The customer confirms they are authorized to dispose of the assets named in
section 4, and authorizes the checks defined in section 5 within the test
window.

| Field | |
|---|---|
| Name of authorizing person: | |

↳ Data field: `engagement.scope_signed_by`

| Field | |
|---|---|
| Position / role at the customer: | |

| Place, date | Signature |
|---|---|
| | |

> [!NOTE]
> **Signature → `scope_doc_sha256`.** After signing, the final document is
> hashed; the SHA-256 is stored as `engagement.scope_doc_sha256` and
> referenced both in the customer report (the "Methodology & Scope" section)
> and in the audit log. This makes it provable exactly which version was
> authorized.

## 4. Scope: assets (allow / deny)

The allow list defines what may be tested. The deny list ALWAYS takes
precedence — it protects against hits on excluded systems.

↳ Data field: `scope_asset` (`rule`, `asset_type`, `value`, `path_pattern`, `active_allowed`)

### 4.1 IN SCOPE (`rule = allow`)

Only test actively if the "Active allowed" column is checked YES. ⚖

| Type (domain/wildcard/ip/cidr) | Value | Path (optional) | Active allowed? |
|---|---|---|---|
| | | | |
| | | | |
| | | | |
| | | | |
| | | | |

### 4.2 OUT OF SCOPE (`rule = deny` — takes precedence)

| Type | Value | Path (optional) | Reason |
|---|---|---|---|
| | | | |
| | | | |
| | | | |
| | | | |

> [!IMPORTANT]
> **⚖ LEGALLY BINDING — `deny` takes precedence over `allow`.** If a target
> matches a `deny` rule (including via wildcard or path), it is blocked —
> even if an `allow` rule also matches. For bug-bounty programs, a hit on an
> out-of-scope asset is a serious violation of the program rules.

### 4.3 Proof of ownership

- [ ] DNS TXT token set (`dns-txt-token`)
- [ ] Signed asset list from the authorized party (`signed-list`)
- [ ] Bug-bounty program scope (`bbp-scope`)
- [ ] Cloud: additional provider authorization obtained (if required)

↳ Data field: `scope_asset.ownership_verified`, `ownership_method`

> [!IMPORTANT]
> **⚖ LEGALLY BINDING — ownership + cloud.** Only assets with confirmed
> ownership may be actively tested (`ownership_verified = true`). For cloud
> assets (AWS/Azure etc.), customer authorization alone is sometimes not
> sufficient — some providers require a separate test notification; this
> must be obtained before testing begins and documented here.

## 5. Authorized checks (`tool_grant`)

Defines which categories are authorized in which mode, and whether every
active step requires individual approval.

↳ Data field: `tool_grant` (`tool_category`, `mode`, `requires_manual_approval`)

| Category | Passive | Active ⚖ | Per-step approval? |
|---|---|---|---|
| `recon` (discovery) | ☐ | ☐ | ☐ |
| `fingerprint` (service/TLS/headers) | ☐ | ☐ | ☐ |
| `vuln` (CVE/misconfig checks) | ☐ | ☐ | ☐ |
| `cred` (default credentials only) | — | ☐ | ☐ (recommended: YES) |
| `exploit` (non-destructive proof) | — | ☐ | ☐ (recommended: YES) |

> [!IMPORTANT]
> **⚖ LEGALLY BINDING — active + per-step approval.** A category checked
> "Active" only executes if the affected asset is also "actively allowed"
> (section 4.1). `requires_manual_approval = YES` means: the (human)
> operator approves every individual step before it runs — the default for
> `cred` and `exploit`.

### 5.1 Explicit exclusions

Excluded by default unless expressly agreed otherwise:

- [ ] No denial-of-service / load testing
- [ ] No social engineering / phishing
- [ ] No data exfiltration (proof only, no extraction)
- [ ] No destructive exploitation (no write/delete/RCE exploitation)
- [ ] No physical testing

| Additional exclusions / special agreements: | *free text* |
|---|---|

## 6. Bug-bounty program (`source = bug_bounty`)

Fill in only if `source = bug_bounty`. Encodes the binding program policy in
machine-readable form.

↳ Data field: `bounty_program` (…)

| Field | |
|---|---|
| Platform (Intigriti / HackerOne): | |

↳ Data field: `bounty_program.platform`

| Field | |
|---|---|
| Program handle / URL: | |

↳ Data field: `bounty_program.program_ref`

| Program rule | Value | Data field |
|---|---|---|
| Automated scanners allowed? | ☐ yes ☐ no | `automation_allowed` |
| AI/agent testing allowed? | ☐ yes ☐ no | `ai_testing_allowed` |
| Max requests/second | | `max_rps` |
| Max concurrency | | `max_concurrency` |
| Ident header name (optional) | e.g. `X-Bug-Bounty` | `ident_header_name` |
| Ident header value (optional) | e.g. username | `ident_header_value` |

> [!IMPORTANT]
> **⚖ LEGALLY BINDING — the program policy is binding.** `automation_allowed`
> and `ai_testing_allowed` must be taken from the CONCRETE program rules, not
> assumed. If `ai_testing_allowed = no`, the Agent may not run against
> this program. When an ident header is configured, it is enforced on EVERY
> active request while `source = bug_bounty`, so the program's blue team can
> recognize test traffic. Not every program requires one (some identify
> researchers out-of-band instead, e.g. via a program-issued email alias) -
> leave it blank in that case.

## 7. Authorization checklist (before transitioning to `active`)

The engagement may only be set to `active` once ALL applicable items are
satisfied. This list mirrors the Scope Gateway's own checks.

- [ ] Type of engagement (`source`) set — section 1
- [ ] Test window set, emergency contact recorded — section 2
- [ ] If `customer`: document signed, `scope_doc_sha256` recorded — section 3 ⚖
- [ ] Allow assets defined; ownership verified — section 4 ⚖
- [ ] Deny list recorded (takes precedence) — section 4.2 ⚖
- [ ] Cloud provider authorization obtained, if required — section 4.3 ⚖
- [ ] `tool_grant` set per category/mode; per-step approvals marked — section 5 ⚖
- [ ] Exclusions confirmed — section 5.1
- [ ] If `bug_bounty`: program linked, policy accepted, ident header set — section 6 ⚖
- [ ] Professional liability insurance with security-testing coverage active
- [ ] Audit logging active (hash chain)

> [!IMPORTANT]
> **⚖ LEGALLY BINDING — fail-closed.** If even one applicable box is
> unchecked, the engagement remains in a non-active status and the gateway
> operates in passive-only mode at most. Active layers stay locked until the
> checklist is complete.

| Authorized by (operator) | Place, date | Signature |
|---|---|---|
| | | |

---

**Note:** This template is a technical/organizational working aid, not legal
advice. The contractual and criminal-law safeguards (including relevant
computer-misuse, data-protection, secondary-employment, and platform-terms
law in your jurisdiction) must be secured with qualified legal counsel.
