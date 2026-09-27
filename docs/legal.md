# ⚖ Legal Prerequisites

> **Not legal advice.** This page summarizes the ⚖ markers from the
> specifications. The concrete criminal-law and contractual assessment
> (computer-misuse, data-protection, secondary-employment, and platform-terms
> law in your jurisdiction) should be secured with qualified legal counsel.

Actively scanning or testing third-party systems without authorization can
be a criminal offense in many jurisdictions. Control is technically
enforced in this system (the Scope Gateway), but the **legal basis** must
be in place before that.

## Before the first scan against a third-party system

Checklist from the Specification Ch. 7 and the
[Rules of Engagement](spec/rules-of-engagement.md):

- [ ] **Signed engagement** with an exact scope (domains/IP ranges, not "the whole company")
- [ ] **Proof of authorization** for every actively authorized asset — ownership, a customer/program
      contract, or a public invitation to test (e.g. a dedicated pentest practice
      platform); for cloud, possibly additional provider authorization
- [ ] **Test window & emergency contact** at the customer
- [ ] **Explicit exclusions** (no DoS, no social engineering, no exfiltration, unless agreed)
- [ ] **Professional liability insurance** with IT-security-testing coverage — before the first scan
- [ ] **A complete audit trail** (already technically enforced, see [security-model.md](security-model.md))
- [ ] **Data-protection compliance** where personal data is captured (e.g. exposed email addresses)
- [ ] **Employer approval** for secondary employment; check for conflicts of interest

## How the system enforces the legal basis

| Requirement | Technical enforcement |
|---|---|
| Authorization needed | `engagement.status` must be `active`; transition only via the authorization checklist (`/activate`) |
| Exact scope | `scope_asset` allow/deny; `deny` takes precedence |
| Time window | Gateway **and** egress proxy reject outside `[authorized_from, authorized_until]` |
| Per-asset authorization | The `active` transition is blocked until actively authorized assets are `authorization_verified` (the basis can be ownership, contract, program, or public invitation) |
| Customer signature | `activate` requires `scope_signed_by` + `scope_doc_sha256` |
| Bug-bounty policy | `automation_allowed` / `ai_testing_allowed` as hard gates; mandatory ident header |
| Provability | a hash-chained, append-only audit trail |

## Special cases

- **Cloud assets** (AWS/Azure etc.): customer authorization alone is
  sometimes not sufficient — some providers require separate test
  notification/approval.
- **Bug bounty**: `automation_allowed` and `ai_testing_allowed` must be
  taken from the **concrete** program rules, not assumed. If
  `ai_testing_allowed=false`, the Vector Agent may not run. A hit on an
  out-of-scope asset is a serious violation — deny precedence protects
  against it.
- **Vulnerable test targets** (lab) must only ever be run in isolated,
  self-controlled environments (see [testing.md](testing.md)).
- **HexStrike** has a documented history of misuse (autonomous zero-day
  exploitation); autonomous exploitation without gateway control is
  excluded.
