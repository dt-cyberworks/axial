# Legal Prerequisites

> **Not legal advice.** This page lists what should be in place before you scan
> a system that is not yours. Actively scanning or testing third-party systems
> without authorization can be a criminal offence in many jurisdictions; a
> qualified lawyer can tell you what applies to you.

The Scope Gateway enforces technically that Axial only touches what you
record as in scope. Having permission to test every target is your
responsibility, and it has to exist before the scan starts.

## Before the first scan against a third-party system

Checklist from the [scanner specification](spec/scanner-specification.md) and
the [Rules of Engagement](spec/rules-of-engagement.md):

- [ ] **A recorded engagement** with an exact scope (domains/IP ranges, not "the whole company")
- [ ] **Proof of authorization** for every actively authorized asset — ownership, a customer/program
      contract, or a public invitation to test (e.g. a dedicated pentest practice
      platform); for cloud, possibly additional provider authorization
- [ ] **Test window & emergency contact** at the customer
- [ ] **Explicit exclusions** (no DoS, no social engineering, no exfiltration, unless agreed)
- [ ] **Insurance or other cover**, if your organization requires it before testing
- [ ] **A complete audit trail** (already technically enforced, see [security-model.md](security-model.md))
- [ ] **Data handling** where personal data is captured (e.g. exposed email addresses): redaction and retention

## How the system enforces it

| Requirement | Technical enforcement |
|---|---|
| Authorization needed | `engagement.status` must be `active`; transition only via the authorization checklist (`/activate`) |
| Exact scope | `scope_asset` allow/deny; `deny` takes precedence |
| Time window | Gateway **and** egress proxy reject outside `[authorized_from, authorized_until]` |
| Per-asset authorization | The `active` transition is blocked until actively authorized assets are `authorization_verified` (the basis can be ownership, contract, program, or public invitation) |
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
