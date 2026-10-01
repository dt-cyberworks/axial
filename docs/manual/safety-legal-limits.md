# Safety, legal and limits

**Who this is for:** anyone who decides whether Axial may be used on a target, anyone who signs off on its use, and operators who want to know exactly what it will and will not do.
**After this page you can:** say what a scan does to a target and what it never does, list what you must have in place before the first scan, and name what Axial does not cover.

<!-- ui-labels: Activate engagement | Authorization PDF | Stop scan | authorization attested -->

> **Not legal advice.** This page summarises how Axial behaves and which legal prerequisites exist. The concrete criminal-law, data-protection and contractual assessment for your jurisdiction should be secured with qualified legal counsel. The binding statements are in [`docs/legal.md`](../legal.md) and the [Rules of Engagement](../spec/rules-of-engagement.md).

## The short version

Actively scanning a system you are not authorised to test can be a criminal offence in many jurisdictions. Axial enforces **technically** that it only touches what you put in scope, inside your test window, with the tools you allowed. It cannot know whether you are *entitled* to put something in scope. That part is yours, and it has to be in place **before** the first scan.

## What a scan does to a target

- **It is conservative and non-destructive by design.** The template-based checks exclude everything tagged intrusive, denial-of-service or fuzzing. Content discovery, crawling and the TLS check are rate-limited, time-boxed and send read requests.
- **Template checks do send some requests with a body.** A few of nuclei's fixed templates try the vendor-default login of a product they identified, or send an injection-style probe. They are chosen as non-destructive and they are part of the tool, not composed by anyone at run time.
- **A request the AI agent composes that could change data always waits for you.** A request with a method other than GET, HEAD or OPTIONS, or with a body, is proposed by the agent and waits for a person's explicit approval, which authorises that one request once.
- **It does not exploit systems.** One supervised probe confirms a specific, serious ActiveMQ flaw; it needs a person's approval every single time and is the exception. Nothing extracts data, drops files, or runs commands on a target.
- **It does not brute-force logins.** No password lists are used. The only credential tests are the default-login templates above and, if you switch it on, a separate tool that tries a short list of vendor defaults (off by default; see [Tools](tools.md#tools-that-exist-but-are-off-by-default)). Where credentials are supplied, or a target allows open self-registration, the agent may log in, with the login itself going through approval.
- **It stays inside the scope.** The Scope Gateway authorises every tool call, and the egress proxy re-checks every web request on the network. A deny row always wins. Names that discovery finds are filtered through the scope before anything touches them.
- **It respects the window.** Outside the authorised dates every call is denied, by both the gateway and the proxy.
- **It is rate-limited.** A global limit applies, and a bug-bounty program's own cap applies on top.
- **The AI agent can only propose.** It cannot cause an action the gateway has not authorised, so an unusual or manipulated prompt cannot move a scan outside its scope.
- **Everything is recorded** in a tamper-evident audit log, so you can show what was done and when it was approved.

You can stop a scan at any time with **Stop scan**, and tools of that run are terminated.

## Before the first scan

From [`docs/legal.md`](../legal.md) and the [Rules of Engagement](../spec/rules-of-engagement.md), the checklist for a scan of a third party's system:

- A **signed engagement** with an exact scope: domains and ranges, not "the whole company".
- **Proof of authorisation** for every actively authorised asset: ownership, a customer or program contract, or a public invitation to test (for example a dedicated practice platform). For cloud assets, the cloud provider may require its own notification.
- A **test window** and an **emergency contact** at the customer.
- **Explicit exclusions.** By default these are excluded unless expressly agreed: denial-of-service or load testing, social engineering, data exfiltration, destructive exploitation and physical testing.
- **Professional liability insurance** that covers security testing, before the first scan.
- **Data-protection compliance** where personal data is captured, for example exposed email addresses in evidence.
- **Employer approval** for secondary work and a check for conflicts of interest, if that applies to you.

How Axial supports this: the **authorization attested** tick on every active allow row, the **Authorization PDF** with signature lines, the checks at **Activate engagement**, and the audit log. None of them replaces the paper.

## Bug-bounty programs

Take `automation_allowed` and the AI-testing permission from the **concrete** program's rules; never assume them. If a program does not permit automated testing, do not tick it: every automated request is then denied. If it does not permit AI testing, the agent is not allowed to run. Enter the program's identification header and its request caps exactly; a hit on an out-of-scope asset is a serious violation, which the deny rules are there to prevent. See [Define an engagement and its scope](guides/define-an-engagement.md#bug-bounty-engagements).

## Practice and lab targets

Deliberately vulnerable targets belong only in an isolated, self-controlled environment. Axial's own lab does exactly that on separate networks; see [`docs/testing.md`](../testing.md). Do not point a scan at a public vulnerable-by-design site unless it invites testing and you have read its rules.

## Your data

- **Evidence** (what the tools returned) and **reports** are stored in the installation's own storage, with secret values redacted before they are written. A report never contains raw tool output, and its screenshots stay out.
- **Deleting an engagement** removes its findings and scope. Its audit trail is kept, on purpose.
- **The AI provider** receives the context the agent works with: the scope, the hosts and services found, tool results and evidence with secrets redacted. Choose a provider that fits your client's terms, or leave the agent off. See [Configure the AI provider](guides/configure-the-llm.md).
- **Public sources** (certificate logs, DNS history, web archives) are queried for names of your authorised domains. Nothing is sent to your own systems at that point.

## What Axial does not cover

An honest list, so that a clean report is read for what it is.

- **It is not a penetration test.** It tests a running system from the outside with a fixed, conservative set of checks. It does not read source code, test business logic, chain weaknesses into an attack, or judge how bad a finding is for your particular business beyond the context you give it.
- **It finds what it can detect.** Template-based checks find *known* issues. A new or unusual weakness, or one that only shows when logged in as a particular user, can be missed. **No finding is not the same as no problem.**
- **Coverage can be partial, and says so.** A check has a time limit; a tool can fail; a host can be down. A run then carries **partial coverage** or **reduced coverage**, and the report states what was skipped. Read those before you read an empty list.
- **Discovery is as complete as public sources and DNS allow.** A subdomain that appears in no public record is not found. For an IP range, host discovery probes TCP 80 and 443 only, so a host that answers on neither is not found. UDP is limited to nine common ports and often inconclusive.
- **IPv4 only.** IPv6 scope is not supported and is rejected when you enter it.
- **Cloud accounts are matched by exact identifier**, not inventoried or scanned through the provider's API.
- **Authenticated testing is limited.** The agent can log in where credentials are supplied or self-registration is open. It is not a substitute for a tester with real accounts and roles. If it cannot log in, it is told to report what is behind the login as untested.
- **The agent is only as good as its model.** Its findings are marked *validated* or *inferred*; inferred ones are leads, not proof.
- **One installation, individual accounts.** There is no multi-tenant separation inside one installation: operators see only their own engagements, admins see all. Sign-in uses a password and an authenticator code; there is no single sign-on, no hardware keys and no self-service password reset, and the system sends no email.
- **No scheduled scans or alerts.** Scans start when a person starts them.
- **No guarantee of completeness for compliance.** A report supports an assessment; it does not certify that a system is secure or compliant.

If you need something on this list, plan for it separately.

## If something goes wrong during a test

1. Choose **Stop scan** on the run. Only that run's processes are terminated.
2. Call the **emergency contact** you recorded and tell them what you saw.
3. Keep the evidence: the run, its Activity tab and the engagement's [audit log](reference/audit.md) show exactly which requests were sent and when.
4. Do not delete the engagement; deleting removes findings and scope.
