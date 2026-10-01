# Glossary

**Who this is for:** anyone who meets a word in the console or the manual that they do not know.
**After this page you can:** look up the meaning of every term Axial uses.

<!-- ui-labels: Vector Agent | Lens Agent | Diff -->

| Term | Meaning |
|---|---|
| **Active (mode)** | a tool grant for tools that send requests to the target. Compare *passive* |
| **Allow / deny** | the two kinds of scope row. Deny always wins |
| **Approval** | a person's one-time decision on one stored request. See [Approve or deny a tool call](guides/approve-or-deny-a-tool-call.md) |
| **Asset** | something in scope or discovered: a host, an address, a service |
| **Asset review** | an optional pause after discovery in which you drop hosts that should not be scanned |
| **Attack surface** | everything about your organisation that can be reached from the internet |
| **Attestation** | your confirmation, per active allow row, that you are permitted to test it |
| **Audit log** | the append-only, hash-chained record of everything the system did. See [Audit](reference/audit.md) |
| **Backup codes** | ten one-time codes shown once at enrolment; the way in if the authenticator is lost |
| **Baseline** | the previous run a run is compared with. The first run has none |
| **Budget** | a limit on a run: tool calls (200 by default), agent iterations (50), and a time limit per check (30 minutes at most) |
| **Campaign** | one engagement's own settings, as opposed to the installation-wide defaults. See *override* |
| **CIDR** | a range of IP addresses written like `203.0.113.0/28` |
| **CNAME** | a DNS alias; the *DNS & hosting* view shows the full chain |
| **Confidence** | *validated* (demonstrated) or *inferred* (reasoned). See [Concepts](concepts.md#confidence-validated-or-inferred) |
| **Coverage** | how much of the surface a run really examined. *Reduced coverage* and *partial coverage* mean it was less than all |
| **CVE** | a numbered public vulnerability, for example CVE-2023-46604 |
| **CVSS** | a standard severity score for a CVE |
| **De-duplication** | the same problem on the same target is one finding, however often it is seen |
| **Discovery** | the first phase: finding hosts and subdomains |
| **Discovery extras** | four optional switches: passive subdomain sources, crawling and URL history, out-of-band testing, web screenshots |
| **Draft** | the first status of an engagement, until it is activated |
| **Egress proxy** | the only route for web tools to a target; it re-checks every request against the scope |
| **Emergency contact** | whom to call if a test causes problems |
| **Engagement** | one authorised assignment: scope, window, tools, runs, findings |
| **EPSS** | a public estimate of how likely a CVE is to be exploited |
| **Evidence** | what a tool returned that proves a finding, with secret values redacted |
| **Fingerprint** | what a service is and runs; also the phase that finds it, and the identity that matches a finding across runs |
| **Finding** | one problem on one target, with evidence, a score and a status |
| **Force on / Force off** | a campaign override for one tool. It cannot create a grant |
| **Grant (tool grant)** | the authorisation for a category of tools on an engagement. See [Control which tools run](guides/control-which-tools-run.md) |
| **Inferred** | see *confidence* |
| **KEV** | the public list of vulnerabilities known to be exploited in the wild; a listed CVE is scored critical |
| **Lens Agent** | the AI model that explains a finding in plain language |
| **MFA / TOTP** | two-factor authentication with a time-based code from an authenticator app |
| **nuclei template** | one small, individually written check for one known issue |
| **OSINT** | information from public sources; what *passive* tools use |
| **Out-of-band** | a test where the target has to contact a server, so a blind weakness can be confirmed |
| **Override (campaign)** | a per-engagement setting that takes precedence over the installation default |
| **Override (operator)** | a one-click action on a denied gateway decision that adds what was missing; it is itself logged |
| **Partial** | a check that stopped at its time budget. What it found is real; it is not clean |
| **Passive (mode)** | a grant for tools that only read public sources and send nothing to the target |
| **Phase** | one stage of a run: discovery, fingerprint, correlate, agent, score, report |
| **Plan** | what a run decided to check on each open port, and what became of each check |
| **Raw egress gateway** | grants network scans a short-lived, scope-bound network permission |
| **Run (scan run)** | one execution of the pipeline for an engagement |
| **Runner** | the isolated place where the scanning tools execute |
| **Scan depth** | *Standard* or *Thorough*: how many checks run on each web service |
| **Scope** | the allow and deny rows that define what may be tested |
| **Scope Gateway** | the deterministic check that authorises every tool call. See [Concepts](concepts.md#scope-gateway) |
| **Severity** | critical, high, medium, low or info, derived from the risk score |
| **Surface** | one open port with its service class: web, redirect only, TLS service, other service |
| **Takeover (subdomain)** | a name whose DNS points at a de-provisioned third-party service an attacker may claim |
| **Test window** | the dates in which scanning is authorised |
| **Thorough** | the deeper scan depth: every template, plus a deep content-discovery sweep |
| **Triage** | giving a finding a status: resolved, accepted risk, false positive, or open |
| **Validated** | see *confidence* |
| **Vector Agent** | the AI model that proposes further checks. It cannot execute anything |
| **WAF** | a web application firewall in front of a site |
| **Wildcard** | a scope row with a pattern such as `*.example.com`; it does not cover the bare domain |
