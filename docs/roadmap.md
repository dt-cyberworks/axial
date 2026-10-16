# Roadmap

What is built, and what comes next. The security layer (Scope Gateway, audit
log, egress controls) is in place before each active capability is added.

## Where the project stands

| Capability | Status |
|---|---|
| Engagement and scope model, Scope Gateway, audit log, passive discovery | ✅ Deterministic gateway with deny precedence, hash-chained audit log, engagement wizard, live run view, multi-source passive discovery, and an isolated lab test loop. |
| Vulnerability correlation, scoring, report, dashboard | ✅ Live NVD/EPSS/CISA-KEV correlation, risk scoring with a persistent KEV override, run-over-run diff, attack-surface graph, and a styled PDF report. |
| Active fingerprinting, safe active checks, approval workflow, rate limiting | ✅ nmap through a signed, time-boxed raw-egress lease; httpx, wafw00f, testssl, nuclei, nikto, and ffuf through the egress proxy; per-command human approval for anything state-changing; scan rate policy. |
| Bug-bounty program policy | ✅ Program model with identification header, rate caps, and per-program network-scan capability. |
| Vector Agent | ✅ Reason-act-observe loop against any OpenAI-compatible model; every proposal goes through the gateway; opt-in per engagement, budget-bounded, read-only by default. |
| Accounts, ownership and triage | ✅ Individual accounts with MFA, per-user engagement ownership, and finding triage (accepted risk / false positive / resolved). |
| Operating modes, change feed and alerts | ✅ Monitoring and test engagements, capabilities per engagement, the change feed, inbox, signed-webhook alerts, run health, pause/close/revoke, semi-attended parking. |
| Scheduled re-scans | ✅ A monitoring engagement can run every N days (1 to 90), inside its authorized window, on the one start path. |

## What's next

Ordered by value; items marked R3 or R4 change what the scanner may do and need
explicit authorization before implementation.

1. **Standing consent to state-changing requests** (R4,
   `operating-modes-state-change-consent.md`, draft) and the gateway-resident forms of the
   narrowing rules. Waiting for the permission to change the Scope Gateway.
   (Scheduled re-scans, REQ-MON-001, are built: one interval in days per monitoring engagement.)
2. **Discovery and detection coverage** (R4) — more passive discovery sources
   (subfinder), subdomain-takeover templates, crawling and URL history for
   endpoint discovery, and a self-hosted interaction server so blind
   vulnerability classes become visible.
   (REQ-COVER-001/003/004/006/007, backlog)
3. **Bug-bounty workflow** — import program scope from platform APIs and
   export a finding as a ready-to-submit report.
   (REQ-BBW-001..002, backlog)
4. **Findings-first engagement view** — findings and assets up front,
   run history and configuration behind them; a cross-engagement view of
   all open findings.
5. **Secrets in Vault/SOPS** instead of environment files.
