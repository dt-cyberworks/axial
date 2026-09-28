# Security Policy

This project is itself a security tool. The threat model and the control
mechanisms are described in
[docs/security-model.md](docs/security-model.md).

## Reporting vulnerabilities

Please **do not** report security-relevant bugs via public issues. Report
them privately through GitHub's private vulnerability reporting: open the
repository's **Security** tab and choose **Report a vulnerability**
(<https://github.com/dt-cyberworks/axial/security/advisories/new>). Include:

- the affected component (control-plane, worker, egress-proxy, tool-runner, frontend),
- reproduction steps,
- an assessment of impact (in particular: can the Scope Gateway or the
  egress proxy be bypassed?).

Especially critical and handled with priority:

- **Scope bypass** — an active tool call reaches a target outside the scope
  (a violation of deny precedence or the time window).
- **Audit tampering** — the hash chain can be broken, or an entry
  suppressed.
- **Zone breakout** — the execution plane (tool-runner) reaches the control
  plane, the DB, or the audit log.

## Operational security (for users)

- **Never** expose deliberately vulnerable test targets to the internet —
  keep them on an internal network with no default route and no published
  ports, and verify that before every use (the project's own lab harness,
  `lab/verify-isolation.sh`, is not yet in the public release).
- Only run active scans with documented authorization (see
  [docs/legal.md](docs/legal.md)).
- Secrets (signing keys, the LLM provider's API key) belong in Vault/SOPS, not in a
  production system's `.env`.
