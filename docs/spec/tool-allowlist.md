# Tool Allowlist

Which tools HexStrike gets. The binding positive list for the runner image &
`tool_grant` mapping.

Build-time allowlist · runtime grants · argument hardening

Version 1.0 · Companion document to Architecture v2.1 & Deployment v1.0

> [!NOTE]
> **Core statement.** By default, HexStrike loads its full arsenal of 150+
> Kali tools — including password crackers, exploit generators, and
> credential harvesting. For a managed ASM service that is far too large an
> attack surface and liability. This document binds what tools get
> installed at all (build time) and how they map onto the `tool_grant`
> categories (runtime). A tool that isn't installed can't be misused.

## 1. Two layers of tool restriction

You need both layers — they complement each other, neither replaces the
other.

| Layer | When | Defined where | Effect |
|---|---|---|---|
| Build-time allowlist | at image build | `runner.Dockerfile` (Deployment doc) | Ceiling: what's possible at all |
| Runtime grant | per engagement | `tool_grant` + gateway + HexStrike `--profile` | Subset: what runs on this engagement |

> [!IMPORTANT]
> **⚖ LEGAL / SECURITY — build time is the hardest boundary.** A tool that
> isn't installed in the runner image can't be invoked by HexStrike or the
> LLM — regardless of any prompt or bug. That's why the image deliberately
> contains ONLY the allowlisted tools, not HexStrike's full arsenal.

> [!NOTE]
> **Relationship to `tool_grant`.** The build-time allowlist (this document)
> is the ceiling. Per engagement, the gateway loads only the categories in
> the signed `tool_grant` (via HexStrike `--profile`). Only what additionally
> has `active_allowed=true` on the target actually becomes active.

## 2. The allowlist (installed in the runner image)

Grouped by your `tool_grant` categories. Only non-destructive tools suitable
for external assessments.

### 2.1 `recon` (discovery) — passive/semi-passive

| Tool | Purpose | Mode |
|---|---|---|
| `subfinder` (runs in the worker image, REQ-COVER-001; per-engagement switch) | passive subdomain enumeration | passive |
| `amass` (retired, REQ-COVER-005: not enabled) | subdomain/OSINT (passive mode) | passive |
| `dnsx` / `dnsutils` | DNS resolution, records | passive |
| `tlsx` | TLS/certificate data | passive |
| (crt.sh via API) | certificate-transparency logs | passive |

### 2.2 `fingerprint` — passive to lightly active

| Tool | Purpose | Mode |
|---|---|---|
| `httpx` | HTTP probing, tech/title detection | active (light) |
| `whatweb` (retired, REQ-COVER-005: not enabled) | technology-stack detection | active (light) |
| `nmap` | service/version detection (`-sV`) | active |
| `sslscan` (retired, REQ-COVER-005: not enabled) / `testssl` | TLS configuration analysis | active (light) |
| `wafw00f` | WAF detection | active (light) |

> [!IMPORTANT]
> **⚖ LEGAL / SECURITY — nmap: hardened arguments only.** nmap is permitted,
> but the gateway enforces safe flags: only `-sV`/`-sS` on the ports allowed
> by the grant, NO exploit NSE scripts (`--script=exploit*` is blocked), no
> aggressive full-range UDP scan. Details in Ch. 4.

### 2.3 `vuln` (CVE/misconfig) — active, non-destructive

| Tool | Purpose | Mode |
|---|---|---|
| `nuclei` | template scans — `safe` tags ONLY | active |
| `nikto` | web-server misconfig (non-invasive) | active |
| (in-house checks) | headers, `.git`/`.env` exposure, takeover | active |

> [!IMPORTANT]
> **⚖ LEGAL / SECURITY — nuclei: safe templates only.** Nuclei ships 4,000+
> templates, including intrusive and DoS ones. Only templates tagged `safe`,
> or without `intrusive`/`dos`, are permitted. The gateway filters the
> template selection; everything else is blocked.

### 2.4 `cred` — only with explicit authorization & per-step confirmation

| Tool | Purpose | Mode |
|---|---|---|
| (in-house default-credential check; retired, REQ-COVER-005: not enabled) | known default logins only, max. 3 attempts | active ⚖ |

> [!IMPORTANT]
> **⚖ LEGAL / SECURITY — no brute force, no general-purpose crackers.**
> hydra/medusa/patator are deliberately NOT installed. The only permitted
> credential test is a narrowly scoped check for vendor-known default
> logins — and only with `tool_grant` (`cred`, active), `active_allowed=true`,
> and human per-step approval.

## 3. Excluded (NOT in the image)

These HexStrike categories and individual tools are deliberately never
installed:

| Category / tool | Why excluded |
|---|---|
| Password crackers: `hydra`, `john`, `hashcat`, `medusa`, `patator`, `ophcrack` | brute force against customer systems; no place in ASM scope |
| Credential harvesting: `responder`, `netexec`, `crackmapexec`, `evil-winrm` | LLMNR/NBT-NS poisoning & lateral movement — offensive intrusion |
| Exploit/payload: `metasploit`, `commix`, `xsser`, `sqlmap` (destructive), `dalfox` | active exploitation/payload generation; destructive risk |
| Binary/RE & CTF: `ghidra`, `radare2`, `gdb`, `pwntools`, `angr`, `volatility3` | irrelevant to external ASM; attack surface only |
| masscan / aggressive full-range scanners | blast radius/load on customer infrastructure not justifiable |

> [!WARNING]
> **✕ EXCLUDED — the principle.** If a tool's primary purpose is to break
> into a system, harvest credentials, or execute payloads, it does NOT
> belong in a managed ASM service. Such capabilities would at most be part
> of a separate offering — contractually and insurance-wise scoped on its
> own — not the scanner's core product.

## 4. Mapping: allowlist → HexStrike profile → `tool_grant`

How the allowlist interlocks with HexStrike's `--profile` mechanism and your
data model.

Listing 1: the profile is always a subset of the installed allowlist.

```python
# Deriving the HexStrike profile from the signed tool_grant
def hexstrike_profile(engagement):
    cats = active_categories(engagement)   # from tool_grant
    tools = set()
    for c in cats:
        tools |= ALLOWLIST[c]              # only tools of this category
                                            # that are ALSO installed
    # HexStrike gets an explicit tool whitelist, never a 'full' profile
    return {'allowed_tools': sorted(tools),
            'profile': 'custom',
            'deny_all_others': True}
# ALLOWLIST is the build-time list from Ch. 2 (superset).
# active_categories() is the engagement-specific subset (Ch. 1).
```

> [!NOTE]
> **`deny_all_others = True`.** HexStrike is never run with `--profile full`.
> It gets an explicit whitelist of permitted tools per engagement; everything
> else is locked. Even if an unintended tool were somehow present in the
> image, the gateway would still reject the call (`tool_not_whitelisted`).

### 4.1 Argument hardening (repeated from the Architecture doc, binding)

| Tool | Enforced | Blocked |
|---|---|---|
| `nmap` | only `-sV`/`-sS`, ports from the grant | `--script=exploit*`, `-sU` full-range |
| `nuclei` | `safe` tag only | `intrusive`, `dos` tags |
| `httpx` | GET/HEAD/OPTIONS | PUT/DELETE without a grant |
| Default-credential check | max. 3 attempts, default list only | brute-force wordlists |

### 4.2 Build-time verification

Listing 2: guard in the Dockerfile — prevents accidental inclusion.

```dockerfile
# Build fails if an excluded tool ends up installed anyway.
RUN set -e; for bad in hydra john hashcat medusa metasploit responder \
        netexec crackmapexec sqlmap ghidra radare2 masscan; do \
      if command -v $bad >/dev/null 2>&1; then \
        echo "FORBIDDEN: $bad is installed" && exit 1; fi; done
```

> [!IMPORTANT]
> **⚖ LEGAL / SECURITY — the allowlist is a versioned artifact.** This list
> is version-controlled (Git) and is part of the release process for a new
> runner image. Every addition of an active/offensive tool is a deliberate
> decision requiring renewed legal/insurance review — never an incidental
> `apt install`.

---

**Note:** Technical specification, not legal advice. Operating offensive
tools is subject to computer-misuse and related law in your jurisdiction and
should be secured with qualified legal counsel.
