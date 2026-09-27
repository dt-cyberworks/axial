# Lab Environment

Isolated test environment (`source = lab`). Vulnerable targets for verifying
BOTH the scanner and the gateway.

Containers preferred · VM where necessary · strict network isolation

Version 1.0 · Companion document to Deployment v1.0 (stage M1)

> [!WARNING]
> **⚠ SECURITY — baseline warning.** Metasploitable and similar targets are
> DELIBERATELY vulnerable. They must never be exposed to the internet or a
> production network. Such a target on an open network gets compromised
> within minutes and can become a stepping stone against other systems. The
> entire lab environment therefore runs on a strictly isolated network with
> no route to the internet (Ch. 3).

## 1. Purpose: two testing directions

The lab environment verifies not only that the scanner finds vulnerabilities,
but equally importantly, that the Scope Gateway correctly blocks. Both need
matching targets.

| Direction | Question | Target type |
|---|---|---|
| Positive test | Does the scanner find real, known vulnerabilities? | vulnerable targets (Metasploitable, Juice Shop) |
| Negative test | Does the gateway block what's outside scope? | an out-of-scope target on the same network that must NOT be hit |
| Regression test | Do findings stay stable across versions (fingerprint/diff)? | the same targets, repeated runs |

> [!NOTE]
> **The negative test is often forgotten.** A second, deliberately
> NOT-authorized target on the same lab network is your most important
> security test: the scanner must be able to "see" it, but the gateway and
> the egress proxy must reject every active access to it. Only once this
> negative test is green is your scope enforcement demonstrably working.

## 2. Target catalog

### 2.1 Containers (preferred)

| Target | Covers | Relates to |
|---|---|---|
| Metasploitable2 (Docker) | many open services, old versions → CVE correlation | `vuln`, `fingerprint` |
| OWASP Juice Shop | modern web-app vulnerabilities (OWASP Top 10) | `vuln`, web logic (agent) |
| DVWA | classic web vulnerabilities, adjustable difficulty | `vuln`, `fingerprint` |
| your own "clean" nginx | negative target: deliberately unremarkable / out-of-scope | gateway negative test |

> [!TIP]
> **✓ Why containers are the default choice.** Fits your existing
> Compose/K8s setup, starts in seconds, is disposable and version-
> controllable. Entirely sufficient for discovery, fingerprinting, CVE
> correlation, and web checks (the bulk of your ASM scan).

### 2.2 VM (only where necessary)

- Metasploitable3 (Vagrant/VM): a more realistic OS/network environment
  including Windows targets — useful if you want to test service
  fingerprinting or scan types that behave differently against a real
  network stack than inside a container.
- When VM instead of container? Only when a container's shared host kernel
  would distort the test result (certain nmap scan types, kernel-adjacent
  services). Usually not necessary to get your ASM scanner started.

> [!NOTE]
> **Pragmatic recommendation.** Start purely container-based (M1). A
> Metasploitable3 VM only pays off once you want to specifically test
> network behavior a container can't authentically reproduce — then as an
> isolated VM on the same locked-down lab network.

## 3. Network isolation (the core of it)

The entire lab runs on an `internal` Docker network with no default route to
the internet. The scanner reaches the targets, but neither the targets nor
the scanner reach the outside world from here.

Listing 1: all targets + scanner on the `internal` network; no port mappings.

```yaml
# lab-compose.yml - fully isolated test environment (source=lab)
services:
  metasploitable2:
    image: tleemcjr/metasploitable2
    networks: [lab]           # lab network only, no egress
    # NO ports: mapping -> nothing is exposed to host/internet

  juice-shop:
    image: bkimminich/juice-shop
    networks: [lab]

  clean-nginx:                # negative target (out-of-scope test)
    image: nginx:stable
    networks: [lab]

  tool-runner:                # your scanner (from the Deployment doc)
    build: {context: ., dockerfile: runner.Dockerfile}
    networks: [lab]           # sees the targets, but no egress
    cap_drop: [ALL]
    cap_add: [NET_RAW]

networks:
  lab:
    internal: true            # NO route to the internet (critical)
```

> [!WARNING]
> **⚠ SECURITY — `internal: true` + no ports.** Two rules make the lab safe:
> (1) `internal: true` removes the network's default route to the internet —
> vulnerable targets can't "phone home" and aren't reachable from outside.
> (2) NO `ports:` mapping — nothing is published to the host or beyond. Both
> together are non-negotiable.

### 3.1 Verifying isolation (mandatory before every use)

Listing 2: three checks — the lab is cleared for use only once all PASS.

```bash
# Test 1: the target does NOT reach the internet
docker compose -f lab-compose.yml exec metasploitable2 \
  sh -c 'wget -q --timeout=5 -O /dev/null http://google.com \
         && echo FAIL:Internet || echo PASS:blocked'

# Test 2: the scanner DOES reach the targets
docker compose -f lab-compose.yml exec tool-runner \
  sh -c 'nmap -sV metasploitable2 | head'

# Test 3: no default route on the lab network
docker compose -f lab-compose.yml exec metasploitable2 \
  sh -c 'ip route | grep -q default && echo FAIL || echo PASS:no-default'
```

## 4. Integration into the scanner & data model

The lab isn't a special case — it's a regular engagement with `source='lab'`,
so you're testing the real code path, not a stand-in.

| Field | Value in the lab | Effect |
|---|---|---|
| `engagement.source` | `lab` | no external authorization needed, but isolated network only |
| `scope_asset` (allow) | `metasploitable2`, `juice-shop` | authorized targets, `active_allowed=true` |
| `scope_asset` (deny) | `clean-nginx` | negative target: must be blocked |
| `tool_grant` | all categories active | full pipeline test |
| Egress proxy | points at the lab network | enforces scope here too (negative test) |

> [!NOTE]
> **The lab run tests THREE things at once.** 1) Does the scanner find the
> known Metasploitable/Juice Shop vulnerabilities (positive)? 2) Do the
> gateway + proxy block every active access to `clean-nginx` (negative)?
> 3) Are classification, risk score, and the report correct? One run
> validates the scan engine, the security layer, and the evaluation layer
> together.

### 4.1 Expected findings as a test oracle

Because Metasploitable2's vulnerabilities are documented, they serve as
"ground truth": you know in advance what the scanner MUST find, and can
measure error rates.

- Known open services (including vsftpd 2.3.4 with backdoor, outdated Samba/
  Tomcat/MySQL versions) → expected CVE findings.
- Comparing actual findings against the documented expected list → measures
  false negatives (missed) and false positives (wrongly reported).
- Juice Shop provides modern web/logic vulnerabilities → a test oracle for
  the Agent (`logic` category).

### 4.2 Placement in the maturity path

| Stage | Environment | Purpose |
|---|---|---|
| M1 (here) | Lab (this document) | verify scanner + gateway against known targets |
| M2–M3 | your own domain | test against real, owned assets |
| M4–M5 | bug-bounty scopes | harden against third-party, authorized targets |
| M6 | customer | production managed service |

> [!TIP]
> **✓ Why the lab comes first.** In the lab you can fail destructively
> without risk: no real target, no legal questions, no reputational damage.
> Only once both the positive AND negative test are reproducibly green here
> do you move to your own domains — and only after that, outward.

---

**Note:** Vulnerable test targets must only ever be operated in isolated,
self-controlled environments. This specification is not legal advice.
