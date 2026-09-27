import { Fragment, useState } from "react";

/**
 * In-app user documentation (REQ-DOC-001). Human-facing reference for every
 * screen, function, and field. Ships with the app (no backend / external site).
 */

interface Field { name: string; text: string }
interface DocSection { id: string; title: string; intro: string; fields?: Field[]; extra?: string }

const SECTIONS: DocSection[] = [
  {
    id: "concepts",
    title: "Core concepts & safety model",
    intro: "Axial runs authorized attack-surface scans. Read this first — it explains the ideas every screen builds on.",
    fields: [
      { name: "Engagement", text: "One authorized assignment against a defined scope, within a time window. Everything (scope, grants, runs, findings) belongs to an engagement." },
      { name: "Scan run", text: "One execution of the pipeline (discovery → fingerprint → correlate → Vector Agent → validate → risk scoring → report). An engagement can have many runs over time." },
      { name: "Scope Gateway", text: "A deterministic check that authorizes EVERY tool call. Out-of-scope, out-of-window, unsafe, or disabled calls are denied. It is the safety boundary — nothing runs without it." },
      { name: "Vector Agent", text: "An LLM that PROPOSES the next check. It never executes anything itself; every proposal passes through the Scope Gateway. A bad or manipulated prompt cannot cause an out-of-scope action." },
      { name: "Lens Agent", text: "An LLM that EXPLAINS an existing finding (what it is, impact, remediation) in customer-readable language. It only reads recorded evidence." },
      { name: "Findings", text: "Engagement-wide and de-duplicated by fingerprint. Re-scanning updates them; it does not create duplicates. Per-run change is shown as a Diff." },
      { name: "Risk score & severity", text: "A custom 0–100 weighted model, not a single named industry standard — it blends real industry signals (EPSS exploitation probability 35%, CVSS base score 20%, CISA KEV as a hard override to critical) with contextual factors (exposure 20%, business context 15%, validated-vs-inferred confidence 10%). Severity is a threshold on that score (critical ≥85, high ≥70, medium ≥40, low ≥15, info below). A tool/agent-asserted severity (e.g. a confirmed PII exposure) is preserved across re-scoring and keeps the numeric score consistent with that severity's band, even when there is no CVE/EPSS data to score from." },
      { name: "Authenticated scanning", text: "Most real applications keep their interesting functionality behind a login, so an unauthenticated-only scan systematically under-reports risk while looking clean. Where credentials are supplied or the target allows open self-registration, the Vector Agent can log in and the session is then carried automatically across its later requests to that same host for the rest of the run. A session is never replayed to a different host, never stored, and never outlives the run, and the login request itself still goes through the normal operator approval flow. If the agent cannot authenticate, it is instructed to report everything behind the login as untested rather than clean.", },
      { name: "Confidence: validated vs. inferred", text: "Every finding records what its conclusion actually rests on. 'Validated' means the weakness was demonstrated — a tool matched a template, or the Vector Agent observed it directly (e.g. requested an endpoint without authentication and got protected data back). 'Inferred' means it was reasoned from a version banner, product name, or context without an observation proving it on this target. Only a validated finding may carry its reporter's own severity assessment; an inferred one is scored by the platform instead, so a speculative claim cannot present itself as critical. The Vector Agent must declare this basis explicitly on every finding it reports, and an unrecognised or missing declaration always falls back to inferred." },
    ],
  },
  {
    id: "tools",
    title: "Tools the scanner uses",
    intro: "Every tool the pipeline can call, in plain language: what it does, why it's used, and — for full transparency — exactly what command and parameters it runs. The same detail is always visible per-call in Run detail → Activity/Vector Agent tab and in Audit.",
    fields: [
      { name: "Passive discovery (crt.sh, CertSpotter, HackerTarget)", text: "Before anything is scanned, the platform looks up which subdomains of your authorized domain already exist in public records — certificate-transparency logs and a couple of free DNS-history lookups — the same way anyone could by browsing those sites by hand. Nothing is sent to your systems at this stage; it only reads public third-party records, then resolves each candidate name's DNS to confirm it's real. This finds forgotten or unlisted subdomains a guess-based scan would miss. Three independent sources are queried so one going down (crt.sh is known to be flaky) never blocks discovery." },
      { name: "nmap — port & service scanner", text: "Finds which network ports are open on a host and identifies the service and version listening on each (e.g. \"Apache 2.4.52\", \"OpenSSH 9.6\"). This is the map everything after it works from — nothing else knows what's even there to test until nmap has looked. Runs as an SYN scan first to find open ports (nmap -sS -Pn -n --max-rate <rate> --host-timeout 600s, your engagement's configured port range), then a focused version-detection pass on just the ports found open (nmap -sV --version-light). UDP is the same idea, only run if you explicitly opted in, and capped to a short, fixed list of the most common UDP services rather than scanning all 65535 UDP ports. -Pn -n means it never pings first and never uses your DNS resolver — it only touches the target itself." },
      { name: "httpx — web liveness & fingerprint", text: "For every host with a web port open, confirms the site actually responds and reads its title, server banner, status code, and detected technology stack (WordPress, React, nginx, …). This is what turns a bare \"port 443 is open\" into \"this is a WordPress site running nginx.\" Runs as httpx -u <host> -tech-detect -status-code -title -web-server -include-response-header, routed through the platform's own egress proxy (never a direct connection) so every request is re-checked against scope at the network level too." },
      { name: "wafw00f — web firewall detector", text: "Checks whether a web application firewall (WAF) is sitting in front of a site (Cloudflare, Akamai, Imperva, …) and, if so, which one. This is context, not a vulnerability by itself — it shapes how the rest of the scan interprets odd responses (a WAF can make a site look \"broken\" when it's actually just blocking probes). Runs as wafw00f -p <proxy>, through the egress proxy like every other web tool here." },
      { name: "testssl — TLS & certificate check", text: "Examines a site's HTTPS setup: which TLS versions and cipher suites it accepts, whether its certificate is valid and correctly configured, and whether it's exposed to well-known TLS-layer weaknesses (Heartbleed, ROBOT, BEAST, and similar named issues). These are real, well-documented classes of TLS misconfiguration, not the site's application logic. Runs as testssl --protocols --server-defaults --vulnerable --severity LOW --proxy <proxy> <site>, restricted to real findings only (informational-only noise is filtered out by --severity LOW)." },
      { name: "nuclei — curated vulnerability templates", text: "Runs thousands of small, individually-written checks (\"templates\") maintained by a large open-source security community, each looking for one specific, known issue — an exposed config file, a default login page, a known CVE with a detectable signature, and so on. This is the platform's broadest single source of concrete, named findings. It deliberately runs in a conservative mode: templates tagged as intrusive, denial-of-service, or fuzzing are excluded outright, and only non-destructive checks run. Runs as nuclei -t /opt/nuclei-templates -tags cve,misconfig,exposure,exposures,default-login,waf,dast -etags intrusive,dos,fuzz,csp-bypass -severity info,low,medium,high,critical -proxy <proxy> -rate-limit 50, using a fixed, pre-downloaded template set (no live updates, so results are reproducible) plus one extra short pass for a single browser-based check (DOM-based cross-site scripting) that needs a real browser engine to evaluate." },
      { name: "nikto — web server misconfiguration scanner", text: "A long-established scanner focused on server-level housekeeping issues: missing security headers, outdated server software banners, and common misconfiguration patterns. It complements nuclei's application-level findings with server/infrastructure-level ones. Runs as nikto -useproxy <proxy> against the target, through the egress proxy like the other web tools." },
      { name: "ffuf — content discovery", text: "Systematically requests a curated list of likely paths (admin panels, backup files, forgotten API routes, …) against a site to find pages that exist but aren't linked from anywhere — the automated equivalent of a tester's own \"let me just try /admin and /backup.zip.\" The AI agent chooses a wordlist sized to what it's already learned about the site (from a short, generic list up to a larger, more thorough one) rather than always brute-forcing everything. Rate-limited and non-destructive: only read (GET-style) requests are ever sent. Runs as ffuf -w <curated wordlist> -u <site>/FUZZ -mc 200,204,301,302,307,401,403,405,500 -ac -rate 20, where -ac is ffuf's own filter for \"catch-all\" pages that would otherwise falsely look like a hit for every single word tried." },
      { name: "http_request (curl) — targeted manual-style probing", text: "The AI agent's own hands: a single, precisely-crafted HTTP request with whatever method, path, and headers it decides are worth trying — the same kind of targeted check a human tester would type by hand, rather than a canned scanner template. Used for things no template can anticipate: trying an access-control bypass header, checking whether a login form has anti-forgery protection, following up on something odd another tool noticed. Read-only requests (GET/HEAD/OPTIONS) run on their own; anything that could change data on the target (POST/PUT/DELETE/PATCH, or any request with a body) always pauses for your explicit approval first, with the agent's stated reason and risk assessment shown to you before it runs. Runs as curl -sS -i -X <method> --max-time 20 -x <proxy> <url>, with the response capped to the first 16 KB." },
      { name: "redis-probe — Redis reachability check", text: "Sends the single word \"PING\" to a port nmap identified as Redis and checks for the standard \"+PONG\" reply. This is the one thing worth confirming about an exposed Redis port from the outside: is it actually reachable, and does it require no authentication to respond at all (a real, common misconfiguration for this kind of database). It sends nothing else, and only that one fixed message — never anything the AI agent composes itself." },
      { name: "activemq-banner — ActiveMQ reachability check", text: "Purely listens: connects to a port nmap flagged as ActiveMQ and reads whatever greeting the broker sends on its own when a client connects (it announces itself unprompted). Sends nothing at all — this only confirms the service is really there and reachable, the passive equivalent of redis-probe for this specific message-queue software." },
      { name: "activemq-openwire-probe — ActiveMQ RCE proof (CVE-2023-46604)", text: "A specialized, one-purpose check for a specific, serious, well-known ActiveMQ vulnerability (CVE-2023-46604) that lets an attacker run commands on the server with no login at all. Ordinary scanners can only guess this exists from a version number; this tool actually triggers the vulnerable code path with a fixed, pre-built network message (never composed by the AI agent) and waits briefly to see whether the target then tries to fetch a one-time web address unique to that single check — if it does, that's direct proof the flaw is real and exploitable on this system, not a guess. Because it genuinely exercises the vulnerability rather than just observing, it is never run automatically: every single use requires your explicit, one-time approval, with the agent's reasoning and risk shown to you beforehand, exactly like a state-changing http_request. If no callback is seen, nothing is reported as a finding — an absence of proof is deliberately never treated as evidence either way." },
    ],
  },
  {
    id: "overview",
    title: "Overview (main page)",
    intro: "The landing page: every engagement, with quick status. Click an engagement to open its detail hub.",
    fields: [
      { name: "Engagements / Active scans / Agent armed / Needs setup", text: "Top metric strip: total engagements, how many have a running scan, how many have the Vector Agent enabled, and how many are still draft/awaiting setup." },
      { name: "Status", text: "Engagement lifecycle: draft → awaiting signature → active → paused/completed/revoked. Only 'active' engagements can scan." },
      { name: "Agent", text: "Whether autonomous Vector Agent proposals are enabled for this engagement (opt-in)." },
      { name: "Authorized window", text: "The date range in which scanning is permitted. Outside it, every tool call is denied — so scans are blocked before they start." },
      { name: "Row actions", text: "Open the engagement, Edit its metadata/config, view its Audit trail, or Delete it (findings/scope removed; audit retained)." },
    ],
  },
  {
    id: "engagement",
    title: "Engagement detail",
    intro: "The hub for one engagement: readiness, starting runs, the list of runs, and the engagement-wide findings.",
    fields: [
      { name: "Authorization", text: "If an active scope row is not yet attested, the hub lists it and offers Attest authorization. The Authorization PDF link remains available for review and signature." },
      { name: "Start a scan run", text: "Pre-flight readiness is checked first (REQ-RUN-002). If blocked (e.g. outside the time window, no active scope, no active tool grant), the reasons are listed and Start is disabled — no doomed run is started." },
      { name: "Start run button", text: "Enqueues a new scan run. Disabled while a run is already active or when readiness fails. Once active, a link opens the running run." },
      { name: "Runs table", text: "Every run for this engagement, newest first: run number, started/finished, duration, current phase, state (running/done/failed/aborted; 'stopping…' while a stop is being applied), and tool-call budget used. Click a row to open the Run detail. A run whose worker crashed or hung stops sending its heartbeat and is automatically aborted (reason 'reaped_stale_heartbeat') so it can never permanently block starting a new scan." },
      { name: "Severity distribution", text: "Counts of open findings by severity. Click a tile to filter the findings table below." },
      { name: "Attack-surface graph", text: "A relationship view of everything discovered for this engagement — hosts, IPs, services, technologies, CVEs and findings — and how they connect (a subdomain hangs off its domain, names resolve to shared IPs, a technology fans out across services, a technology is linked to a CVE). It is derived metadata built from the scan results and NEVER widens scope: solid nodes are in-scope assets you can target; dashed nodes (shared IPs, external CNAME targets, technologies, CVEs) are context only and are never scanned. Click a node for its details. The same relationships are given to the Vector Agent so it can reason across hosts (e.g. confirm a shared-infra weakness once instead of re-testing each name)." },
      { name: "DNS & hosting", text: "How each in-scope name resolves: the full CNAME chain and the hosting provider (AWS, Azure, Cloudflare, Okta, GitHub Pages, …). This is inventory metadata only — a CNAME target (e.g. an ELB or an Okta tenant) is never scanned and never becomes an asset; only the original name is. A row flagged 'dangling — takeover?' means the name's CNAME points to a de-provisioned target and may be claimable by an attacker (subdomain takeover); it is detected at the DNS level only (no request is sent to the third-party target) and is also raised as a finding for you to verify manually." },
      { name: "Open findings", text: "Engagement-wide findings (accumulated and de-duplicated across all runs). Click a row to expand evidence and request a Lens Agent explanation." },
      { name: "Scope assets", text: "Allow/deny rules for this engagement, viewable and editable here after creation (not only in the wizard). Deny always wins over allow. A host excluded via an asset review popup appears here as an automatically added deny row — remove it to re-include the host in future scans." },
      { name: "Asset review pause", text: "If enabled for this engagement, each scan run pauses right after discovery, before fingerprint/scanning continues, and shows every in-scope discovered host for manual confirmation (see Run detail → Asset review popup). Useful when a customer's DNS is poorly managed and discovery may include hosts that are not actually authorized." },
    ],
  },
  {
    id: "run",
    title: "Run detail",
    intro: "Everything about ONE run. A breadcrumb shows Engagements / {engagement} / Run #{n}. A running run can be stopped here.",
    fields: [
      { name: "Stop scan", text: "Cooperatively stops a running run (REQ-RUN-001). The control plane immediately marks the run aborted, closes pending approvals, and the worker terminates only that run's in-flight tool process group. Raw Nmap then revokes its lease; no other run is touched." },
      { name: "Progress tab", text: "The pipeline phases, each with the tools it can run (REQ-RUN-003) and its state for this run. Internal phases (correlate, validate, scoring, report) touch no targets." },
      { name: "Diff tab", text: "What changed versus the previous run: findings newly observed, findings no longer observed, and how many persist. The first run has no baseline." },
      { name: "Vector Agent tab", text: "Every agent iteration. Click a step to see the exact input sent to the model (system prompt + running messages) and the model's response and proposed tool calls (REQ-RUN-006). API keys are never stored. An observation marked 'EGRESS BLOCKED' means the request was stopped at the egress proxy and never reached the target — it is an infrastructure block, not a clean result." },
      { name: "Activity tab", text: "Human-readable tool outcomes, blocks, throttling, TCP/UDP ports, and UDP state counts grouped by phase. Routine checks can be expanded; the complete raw trail lives on Audit." },
      { name: "Approval popup", text: "Reads run autonomously, but a state-changing request (POST/PUT/DELETE/PATCH, or any request with a body) never runs on its own. When the agent proposes one, the run pauses ('waiting for approval') and a popup shows What (the exact request), Why (the agent's rationale), and Risk (the agent's own risk level and description). The popup appears wherever you are in the console — not only on this Run screen — and names the engagement it belongs to, so you never miss one. Approving takes you straight to that run so you can watch the request execute and feed its result back to the agent; Reject skips it. One popup per command (others queue); nothing state-changing executes without your click." },
      { name: "Asset review popup", text: "Only appears when 'Pause after discovery for manual asset review' is enabled for the engagement. Right after discovery, the run pauses and lists every in-scope discovered host, all pre-selected. Deselect any host that should not be scanned, then Continue with selected. Deselected hosts become a real deny rule (Scope Gateway-enforced, visible under Edit engagement → Scope assets) — this can only narrow what gets scanned, never widen it. If you don't answer within the review window, the run aborts rather than silently scanning everything." },
    ],
  },
  {
    id: "wizard",
    title: "New engagement wizard",
    intro: "Creates an engagement in guided steps: Window, Scope, Tools, Review, Authorize.",
    fields: [
      { name: "Window", text: "Title, emergency contact, authorized time window, TCP single-port/range (default 1-65535), explicit bounded UDP opt-in, and the optional post-discovery asset review pause. These persisted values define the signed Nmap envelope." },
      { name: "Scope", text: "The allow/deny assets. 'Authorization attested' confirms you are permitted to test the asset. Only active-allowed assets can receive active checks." },
      { name: "Tools", text: "Which tool categories are granted, in passive and/or active mode, and which require manual approval. Passive mode is only offered for real passive (OSINT) tools." },
      { name: "Review / Authorize", text: "A summary plus a downloadable authorization PDF documenting exactly what is configured, for signature before activation." },
    ],
  },
  {
    id: "settings",
    title: "Agent settings",
    intro: "Global configuration for the LLM provider, scan rate, per-tool policy, and the Vector Agent instructions.",
    fields: [
      { name: "Provider", text: "The OpenAI-compatible endpoint (base URL + model + API key) used by the Vector and Lens agents. Without it, the agent phase is a no-op." },
      { name: "Scan rate policy", text: "Maximum gateway-approved tool calls per second. With auto slow-down on, rate-limited calls wait and retry instead of hard-failing." },
      { name: "Tool policy (global defaults)", text: "Per tool: enabled and whether it needs one-time approval. Tools not installed can never be enabled. Campaigns can override these per engagement." },
      { name: "Vector Agent instructions", text: "The agent's global system prompt, always shown — starts as the built-in default (platform overview, engagement-parameter awareness, and an OWASP-Top-10-based check checklist) and is editable in place. Safe to edit: the Scope Gateway decides every action regardless of the prompt. Save an empty box to revert to the built-in default. Each engagement's edit page shows this same effective text and can save its own campaign-specific override without affecting other campaigns or the global default." },
      { name: "Vector Agent iteration budget", text: "The maximum number of tool-call round-trips the agent may make per run (default 50) before it must conclude. A malformed or rejected proposal still consumes one iteration, so raise this if the agent is running out of budget before finishing. Campaigns can override per engagement." },
    ],
  },
  {
    id: "audit",
    title: "Audit",
    intro: "The complete, hash-chained compliance trail for an engagement — every gateway decision, network request, transition, and agent event — presented as one chronological, searchable log.",
    fields: [
      { name: "One log, in order", text: "A single time-ordered list (newest first) of everything the system did. Each row is a plain-language line — who did what, on which target, and the outcome — with a colored decision badge (allow / deny / pending)." },
      { name: "Search", text: "The search box matches anywhere in the record — actor, action, reason, and inside the event payload — so you can type a hostname, tool name, target, or scan-run id and see just those events." },
      { name: "Filters", text: "Narrow by decision (allow/deny/pending), by actor (gateway, agent, egress-proxy, worker, a user…), or by action. 'Load older events' pages back through the full history; 'Live' tails new events while you're at the top." },
      { name: "Details & overrides", text: "Expand any row for the raw actor/action/reason/payload. Denied gateway decisions show a plain-language explanation and, where applicable, the one-click operator override." },
    ],
    extra: "Use Audit for evidence and troubleshooting. The Run detail Log is a filtered, run-scoped subset; Audit is the full record. Filtering/search is read-only — it never alters the hash-chained log.",
  },
  {
    id: "accounts",
    title: "Accounts, login & MFA",
    intro: "Individual accounts with mandatory two-factor authentication (TOTP) — there is no shared password and no public sign-up.",
    fields: [
      { name: "Signing in", text: "Email + password, then a 6-digit code from an authenticator app (Google Authenticator, 1Password, Authy, …) or a one-time backup code. A session is never issued from a password alone." },
      { name: "First login", text: "A new account starts with a one-time temporary password issued by an admin. First sign-in forces setting a real password, then enrolling MFA (scan the QR code or enter the secret manually) before any access is granted. 10 backup codes are shown once — save them; they're the only way in if the authenticator device is lost." },
      { name: "Account page", text: "Change your password, re-enroll MFA (requires re-entering your current password — replaces the old secret and backup codes immediately), and see/revoke your other active sessions." },
      { name: "Engagement ownership", text: "Each engagement belongs to the operator who created it — they see and manage only their own. Admins see and manage every engagement and can reassign ownership." },
      { name: "Admin: Users", text: "Admin-only. Invite new accounts (email + role; the temporary password is shown once), change roles, disable/re-enable accounts, and force a password or MFA reset (e.g. a lost phone) without needing that user's password." },
      { name: "Admin: Account audit", text: "Admin-only. Tamper-evident, hash-chained log of every login, MFA event, password change, session, and admin action — separate from the per-engagement Audit trail above." },
    ],
  },
];

export default function Documentation() {
  const [active, setActive] = useState(SECTIONS[0].id);
  return (
    <section className="page-stack">
      <header className="page-header">
        <div><span className="eyebrow">Help</span><h1>Documentation</h1><p>What every screen, function, and field does, and how to use it.</p></div>
      </header>
      <div className="docs-layout">
        <nav className="docs-index">
          {SECTIONS.map((s) => (
            <a key={s.id} href={`#${s.id}`} className={active === s.id ? "active" : ""} onClick={() => setActive(s.id)}>{s.title}</a>
          ))}
        </nav>
        <div className="docs-body">
          {SECTIONS.map((s) => (
            <section key={s.id} id={s.id} className="table-panel docs-section">
              <div className="panel-heading"><div><h2>{s.title}</h2><p>{s.intro}</p></div></div>
              {s.fields && (
                <dl className="definition-grid docs-fields">
                  {s.fields.map((f) => (<Fragment key={f.name}><dt>{f.name}</dt><dd>{f.text}</dd></Fragment>))}
                </dl>
              )}
              {s.extra && <p style={{ padding: "12px 16px", margin: 0 }}>{s.extra}</p>}
            </section>
          ))}
        </div>
      </div>
    </section>
  );
}
