# Tools: what each one does and why

**Who this is for:** operators who want to know what Axial sends to a target, and reviewers who have to approve that.
**After this page you can:** name every tool a scan can use, say in plain words what it does, why it is there, and whether it runs by itself, only when you switch it on, or only on your approval.

<!-- ui-labels: Discovery extras | Campaign tool overrides | Scan depth -->

Every request a tool sends goes through the [Scope Gateway](concepts.md#scope-gateway) first and, for web tools, through the platform's own egress proxy, which re-checks the target against your scope on the network. For the **exact command line, arguments and rationale** of each tool, see the [tool catalog](../security/tool-catalog.md), written for security researchers. This page deliberately does not repeat them, so the two cannot drift apart. What each tool did in a given run is always visible per call in **Run detail → Activity** and in the [Audit](reference/audit.md) log.

## At a glance

| Tool | Tells you | Started by | Your approval needed |
|---|---|---|---|
| Passive discovery (certificate logs, DNS history) | which subdomains exist in public records | the scan, always | never; nothing is sent to your systems |
| subfinder | more subdomains from public sources | the scan, on by default | never |
| nmap | which ports are open and what listens on them | the scan | only if you mark it for approval |
| httpx | which sites answer, and what they run | the scan | only if you mark it for approval |
| Security headers | missing browser security headers | the scan, from httpx's answer | never; no extra request |
| wafw00f | whether a web firewall is in front | the scan | only if you mark it for approval |
| testssl | HTTPS and TLS weaknesses | the scan | only if you mark it for approval |
| nuclei | known vulnerabilities, exposures, default logins | the scan | only if you mark it for approval |
| ffuf | pages and files that exist but are not linked | the scan (short list); deep list on **Thorough** | only if you mark it for approval |
| katana, URL history, nuclei on crawled URLs | pages and parameters the front page does not show | the scan, only if **Crawling and URL history** is on | only if you mark it for approval |
| nuclei out-of-band pass | blind vulnerabilities | the scan, only if **Out-of-band testing** is on | only if you mark it for approval |
| screenshot | what each web page looks like | the scan, only if **Web screenshots** is on | only if you mark it for approval |
| http_request | whatever one targeted request shows | the Vector Agent only | read-only requests: no. Anything that can change data: **always** |
| redis-probe, activemq-banner | whether an exposed Redis or ActiveMQ answers | the Vector Agent only | only if you mark it for approval |
| activemq-openwire-probe | proof of one specific ActiveMQ flaw | the Vector Agent only | **always, every time** |
| nikto | a classic web server check | the Vector Agent only; no longer part of the automatic scan | only if you mark it for approval |

"Only if you mark it for approval" refers to **Require approval for these active tools** in the tool grants; see [Control which tools run](guides/control-which-tools-run.md). Tools you have not granted, or have switched off, do not run at all.

## Finding what exists

### Passive discovery: public records

Before anything is scanned, Axial looks up which subdomains of your authorised domain already appear in public records: certificate-transparency logs and a couple of free DNS-history lookups. It is what anyone could do by browsing those sites by hand. **Nothing is sent to your systems at this stage.** Each name found is then resolved in DNS to confirm it is real and filtered through your scope. Three independent sources are asked, so one being down (one of them is known to be unreliable) never blocks discovery. This finds forgotten and unlisted subdomains that a guess-based scan would miss.

### subfinder: passive subdomain sources

Asks dozens of public data sources (certificate logs, DNS history, search indexes) for subdomains of your authorised domains. It runs in passive mode only: it never guesses names by brute force and never sends anything to your systems. Every name it returns goes through the same scope filter as every other source; names outside your allow rows, or matching a deny row, are dropped. Some sources return more with a free API key, which an admin can store in Settings (kept encrypted, never shown again). On by default; switch it off per engagement under **Discovery extras**.

### nmap: ports and services

Finds which network ports are open on a host and identifies the service and version listening on each, for example "Apache 2.4.52" or "OpenSSH 9.6". Everything after it works from this map: nothing else knows what there is to test until nmap has looked. It first finds open ports in your engagement's configured port range, then runs a focused version check on just those. UDP uses the same idea but only if you opted in, and only for a short fixed list of common UDP services, never all 65,535 ports. It never pings first and never uses your DNS resolver; it touches the target itself and nothing else. Exact flags: [catalog §2.1](../security/tool-catalog.md#21-nmap--portservice-discovery).

### httpx: is it a web site, and what runs on it

For every host with a web port open, confirms that the site answers and reads its title, server banner, status code and detected technology (WordPress, React, nginx and so on). It turns a bare "port 443 is open" into "this is a WordPress site on nginx". It goes through the platform's own egress proxy, never a direct connection. Exact flags: [catalog §2.2](../security/tool-catalog.md#22-httpx--http-liveness-and-tech-stack-fingerprint).

### Security headers

Axial no longer runs nikto in the automatic scan, because it always ran out of its time budget and most of what it found overlaps nuclei. Missing security headers (Strict-Transport-Security on HTTPS, Content-Security-Policy, X-Content-Type-Options, X-Frame-Options or a frame-ancestors rule, Referrer-Policy) are now read from the response headers httpx already recorded, so the check costs **no extra request** to your systems. A redirect is not judged, because its headers say nothing about the application.

### wafw00f: is a web firewall in front

Checks whether a web application firewall (Cloudflare, Akamai, Imperva and similar) sits in front of a site and which one. This is context, not a vulnerability: a firewall can make a site look broken when it is simply blocking probes. Exact flags: [catalog §2.4](../security/tool-catalog.md#24-wafw00f--waf-fingerprint-informational-only).

## Checking for known problems

### testssl: HTTPS and certificate hygiene

Examines which TLS versions and cipher suites a site accepts, whether its certificate is valid and correctly configured, and whether it is exposed to well-known TLS weaknesses such as Heartbleed, ROBOT or BEAST. It reports real findings only; informational noise is filtered out. It also checks non-web TLS services that the port scan found, such as mail and directory servers: ports that speak TLS from the start (465, 993) directly, and services that upgrade with STARTTLS (25, 587, 143, 110 and others) with the matching protocol. Each finding names the service and port, and a service that turns out not to speak TLS is shown as *skipped*, never as clean. testssl follows the engagement's tool list: while it is selected there it runs on web and non-web services alike, and when it is switched off it runs nowhere and the plan shows its checks as skipped. Exact flags: [catalog §2.5](../security/tool-catalog.md#25-testssl--tlscertificate-hygiene).

### nuclei: curated vulnerability templates

Runs thousands of small, individually written checks ("templates") maintained by a large open-source security community. Each looks for one specific, known issue: an exposed config file, a default login page, a known CVE with a detectable signature, a subdomain pointing at a de-provisioned third-party service (a *takeover*), and so on. Some of them try the vendor-default login of a product they identified, and a few send an injection-style probe; none uses password lists. It is the platform's broadest source of concrete, named findings.

It runs conservatively. Templates tagged as intrusive, denial-of-service or fuzzing are excluded outright, and only non-destructive checks run, from a fixed, pre-downloaded template set, so results are reproducible. The scan does not run all of the roughly 5,900 templates against every site. A technology check first works out what the site runs; then the generic templates run in shards of about 400, plus only the templates written for the products identified. A site where nothing could be identified gets the templates of a fixed list of common web products instead (WordPress, Drupal, Joomla, Apache, nginx, IIS, Tomcat, Jenkins, GitLab, Grafana, Confluence, Jira, PHP, Spring). Templates for network protocols such as FTP never run against a web service. Two short extra passes run one browser-based check (DOM-based cross-site scripting) and the subdomain-takeover templates.

Every call has its own time budget, 30 minutes at most, enforced by the tool runner. Whatever a call printed before its budget ended is kept, and the check is marked **partial**, never clean. **Thorough** [scan depth](guides/tune-a-scan.md) runs every template on every web service instead. Exact flags: [catalog §2.6](../security/tool-catalog.md#26-nuclei--template-based-vulnerabilityexposure-scan-two-passes).

### ffuf: content discovery

Requests a curated list of likely paths (admin panels, backup files, forgotten API routes) to find pages that exist but are not linked from anywhere: the automated version of a tester trying `/admin` and `/backup.zip`. Every scan runs a short baseline list on each web service. **Thorough** scan depth adds a large list, about 30,000 paths per web service and about 25 minutes each, as a planned check with its own time budget; if a slow target or a bug-bounty rate limit cuts it short it is shown as partial. The Vector Agent is shown what the scan already ran and uses its own ffuf call only for targeted paths, a few reasoned guesses or small lists, and is told plainly when a call was cut short by its time limit. ffuf is rate-limited and sends only read requests. It filters out "catch-all" pages that would otherwise look like a hit for every word tried. Exact flags: [catalog §3.3](../security/tool-catalog.md#33-content_discovery-ffuf--curated-directoryendpoint-brute-force).

## Optional discovery extras

These are the four switches under **Discovery extras**, on the wizard's advanced options and on the Edit page. Each one only ever narrows what your scope and tool grants already allow. See [Tune a scan](guides/tune-a-scan.md).

### katana: crawler (Crawling and URL history)

Follows links on an in-scope website to find pages and API endpoints that the front page does not list. It is shallow (two levels), capped in time and page count, sent through the egress proxy under the engagement's rate limit, one host at a time. URLs outside your scope are never stored or requested. It is a fixed step of the scan and is not offered to the Vector Agent. Off by default.

### URL history: web archives

With crawling on, Axial also asks the Wayback Machine and CommonCrawl which URLs of your in-scope domains existed in the past. Old URLs often still work and are forgotten: old admin pages, test endpoints. Only the URL list is read from the archives; **nothing is fetched from your systems at this point**, and every URL is filtered by your scope first. Capped at 1,500 URLs per source.

### nuclei on crawled endpoints, and the out-of-band pass

With crawling on, nuclei additionally tests the crawled and archived URLs that have query parameters (up to 50 per run) with its injection-style templates, non-destructive checks only. With **Out-of-band testing** on, a further pass runs nuclei's blind-vulnerability templates: they ask the target to contact a server, and the finding is confirmed when that server sees the contact. The server is the platform's own interaction server, never a public one; the runner may reach only that server, on one port, and each interaction is tied to one scan and logged. If the server is not set up, the pass is recorded as *unavailable* instead of running.

### screenshot: one picture per page (Web screenshots)

Loads each in-scope web page once in a headless browser and stores a screenshot, so you can spot admin panels, default pages and forgotten apps at a glance. It makes one page load per service, no clicking and no typing, with a hard time limit, always through the egress proxy. Screenshots are shown on the **Assets** tab and are not part of the PDF report, because a page can contain personal data. Not available for bug-bounty engagements that require an identification header on every request. Off by default.

## Only when the Vector Agent asks

### http_request: one targeted request

The agent's own hands: a single, precisely crafted request with the method, path and headers it decides are worth trying, the kind of targeted check a human tester would type by hand rather than a canned template. It is used for things no template anticipates: trying an access-control bypass header, checking whether a login form has anti-forgery protection, following up on something odd another tool noticed. Read-only requests (GET, HEAD, OPTIONS) run on their own. **Anything that could change data on the target** (POST, PUT, DELETE, PATCH, or any request with a body) always pauses for your explicit approval first, with the agent's stated reason and risk assessment shown to you before it runs. It is always exactly one request, and the response is capped at the first 16 KB. Exact flags: [catalog §3.2](../security/tool-catalog.md#32-http_request--agent-crafted-raw-http-readwrite).

### redis-probe and activemq-banner: is the service reachable

`redis-probe` sends the single word `PING` to a port that nmap identified as Redis and checks for the standard reply. It confirms whether an exposed Redis is reachable and answers without any authentication, a real and common misconfiguration. It sends nothing else, and never anything the agent composes. `activemq-banner` only listens: it connects to a port nmap flagged as ActiveMQ and reads the greeting the broker sends on its own. It sends nothing at all. Both are curated, bounded probes.

### activemq-openwire-probe: proof of one specific flaw

A specialised check for one serious, well-known ActiveMQ vulnerability (CVE-2023-46604), which lets an attacker run commands on the server without a login. A scanner can usually only guess from a version number; this tool triggers the vulnerable code path with a fixed, pre-built message (never composed by the agent) and waits briefly to see whether the target then tries to fetch a one-time web address unique to that single check. If it does, that is direct proof the flaw is real. Because it genuinely exercises the vulnerability, it is **never run automatically**: every single use requires your explicit, one-time approval, with the agent's reasoning and risk shown first. If no callback is seen, nothing is reported as a finding; an absence of proof is deliberately never treated as evidence either way.

### nikto: classic web server check

Still installed, and the Vector Agent can still ask for it, but it is no longer part of the automatic scan.

## Tools that exist but are off by default

`amass`, `whatweb`, `sslscan` and `default-cred-check` are in the tool list but switched off by default, and a tool that is not installed can never be turned on. The status of every tool, and why one cannot run on your engagement, is shown under **Campaign tool overrides** on the Edit page.
