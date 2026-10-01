#!/usr/bin/env python3
"""Demo data for the user manual's screenshots (REQ-MANUAL-004).

Run inside a THROWAWAY control-plane container with an empty database (see
scripts/manual_screenshots.py); it is never run against a real installation. It
creates a small, believable installation with example data only: the hostnames are
example.com and its subdomains, the addresses are in the documentation range
203.0.113.0/24, the accounts are @example.com, and the findings are generic. The data
goes in through the real models and the real audit writer, so the screens render exactly
what they render in use and the audit chain verifies.

    docker exec -e MANUAL_DEMO_PASSWORD=... <container> python scripts/manual_demo_seed.py

Prints the demo accounts (with their one-time TOTP secrets) as JSON.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import mfa, passwords  # noqa: E402
from app.gateway.audit import append_audit_log  # noqa: E402
from app.graph.builder import materialize_graph  # noqa: E402
from app.models.approval import ApprovalRequest  # noqa: E402
from app.models.asset import DiscoveredAsset, Service  # noqa: E402
from app.models.discovery_artifacts import DiscoveredEndpoint  # noqa: E402
from app.models.dns_record import DnsRecord  # noqa: E402
from app.models.engagement import Engagement, ScopeAsset, ToolApprovalPolicy, ToolGrant  # noqa: E402
from app.models.finding import Finding, FindingObservation  # noqa: E402
from app.models.report import Report  # noqa: E402
from app.models.scan_plan import ScanCheck, ScanSurface  # noqa: E402
from app.models.scan_run import AgentStep, ScanRun  # noqa: E402
from app.models.user import User  # noqa: E402

DOMAIN = "example.com"
RETAIL = "retail.example.org"
SEVERITY_SCORE = {"critical": 94.0, "high": 78.0, "medium": 55.0, "low": 28.0, "info": 8.0}

ACCOUNTS = [
    ("demo.admin@example.com", "Demo Admin", "admin", "active"),
    ("demo.operator@example.com", "Demo Operator", "operator", "active"),
    ("sam.analyst@example.com", "Sam Analyst", "operator", "active"),
    ("alex.contractor@example.com", "Alex Contractor", "operator", "disabled"),
    ("new.colleague@example.com", "New Colleague", "operator", "invited"),
]

LENS = """What it is
The web server exposes its version control directory. Anyone can download the repository metadata and often the whole source code.

Where it was found
`https://shop.example.com/.git/config` answers with the repository configuration.

Why it matters
Source code usually contains secrets (keys, passwords, internal addresses) and shows an attacker exactly how the application works.

What to do
1. Block access to dot-directories in the web server configuration.
2. Remove the `.git` directory from the deployed files.
3. Assume any secret that was in the repository is exposed, and replace it.
"""


def _ts(now: dt.datetime, **delta) -> dt.datetime:
    return now - dt.timedelta(**delta)


def _fingerprint(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:40]


def _users(db, password: str, now: dt.datetime) -> tuple[dict, list[dict]]:
    users, accounts = {}, []
    for email, name, role, status in ACCOUNTS:
        secret = mfa.generate_secret() if status != "invited" else None
        user = User(
            email=email, display_name=name, role=role, status=status,
            password_hash=passwords.hash_secret(password), must_change_password=status == "invited",
            totp_secret_encrypted=mfa.encrypt_secret(secret) if secret else None,
            totp_confirmed_at=now if secret else None,
            last_login_at=_ts(now, hours=3) if status == "active" else None,
        )
        db.add(user)
        db.flush()
        users[email] = user
        accounts.append({"email": email, "role": role, "status": status, "password": password, "totp_secret": secret})
    db.commit()
    return users, accounts


def _engagement(db, owner: User, now: dt.datetime, **fields) -> Engagement:
    eng = Engagement(owner_user_id=owner.id, source="own_domain", **fields)
    db.add(eng)
    db.flush()
    return eng


def _scope(db, eng: Engagement, rows: list[tuple]) -> None:
    for rule, kind, value, active, attested in rows:
        db.add(ScopeAsset(
            engagement_id=eng.id, rule=rule, asset_type=kind, value=value, active_allowed=active,
            authorization_verified=attested,
            authorization_method="operator_authorization_attestation" if attested else None,
        ))


def _grants(db, eng: Engagement, rows: list[tuple]) -> None:
    for category, mode in rows:
        db.add(ToolGrant(engagement_id=eng.id, tool_category=category, mode=mode, requires_manual_approval=False))


def _finding(db, eng, asset, service, *, title, category, severity, confidence, evidence, status="open",
             note=None, by=None, cves=None, cvss=None, epss=None, kev=False, now, first_seen_days=8) -> Finding:
    finding = Finding(
        engagement_id=eng.id, asset_id=asset.id if asset else None, service_id=service.id if service else None,
        category=category, title=title, cve_ids=cves, cvss_base=cvss, epss=epss, confidence=confidence, status=status,
        status_note=note, status_changed_at=_ts(now, hours=5) if status != "open" else None,
        status_changed_by=by if status != "open" else None, evidence=evidence, is_kev=kev,
        severity=severity, risk_score=SEVERITY_SCORE[severity], first_seen=_ts(now, days=first_seen_days),
        fingerprint=_fingerprint(str(eng.id), title, asset.value if asset else ""),
    )
    db.add(finding)
    db.flush()
    return finding


def _audit(db, eng, run, *, actor, action, decision=None, reason=None, **payload) -> None:
    payload["scan_run_id"] = str(run.id)
    append_audit_log(db, engagement_id=eng.id, actor=actor, action=action, decision=decision, reason=reason, payload=payload)


def _call(db, eng, run, tool, category, mode, phase, target, *, services=None, command=None, ok=True,
          rationale=None, error=None):
    _audit(db, eng, run, actor="gateway", action="tool_call", decision="ALLOW", reason="all_checks_passed",
           tool=tool, category=category, mode=mode, phase=phase, target=target, args={}, path=None, risk=None,
           rationale=rationale, is_automated=phase != "agent", engagement_id=str(eng.id), target_is_range=False)
    _audit(db, eng, run, actor="worker", action="tool_execution", decision="ALLOW" if ok else "DENY",
           reason="completed" if ok else (error or "nonzero_exit"), tool=tool, phase=phase, command=command or tool,
           success=ok, exit_code=0 if ok else 1, authorized_target=target, resolved_target=None, port_range="1-65535",
           error_reason=None if ok else (error or "nonzero_exit"), discovered_services=services,
           outcome_summary={"outcome": "complete" if ok else "failed"})


def seed(db, *, password: str, now: dt.datetime | None = None) -> dict:
    now = now or dt.datetime.now(dt.timezone.utc)
    users, accounts = _users(db, password, now)
    operator = users["demo.operator@example.com"]

    # ------------------------------------------------------------------ engagements
    main = _engagement(
        db, operator, now, title="Example Corp: external attack surface", status="active",
        authorized_from=_ts(now, days=14), authorized_until=now + dt.timedelta(days=76),
        emergency_contact="Alex Morgan, +1 555 0100 (security on-call)", ai_testing_allowed=True,
        subfinder_enabled=True, crawling_enabled=True, scan_profile="standard",
    )
    _scope(db, main, [("allow", "domain", DOMAIN, True, True), ("deny", "domain", f"legacy.{DOMAIN}", False, False),
                      ("allow", "cidr", "203.0.113.0/28", True, True)])
    _grants(db, main, [("recon", "passive"), ("recon", "active"), ("fingerprint", "active"), ("vuln", "active")])
    db.add_all([
        ToolApprovalPolicy(engagement_id=main.id, tool_name="testssl", enabled=False, requires_manual_approval=False),
        ToolApprovalPolicy(engagement_id=main.id, tool_name="nmap", requires_manual_approval=True),
        ToolApprovalPolicy(engagement_id=main.id, tool_name="http_request", requires_manual_approval=True),
    ])
    draft = _engagement(
        db, operator, now, title="Example Corp: partner portal", status="draft",
        authorized_from=now, authorized_until=now + dt.timedelta(days=30), emergency_contact="Alex Morgan, +1 555 0100",
    )
    _scope(db, draft, [("allow", "domain", f"partners.{DOMAIN}", True, False)])
    retail = _engagement(
        db, operator, now, title="Example Retail: annual review", status="active",
        authorized_from=_ts(now, days=3), authorized_until=now + dt.timedelta(days=27),
        emergency_contact="Jo Rivera, +1 555 0111", scan_profile="standard",
    )
    _scope(db, retail, [("allow", "domain", RETAIL, True, True)])
    _grants(db, retail, [("fingerprint", "active"), ("vuln", "active")])
    db.add(ToolApprovalPolicy(engagement_id=retail.id, tool_name="http_request", requires_manual_approval=True))
    for eng in (main, retail):
        append_audit_log(db, engagement_id=eng.id, actor=f"user:{operator.email}", action="engagement_created",
                         decision="ALLOW", reason=None, payload={"title": eng.title})
        append_audit_log(db, engagement_id=eng.id, actor=f"user:{operator.email}", action="engagement_activated",
                         decision="ALLOW", reason=None, payload={})
    db.commit()

    # ------------------------------------------------------------------ assets, services, DNS
    assets: dict[str, DiscoveredAsset] = {}
    for host, via in [(DOMAIN, "scope"), (f"www.{DOMAIN}", "passive-osint"), (f"api.{DOMAIN}", "passive-osint"),
                      (f"shop.{DOMAIN}", "passive-osint"), (f"mail.{DOMAIN}", "passive-osint"),
                      (f"admin.{DOMAIN}", "passive-osint"), (f"old-blog.{DOMAIN}", "passive-osint")]:
        assets[host] = DiscoveredAsset(engagement_id=main.id, asset_type="domain", value=host, in_scope=True,
                                       discovered_via=via, first_seen=_ts(now, days=8), last_seen=_ts(now, days=1))
    assets["203.0.113.5"] = DiscoveredAsset(engagement_id=main.id, asset_type="ip", value="203.0.113.5", in_scope=True,
                                            discovered_via="cidr-sweep", first_seen=_ts(now, days=8), last_seen=_ts(now, days=1))
    db.add_all(assets.values())
    db.flush()
    services = {
        "www": Service(asset_id=assets[f"www.{DOMAIN}"].id, port=443, protocol="https", transport="tcp", product="nginx",
                       version="1.24.0", tech_stack={"technologies": ["nginx", "WordPress", "PHP"]}),
        "api": Service(asset_id=assets[f"api.{DOMAIN}"].id, port=443, protocol="https", transport="tcp",
                       product="Apache httpd", version="2.4.49", tech_stack={"technologies": ["Apache HTTP Server"]}),
        "shop": Service(asset_id=assets[f"shop.{DOMAIN}"].id, port=443, protocol="https", transport="tcp", product="nginx",
                        version="1.18.0"),
        "mail": Service(asset_id=assets[f"mail.{DOMAIN}"].id, port=25, protocol="smtp", transport="tcp", product="Postfix"),
        "ssh": Service(asset_id=assets["203.0.113.5"].id, port=22, protocol="ssh", transport="tcp", product="OpenSSH", version="7.4"),
        "redis": Service(asset_id=assets["203.0.113.5"].id, port=6379, protocol="redis", transport="tcp", product="Redis",
                         version="6.2.6"),
    }
    db.add_all(services.values())
    for fqdn, chain, terminal, ips, provider, flags in [
        (f"www.{DOMAIN}", [f"cdn.{DOMAIN}.example-cdn.net"], f"cdn.{DOMAIN}.example-cdn.net", ["203.0.113.8"], "Example CDN", {"is_cdn": True}),
        (f"shop.{DOMAIN}", ["shops.example-saas.net"], "shops.example-saas.net", ["203.0.113.9"], "Example SaaS", {"is_saas": True}),
        (f"api.{DOMAIN}", [], f"api.{DOMAIN}", ["203.0.113.4"], None, {}),
        (f"mail.{DOMAIN}", [], f"mail.{DOMAIN}", ["203.0.113.6"], None, {}),
        (f"old-blog.{DOMAIN}", ["gone.example-hosting.net"], "gone.example-hosting.net", [], "Example Hosting", {"takeover_suspected": True}),
    ]:
        db.add(DnsRecord(engagement_id=main.id, asset_id=assets[fqdn].id, fqdn=fqdn, cname_chain=chain, terminal_target=terminal,
                         terminal_ips=ips, hosting_provider=provider, dns_status="nxdomain" if flags.get("takeover_suspected") else "resolved",
                         resolved_at=_ts(now, days=1), **flags))
    for url, host, source, params in [
        (f"https://www.{DOMAIN}/search?q=&page=1", f"www.{DOMAIN}", "katana", ["q", "page"]),
        (f"https://www.{DOMAIN}/blog/archive?year=2021", f"www.{DOMAIN}", "wayback", ["year"]),
        (f"https://api.{DOMAIN}/v1/items?id=1&format=json", f"api.{DOMAIN}", "katana", ["id", "format"]),
        (f"https://shop.{DOMAIN}/cart?item=42", f"shop.{DOMAIN}", "katana", ["item"]),
        (f"https://admin.{DOMAIN}/login?next=%2F", f"admin.{DOMAIN}", "commoncrawl", ["next"]),
    ]:
        db.add(DiscoveredEndpoint(engagement_id=main.id, url=url, host=host, port=443, method="GET", source=source,
                                  param_names=params, first_seen_at=_ts(now, days=1)))
    db.commit()

    # ------------------------------------------------------------------ runs
    def run(eng, *, started, finished, state, phase, used, reason=None, **extra) -> ScanRun:
        item = ScanRun(engagement_id=eng.id, started_at=started, finished_at=finished, heartbeat_at=finished or now,
                       phase=phase, state=state, budget_tool_calls_used=used, state_reason=reason, attempt=1,
                       scan_profile="standard", **extra)
        db.add(item)
        db.flush()
        return item

    run1 = run(main, started=_ts(now, days=8), finished=_ts(now, days=8) + dt.timedelta(minutes=14), state="done",
               phase="report", used=88)
    run2 = run(main, started=_ts(now, days=1), finished=_ts(now, days=1) + dt.timedelta(minutes=13), state="done",
               phase="report", used=94, reason="coverage_partial:nuclei=1")
    run3 = run(retail, started=_ts(now, minutes=6), finished=None, state="running", phase="fingerprint", used=31,
               current_tool="nuclei", current_target=RETAIL, current_started_at=_ts(now, seconds=95))

    # ------------------------------------------------------------------ findings and what each run saw
    def web(host):
        return assets[f"{host}.{DOMAIN}"]

    specs = [
        ("Exposed .git directory discloses source code", "exposure", "critical", "validated", web("shop"), services["shop"],
         {"tool": "nuclei", "template_id": "git-config", "matched_at": f"https://shop.{DOMAIN}/.git/config",
          "lens_agent": {"explanation": LENS, "model": "demo-model", "generated_at": now.isoformat(), "truncated": False}}, {}),
        ("Apache HTTP Server 2.4.49 path traversal (CVE-2021-41773)", "cve", "critical", "validated", web("api"), services["api"],
         {"tool": "nuclei", "template_id": "CVE-2021-41773", "matched_at": f"https://api.{DOMAIN}/cgi-bin/"},
         {"cves": ["CVE-2021-41773"], "cvss": 7.5, "epss": 0.9437, "kev": True}),
        ("Redis is reachable without authentication", "exposure", "high", "validated", assets["203.0.113.5"], services["redis"],
         {"tool": "redis-probe", "matched_at": "203.0.113.5:6379", "reply": "+PONG"}, {}),
        ("Subdomain takeover possible: old-blog", "misconfig", "high", "inferred", web("old-blog"), None,
         {"tool": "dns", "matched_at": f"old-blog.{DOMAIN}", "cname": "gone.example-hosting.net", "dns_status": "nxdomain"}, {}),
        ("Expired TLS certificate", "misconfig", "high", "validated", web("mail"), services["mail"],
         {"tool": "testssl", "matched_at": f"mail.{DOMAIN}:25", "detail": "certificate expired 12 days ago"}, {}),
        ("Outdated OpenSSH 7.4 (user enumeration, CVE-2018-15473)", "cve", "medium", "inferred", assets["203.0.113.5"], services["ssh"],
         {"tool": "nmap", "matched_at": "203.0.113.5:22", "banner": "SSH-2.0-OpenSSH_7.4"},
         {"cves": ["CVE-2018-15473"], "cvss": 5.3, "epss": 0.0721}),
        ("Directory listing enabled on /backup/", "exposure", "medium", "validated", web("www"), services["www"],
         {"tool": "ffuf", "matched_at": f"https://www.{DOMAIN}/backup/", "status": 200}, {}),
        ("TLS 1.0 is still offered", "misconfig", "medium", "validated", web("mail"), services["mail"],
         {"tool": "testssl", "matched_at": f"mail.{DOMAIN}:25", "detail": "TLS 1.0 offered"}, {}),
        ("Admin login page is exposed", "exposure", "medium", "validated", web("admin"), None,
         {"tool": "nuclei", "template_id": "admin-panel-detect", "matched_at": f"https://admin.{DOMAIN}/login"}, {}),
        ("Missing security headers", "misconfig", "low", "validated", web("www"), services["www"],
         {"tool": "httpx", "matched_at": f"https://www.{DOMAIN}/",
          "missing_headers": ["Strict-Transport-Security", "Content-Security-Policy"]}, {}),
        ("Server version disclosed in a response header", "misconfig", "low", "validated", web("shop"), services["shop"],
         {"tool": "httpx", "matched_at": f"https://shop.{DOMAIN}/", "header": "Server: nginx/1.18.0"}, {}),
        ("WordPress 6.2 detected", "exposure", "info", "validated", web("www"), services["www"],
         {"tool": "httpx", "matched_at": f"https://www.{DOMAIN}/", "technology": "WordPress 6.2"}, {}),
    ]
    statuses = {"Server version disclosed in a response header": ("accepted_risk", "Fixed by the next planned proxy upgrade; no sensitive data exposed.", operator.email),
                "Expired TLS certificate": ("resolved", "Certificate renewed and deployed.", operator.email),
                "WordPress 6.2 detected": ("false_positive", "A marketing microsite, not our WordPress.", operator.email)}
    made = {}
    for title, category, severity, confidence, asset, service, evidence, extra in specs:
        status, note, by = statuses.get(title, ("open", None, None))
        made[title] = _finding(db, main, asset, service, title=title, category=category, severity=severity,
                               confidence=confidence, evidence=evidence, status=status, note=note, by=by, now=now,
                               cves=extra.get("cves"), cvss=extra.get("cvss"), epss=extra.get("epss"), kev=extra.get("kev", False))
    new_in_run2 = {"Redis is reachable without authentication", "Directory listing enabled on /backup/"}
    gone_in_run2 = {"Expired TLS certificate"}
    for title, finding in made.items():
        if title not in new_in_run2:
            db.add(FindingObservation(scan_run_id=run1.id, fingerprint=finding.fingerprint, engagement_id=main.id,
                                      finding_id=finding.id, observed_at=_ts(now, days=8)))
        if title not in gone_in_run2:
            db.add(FindingObservation(scan_run_id=run2.id, fingerprint=finding.fingerprint, engagement_id=main.id,
                                      finding_id=finding.id, observed_at=_ts(now, days=1)))
    retail_asset = DiscoveredAsset(engagement_id=retail.id, asset_type="domain", value=RETAIL, in_scope=True,
                                   discovered_via="scope")
    db.add(retail_asset)
    db.flush()
    for title, severity, evidence in [
        ("Missing security headers", "low", {"tool": "httpx", "matched_at": f"https://{RETAIL}/", "missing_headers": ["Content-Security-Policy"]}),
        ("Directory listing enabled on /uploads/", "medium", {"tool": "ffuf", "matched_at": f"https://{RETAIL}/uploads/", "status": 200}),
    ]:
        f = _finding(db, retail, retail_asset, None, title=title, category="misconfig", severity=severity,
                     confidence="validated", evidence=evidence, now=now, first_seen_days=0)
        db.add(FindingObservation(scan_run_id=run3.id, fingerprint=f.fingerprint, engagement_id=retail.id,
                                  finding_id=f.id, observed_at=_ts(now, minutes=3)))
    db.commit()

    # ------------------------------------------------------------------ the plan of the latest run
    def surface(host, port, cls, *, scheme=None, alias_of=None, profile=None, ip=None):
        item = ScanSurface(scan_run_id=run2.id, engagement_id=main.id, asset_id=assets[host].id if host in assets else None,
                           host=host, ip=ip, port=port, scheme=scheme, service_class=cls, alias_of=alias_of,
                           profile=profile or [], fingerprint={"protocol": scheme} if scheme else {})
        db.add(item)
        db.flush()
        return item

    seq = [0]

    def check(surf, check_id, tool, state, reason, *, seconds=None, templates=None, findings=0, detail=None, budget=None):
        seq[0] += 1
        summary = {}
        if templates is not None:
            summary["templates"] = templates
        if detail:
            summary["detail"] = detail
        db.add(ScanCheck(scan_run_id=run2.id, engagement_id=main.id, surface_id=surf.id, seq=seq[0], check_id=check_id,
                         tool=tool, args={}, state=state, reason=reason, budget_s=budget, attempt=1 if state != "skipped" else 0,
                         started_at=_ts(now, days=1), finished_at=_ts(now, days=1) + dt.timedelta(seconds=seconds or 0),
                         duration_s=seconds, findings=findings, outcome_summary=summary))

    www = surface(f"www.{DOMAIN}", 443, "web", scheme="https", profile=["nginx", "wordpress", "php"])
    for cid, tool, state, reason, kw in [
        ("wafw00f", "wafw00f", "complete", "web", {"seconds": 6}),
        ("testssl", "testssl", "skipped", "tool_disabled", {}),
        ("header_findings", "httpx", "complete", "web", {"seconds": 1, "findings": 1}),
        ("ffuf", "ffuf", "complete", "web", {"seconds": 74, "findings": 1}),
        ("katana", "katana", "complete", "switch_on", {"seconds": 38}),
        ("screenshot", "screenshot", "skipped", "switch_off", {}),
        ("nuclei:generic:1of5", "nuclei", "complete", "generic_web", {"seconds": 214, "templates": 396}),
        ("nuclei:generic:2of5", "nuclei", "complete", "generic_web", {"seconds": 231, "templates": 396}),
        ("nuclei:generic:3of5", "nuclei", "partial", "generic_web", {"seconds": 1288, "templates": 396, "budget": 1288, "detail": "budget_reached"}),
        ("nuclei:product:wordpress", "nuclei", "complete", "product:wordpress", {"seconds": 96, "templates": 214}),
        ("nuclei:crawled", "nuclei", "complete", "crawled_endpoints", {"seconds": 41, "templates": 58}),
    ]:
        check(www, cid, tool, state, reason, **kw)
    alias = surface(f"www.{DOMAIN}", 80, "web_alias", scheme="http", alias_of=f"www.{DOMAIN}:443")
    check(alias, "wafw00f", "wafw00f", "skipped", f"web_alias_of:www.{DOMAIN}:443")
    api = surface(f"api.{DOMAIN}", 443, "web", scheme="https", profile=["apache"])
    for cid, tool, state, reason, kw in [
        ("wafw00f", "wafw00f", "complete", "web", {"seconds": 5}),
        ("testssl", "testssl", "skipped", "tool_disabled", {}),
        ("ffuf", "ffuf", "complete", "web", {"seconds": 69}),
        ("nuclei:generic:1of5", "nuclei", "complete", "generic_web", {"seconds": 207, "templates": 396, "findings": 1}),
        ("nuclei:product:apache", "nuclei", "complete", "product:apache", {"seconds": 88, "templates": 171}),
    ]:
        check(api, cid, tool, state, reason, **kw)
    mail = surface(f"mail.{DOMAIN}", 25, "tls_service", profile=["postfix"])
    check(mail, "testssl", "testssl", "skipped", "tool_disabled")
    surface("203.0.113.5", 22, "service", profile=["openssh"], ip="203.0.113.5")
    surface("203.0.113.5", 6379, "service", profile=["redis"], ip="203.0.113.5")
    db.commit()

    # ------------------------------------------------------------------ audit trail of the latest run
    for phase, state in [("discovery", "running"), ("fingerprint", "running"), ("correlate", "running"),
                         ("agent", "running"), ("score", "running"), ("report", "done")]:
        _audit(db, main, run2, actor="worker", action="scan_run_transition", phase=phase, state=state)
        if phase == "discovery":
            _audit(db, main, run2, actor="control-plane", action="dns_materialization",
                   resolved=[{"hostname": f"www.{DOMAIN}", "ip_address": "203.0.113.8"}], denied_ips=[], unresolved=[])
            _call(db, main, run2, "subfinder", "recon", "passive", "discovery", DOMAIN, services=None)
    for tool, category, target, services in [("nmap", "fingerprint", f"www.{DOMAIN}", 2), ("httpx", "fingerprint", f"www.{DOMAIN}", 1),
                                              ("wafw00f", "fingerprint", f"www.{DOMAIN}", None), ("ffuf", "vuln", f"www.{DOMAIN}", None),
                                              ("nuclei", "vuln", f"api.{DOMAIN}", None)]:
        _call(db, main, run2, tool, category, "active", "fingerprint", target, services=services)
    _call(db, main, run2, "testssl", "fingerprint", "active", "fingerprint", f"mail.{DOMAIN}", ok=False, error="tool_disabled")
    _audit(db, main, run2, actor="agent", action="agent_event", decision="ALLOW", reason="agent_phase_started",
           event="started", budget_max_iterations=50)
    _audit(db, main, run2, actor="agent", action="agent_event", reason="llm_proposed_tool", event="proposal",
           proposal={"tool": "redis-probe", "target": "203.0.113.5", "rationale": "nmap found Redis on 6379; check whether it answers without authentication."})
    _call(db, main, run2, "redis-probe", "fingerprint", "active", "agent", "203.0.113.5", services=1,
          rationale="nmap found Redis on 6379; check whether it answers without authentication.")
    _audit(db, main, run2, actor="agent", action="agent_event", decision="ALLOW", reason="tool_observed", event="observation",
           findings=1, services=0, proposal={"tool": "redis-probe", "target": "203.0.113.5"},
           observation="[redis-probe 203.0.113.5] +PONG: Redis answers without authentication.")
    _audit(db, main, run2, actor="agent", action="agent_event", decision="ALLOW", reason="agent_phase_finished", event="finished",
           denied=0, exhausted=False, conclusion="The surface was reviewed; one exposed Redis was confirmed.")

    # ------------------------------------------------------------------ agent steps of the latest run
    first_user = "Scope: example.com. Discovered: www, api, shop, mail, admin, 203.0.113.5. Findings so far: 11."
    first_reply = "nmap found Redis on 203.0.113.5:6379. I will check whether it requires authentication."
    system = "You are the Vector Agent of an authorized attack-surface scan. You only propose; the Scope Gateway decides."
    for iteration, (user, reply, calls) in enumerate([
        ("Scope: example.com. Discovered: www, api, shop, mail, admin, 203.0.113.5. Findings so far: 11.",
         "nmap found Redis on 203.0.113.5:6379. I will check whether it requires authentication.",
         [{"name": "run_check", "arguments": json.dumps({"tool": "redis-probe", "target": "203.0.113.5",
                                                        "rationale": "Is Redis reachable without authentication?"})}]),
        ("[redis-probe 203.0.113.5] +PONG", "Redis answers without authentication; I will report it and finish.",
         [{"name": "report_finding", "arguments": json.dumps({"title": "Redis is reachable without authentication",
                                                              "severity": "high", "evidence_basis": "validated"})},
          {"name": "finish", "arguments": json.dumps({"summary": "One exposed Redis was confirmed."})}]),
    ], start=1):
        history = [{"role": "system", "content": system}, {"role": "user", "content": first_user}]
        if iteration == 2:
            history += [{"role": "assistant", "content": first_reply}, {"role": "tool", "content": user}]
        else:
            history[1]["content"] = user
        db.add(AgentStep(engagement_id=main.id, scan_run_id=run2.id, iteration=iteration,
                         request_messages=history, response_text=reply, response_tool_calls=calls,
                         stop_reason="tool_calls", created_at=_ts(now, days=1) + dt.timedelta(minutes=9 + iteration)))
    db.add(Report(engagement_id=main.id, scan_run_id=run2.id, status="done", requested_by=operator.email,
                  filename="example-corp-report.pdf", byte_size=184_320, created_at=_ts(now, hours=20)))

    db.commit()
    materialize_graph(main.id, db)
    return {"accounts": accounts, "engagements": {"main": str(main.id), "draft": str(draft.id), "retail": str(retail.id)},
            "runs": {"main_latest": str(run2.id), "main_first": str(run1.id), "retail_running": str(run3.id)}}


def add_pending_approval(db, *, engagement_id: uuid.UUID, scan_run_id: uuid.UUID, now: dt.datetime | None = None) -> uuid.UUID:
    """One state-changing request waiting for a decision. Kept apart from seed(): the
    console shows this popup on every page until it is decided, so the screenshots
    that are not about it must be taken without it."""
    now = now or dt.datetime.now(dt.timezone.utc)
    request = ApprovalRequest(engagement_id=engagement_id, state="requested", expires_at=now + dt.timedelta(minutes=14), tool_call={
        "tool": "http_request", "target": RETAIL, "category": "vuln", "mode": "active", "scan_run_id": str(scan_run_id),
        "args": {"method": "POST", "path": "/contact", "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                 "body": "name=test&message=hello"},
        "rationale": "Check whether the contact form is protected by an anti-forgery token before accepting a submission.",
        "risk": {"level": "medium", "description": "Submits one contact-form entry; the site owner may receive a message."},
    })
    db.add(request)
    db.commit()
    return request.id


def main() -> int:
    import argparse

    from app.db.base import SessionLocal

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--pending-approval", nargs=2, metavar=("ENGAGEMENT_ID", "RUN_ID"),
                        help="only add one request waiting for approval to an already seeded installation")
    args = parser.parse_args()
    with SessionLocal() as db:
        if args.pending_approval:
            engagement_id, run_id = (uuid.UUID(value) for value in args.pending_approval)
            print(json.dumps({"approval": str(add_pending_approval(db, engagement_id=engagement_id, scan_run_id=run_id))}))
            return 0
        password = os.environ.get("MANUAL_DEMO_PASSWORD", "").strip()
        if len(password) < 12:
            print("MANUAL_DEMO_PASSWORD (at least 12 characters) is required.", file=sys.stderr)
            return 1
        print(json.dumps(seed(db, password=password)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
