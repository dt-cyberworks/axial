"""REQ-REPORT-001/002/003/005: the generated customer report.

Runs against a real Postgres because the report reads across engagement, scope
asset, finding, observation, service, DNS, and scan-run state - a mocked
session would prove nothing about the document an operator actually gets.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import re
import uuid

import pytest
from fastapi import HTTPException
from pypdf import PdfReader

from app.api.findings import download_report, list_reports, request_report
from app.api.internal import internal_request_report
from app.models.asset import DiscoveredAsset, Service
from app.models.audit import AuditLog
from app.models.dns_record import DnsRecord
from app.models.engagement import Engagement, ScopeAsset
from app.models.finding import Finding, FindingObservation
from app.models.report import Report
from app.models.scan_run import ScanRun

BEARER = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.s3cr3tS1gnatureV4lue"
COOKIE = "PHPSESSID=9c8b7a6d5e4f3a2b1c0d9e8f7a6b5c4d"
API_KEY = "sk-live-7f3a9c2e5b8d1f4a6c0e2b7d9f1a3c5e"
PASSWORD = "Hunter2!SuperSecret"


def _engagement(db, **overrides) -> Engagement:
    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(
        title=overrides.pop("title", "Report Test Engagement"), source="own_domain", status="active",
        authorized_from=now - dt.timedelta(days=1), authorized_until=now + dt.timedelta(days=1),
        tcp_port_from=1, tcp_port_to=65535, ai_testing_allowed=True,
        emergency_contact="ops@example.test", scope_doc_sha256="a" * 64,
        **overrides,
    )
    db.add(eng)
    db.commit()
    db.refresh(eng)
    return eng


def _scope(db, eng, rule, value, **kw):
    asset = ScopeAsset(
        engagement_id=eng.id, rule=rule, asset_type="domain", value=value,
        active_allowed=kw.pop("active_allowed", True),
        authorization_verified=kw.pop("authorization_verified", True), **kw,
    )
    db.add(asset)
    db.commit()
    return asset


def _run(db, eng, *, state="done", started=None, state_reason=None) -> ScanRun:
    run = ScanRun(
        engagement_id=eng.id, phase="report", state=state,
        started_at=started or dt.datetime.now(dt.timezone.utc),
        state_reason=state_reason,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def _finding(db, eng, *, title, severity="high", asset=None, evidence=None, fingerprint=None, **kw):
    finding = Finding(
        engagement_id=eng.id, category=kw.pop("category", "misconfig"), title=title,
        confidence=kw.pop("confidence", "validated"), status=kw.pop("status", "open"), severity=severity,
        risk_score=kw.pop("risk_score", 70), evidence=evidence,
        asset_id=asset.id if asset else None,
        fingerprint=fingerprint or f"fp-{uuid.uuid4().hex[:12]}", **kw,
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


def _pdf_pages(content: bytes) -> list[str]:
    """The text of each page, via a real PDF text-extraction library.

    The reportlab renderer draws text through `Tj`/`TJ` operators inside
    Paragraph/Table flowables - a different, richer content-stream shape than
    the old `simple_pdf` writer's one-`Tj`-per-line convention, so a
    format-specific regex can no longer be trusted to find everything drawn
    into the document (REQ-REPORT-005's re-verification of the R3 gate
    depends on that not happening quietly).
    """
    reader = PdfReader(io.BytesIO(content))
    return [page.extract_text() or "" for page in reader.pages]


def _pdf_text(content: bytes) -> str:
    return "\n".join(_pdf_pages(content))


def _has_phrase(text: str, phrase: str) -> bool:
    """Substring match tolerant of a paragraph wrap landing inside `phrase`.

    Reportlab wraps prose at word boundaries and the resulting line break is
    a bare newline, not a space - a plain `phrase in text` check on multi-word
    prose can spuriously fail (or, worse, be trimmed to a short-enough phrase
    that it spuriously passes) depending on exactly where a paragraph wrapped.
    """
    pattern = re.escape(phrase).replace(r"\ ", r"\s+")
    return re.search(pattern, text) is not None


def _severity_count_shown(text: str, severity: str, count: int) -> bool:
    return re.search(rf"{severity.upper()}\s+{count}\b", text) is not None


class _Caller:
    """Stands in for the authenticated `user` dependency."""
    def __init__(self, email="operator@example.test"):
        self.email = email


# --- REQ-REPORT-001: real PDF, specified structure ------------------------

def test_report_is_a_real_pdf_with_all_specified_sections(db):
    eng = _engagement(db)
    _scope(db, eng, "allow", "target.example")
    _scope(db, eng, "deny", "excluded.target.example")
    run = _run(db, eng)
    asset = DiscoveredAsset(
        engagement_id=eng.id, asset_type="domain", value="target.example",
        in_scope=True, discovered_via="seed",
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    db.add(Service(asset_id=asset.id, port=443, transport="tcp", product="nginx", version="1.24.0"))
    _finding(db, eng, title="Directory listing enabled", severity="medium", asset=asset)
    db.commit()

    result = request_report(eng.id, db, _Caller())

    assert result["status"] == "done"
    assert result["job_id"] == result["report_id"]
    report = db.get(Report, uuid.UUID(result["report_id"]))
    assert report.content[:5] == b"%PDF-"
    assert report.byte_size == len(report.content)
    assert report.sha256 == hashlib.sha256(bytes(report.content)).hexdigest()
    assert report.scan_run_id == run.id

    text = _pdf_text(bytes(report.content))
    for heading in (
        "1. Executive summary", "2. Risk overview", "3. Detailed findings",
        "4. Asset inventory", "5. Methodology & scope",
    ):
        assert heading in text, f"missing section: {heading}"


def test_methodology_section_documents_the_authorization_and_exclusions(db):
    eng = _engagement(db)
    _scope(db, eng, "allow", "target.example")
    _scope(db, eng, "deny", "secret.target.example")
    _run(db, eng)

    result = request_report(eng.id, db, _Caller())
    text = _pdf_text(bytes(db.get(Report, uuid.UUID(result["report_id"])).content))

    # ⚖ The mandatory section: window, authorization reference, scope, exclusions.
    assert "a" * 64 in text, "scope_doc_sha256 authorization reference must be present"
    assert "What was in scope (tested)" in text
    assert "target.example" in text
    assert "What was explicitly excluded (never tested)" in text
    assert "secret.target.example" in text
    assert str(eng.id) in text


def test_severity_counts_and_findings_reflect_open_findings(db):
    eng = _engagement(db)
    _scope(db, eng, "allow", "target.example")
    _run(db, eng)
    _finding(db, eng, title="Critical RCE candidate", severity="critical")
    _finding(db, eng, title="Weak TLS configuration", severity="medium")
    _finding(db, eng, title="Already fixed thing", severity="high", status="resolved")

    result = request_report(eng.id, db, _Caller())
    text = _pdf_text(bytes(db.get(Report, uuid.UUID(result["report_id"])).content))

    assert "Critical RCE candidate" in text
    assert "Weak TLS configuration" in text
    # status != open must not be counted or listed.
    assert "Already fixed thing" not in text
    assert _severity_count_shown(text, "critical", 1)
    assert _severity_count_shown(text, "medium", 1)
    assert _severity_count_shown(text, "high", 0)


def test_diff_section_reports_new_and_resolved_against_the_previous_run(db):
    eng = _engagement(db)
    _scope(db, eng, "allow", "target.example")
    now = dt.datetime.now(dt.timezone.utc)
    previous = _run(db, eng, started=now - dt.timedelta(hours=2))
    current = _run(db, eng, started=now)

    gone = _finding(db, eng, title="Old issue now gone", severity="low", fingerprint="fp-old")
    fresh = _finding(db, eng, title="Newly discovered issue", severity="high", fingerprint="fp-new")
    db.add(FindingObservation(scan_run_id=previous.id, fingerprint="fp-old", engagement_id=eng.id, finding_id=gone.id))
    db.add(FindingObservation(scan_run_id=current.id, fingerprint="fp-new", engagement_id=eng.id, finding_id=fresh.id))
    db.commit()

    result = request_report(eng.id, db, _Caller())
    text = _pdf_text(bytes(db.get(Report, uuid.UUID(result["report_id"])).content))

    assert _has_phrase(text, "NEW in this run: 1")
    assert "Newly discovered issue" in text
    assert _has_phrase(text, "NO LONGER OBSERVED in this run: 1")
    assert "Old issue now gone" in text


def test_shadow_it_hints_appear_in_the_asset_inventory(db):
    eng = _engagement(db)
    _scope(db, eng, "allow", "target.example")
    _run(db, eng)
    db.add(DnsRecord(
        engagement_id=eng.id, fqdn="files.target.example", cname_chain=[], terminal_ips=[],
        terminal_target="storage.saas.test", hosting_provider="SaaSCo",
        is_saas=True, dns_status="resolved",
    ))
    db.add(DnsRecord(
        engagement_id=eng.id, fqdn="dead.target.example", cname_chain=[], terminal_ips=[],
        terminal_target="gone.provider.test", dns_status="dangling", takeover_suspected=True,
    ))
    db.commit()

    result = request_report(eng.id, db, _Caller())
    text = _pdf_text(bytes(db.get(Report, uuid.UUID(result["report_id"])).content))

    assert "Third-party / shadow-IT hints" in text
    assert "files.target.example" in text and "SaaS" in text
    assert "possible subdomain takeover" in text


def test_degraded_coverage_is_called_out_so_a_short_list_is_not_read_as_clean(db):
    eng = _engagement(db)
    _scope(db, eng, "allow", "target.example")
    _run(db, eng, state_reason="coverage_degraded:nmap=runner_dispatch_failed")

    result = request_report(eng.id, db, _Caller())
    text = _pdf_text(bytes(db.get(Report, uuid.UUID(result["report_id"])).content))

    assert "reduced coverage" in text.lower()
    assert _has_phrase(text, "does NOT mean the")


def test_report_without_any_completed_run_still_generates(db):
    """An operator may ask for a report before ever scanning. That must produce
    an honest document, not a 500."""
    eng = _engagement(db)
    _scope(db, eng, "allow", "target.example")

    result = request_report(eng.id, db, _Caller())

    assert result["status"] == "done"
    text = _pdf_text(bytes(db.get(Report, uuid.UUID(result["report_id"])).content))
    assert "5. Methodology & scope" in text
    assert "No scan run has been executed" in text


# --- REQ-REPORT-001: listing, download, isolation, audit -------------------

def test_reports_are_listed_and_downloaded_byte_identical(db):
    eng = _engagement(db)
    _scope(db, eng, "allow", "target.example")
    _run(db, eng)

    created = request_report(eng.id, db, _Caller())
    listed = list_reports(eng.id, db)
    assert [r["report_id"] for r in listed] == [created["report_id"]]
    assert "content" not in listed[0]

    stored = bytes(db.get(Report, uuid.UUID(created["report_id"])).content)
    response = download_report(eng.id, uuid.UUID(created["report_id"]), db, _Caller())
    assert response.media_type == "application/pdf"
    assert response.body == stored


def test_a_report_from_another_engagement_is_not_readable(db):
    first = _engagement(db)
    second = _engagement(db, title="Someone else")
    _scope(db, first, "allow", "target.example")
    created = request_report(first.id, db, _Caller())

    with pytest.raises(HTTPException) as exc:
        download_report(second.id, uuid.UUID(created["report_id"]), db, _Caller())
    assert exc.value.status_code == 404


def test_generation_and_download_are_audited(db):
    eng = _engagement(db)
    _scope(db, eng, "allow", "target.example")
    created = request_report(eng.id, db, _Caller("alice@example.test"))
    download_report(eng.id, uuid.UUID(created["report_id"]), db, _Caller("alice@example.test"))

    actions = {row.action: row for row in db.query(AuditLog).filter(AuditLog.engagement_id == eng.id)}
    assert "report_generated" in actions
    assert actions["report_generated"].payload["sha256"] == created["sha256"]
    assert actions["report_generated"].actor == "user:alice@example.test"
    assert "report_downloaded" in actions


def test_unknown_engagement_is_a_404_not_a_crash(db):
    with pytest.raises(HTTPException) as exc:
        request_report(uuid.uuid4(), db, _Caller())
    assert exc.value.status_code == 404


# --- REQ-REPORT-002: the negative test that matters -----------------------

def test_negative_no_credential_from_evidence_or_lens_reaches_the_pdf(db):
    """The load-bearing R3 test: a finding carrying real-shaped secrets in its
    evidence AND a cached Lens explanation that repeats them in prose must
    produce a PDF containing none of those values."""
    eng = _engagement(db)
    _scope(db, eng, "allow", "target.example")
    _run(db, eng)
    _finding(
        db, eng, title="Authenticated endpoint exposed", severity="critical",
        evidence={
            "url": "https://target.example/admin",
            "status_code": 200,
            "authorization": f"Bearer {BEARER}",
            "cookie": COOKIE,
            "x-api-key": API_KEY,
            "password": PASSWORD,
            "raw_response": {"headers": {"set-cookie": COOKIE}, "body": PASSWORD},
            "lens_agent": {
                "explanation": (
                    "What it is: the endpoint accepted the request.\n"
                    f"Where it was found: we sent Authorization: Bearer {BEARER} "
                    f"together with Cookie: {COOKIE} and X-Api-Key: {API_KEY}, "
                    f"having logged in with password={PASSWORD}."
                ),
                "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "model": "test-model",
            },
        },
    )

    result = request_report(eng.id, db, _Caller())
    content = bytes(db.get(Report, uuid.UUID(result["report_id"])).content)
    text = _pdf_text(content)

    for secret in (BEARER, COOKIE, API_KEY, PASSWORD):
        assert secret not in text, f"credential leaked into report text: {secret}"
        assert secret.encode("latin-1") not in content, f"credential leaked into report bytes: {secret}"

    # The finding itself is still reported - redaction must not gut the content.
    assert "Authenticated endpoint exposed" in text
    assert "https://target.example/admin" in text


def test_raw_tool_output_is_not_reproduced_in_the_report(db):
    eng = _engagement(db)
    _scope(db, eng, "allow", "target.example")
    _finding(
        db, eng, title="Service banner", severity="info",
        evidence={"raw_stdout": {"lines": ["INTERNAL BUILD 9.9.9 do-not-publish"]}},
    )

    result = request_report(eng.id, db, _Caller())
    text = _pdf_text(bytes(db.get(Report, uuid.UUID(result["report_id"])).content))

    assert "do-not-publish" not in text
    assert "Service banner" in text


# --- REQ-REPORT-003: the pipeline's report phase --------------------------

def test_internal_route_generates_a_real_report_attributed_to_the_pipeline(db):
    eng = _engagement(db)
    _scope(db, eng, "allow", "target.example")
    run = _run(db, eng)

    result = internal_request_report(eng.id, scan_run_id=run.id, db=db)

    assert result["status"] == "done"
    report = db.get(Report, uuid.UUID(result["report_id"]))
    assert report.requested_by == "pipeline"
    assert report.scan_run_id == run.id
    assert report.content[:5] == b"%PDF-"


def test_internal_route_binds_the_report_to_the_run_it_was_given(db):
    """Not merely "the newest run": the phase reports on the run that just
    finished, which is what makes the diff section meaningful."""
    eng = _engagement(db)
    _scope(db, eng, "allow", "target.example")
    now = dt.datetime.now(dt.timezone.utc)
    older = _run(db, eng, started=now - dt.timedelta(hours=3))
    _run(db, eng, started=now)

    result = internal_request_report(eng.id, scan_run_id=older.id, db=db)

    assert db.get(Report, uuid.UUID(result["report_id"])).scan_run_id == older.id


# --- REQ-REPORT-005: professional formatting --------------------------------

def test_cover_page_and_confidential_page_footer_with_page_numbers(db):
    eng = _engagement(db, title="Cover Page Engagement")
    _scope(db, eng, "allow", "target.example")
    _run(db, eng)
    _finding(db, eng, title="Some finding", severity="high")

    result = request_report(eng.id, db, _Caller())
    pages = _pdf_pages(bytes(db.get(Report, uuid.UUID(result["report_id"])).content))
    assert len(pages) >= 2, "expected at least a cover page plus one content page"

    cover, content_pages = pages[0], pages[1:]
    assert "Cover Page Engagement" in cover
    assert "confidential" in cover.lower()
    # The cover page carries the notice prose, not the running footer marker.
    assert "CONFIDENTIAL" not in cover

    total = len(content_pages)
    for page_number, page_text in enumerate(content_pages, start=1):
        assert "CONFIDENTIAL" in page_text
        assert "Cover Page Engagement" in page_text
        assert re.search(rf"Page\s+{page_number}\s+of\s+{total}", page_text)


def test_findings_summary_table_precedes_the_detailed_findings(db):
    eng = _engagement(db)
    _scope(db, eng, "allow", "target.example")
    _run(db, eng)
    _finding(db, eng, title="Summarized finding", severity="high")

    result = request_report(eng.id, db, _Caller())
    text = _pdf_text(bytes(db.get(Report, uuid.UUID(result["report_id"])).content))

    assert "Findings summary" in text
    assert "Findings in detail" in text
    assert text.index("Findings summary") < text.index("Findings in detail")
    # The finding appears in both the summary table and the per-finding detail.
    assert text.count("Summarized finding") >= 2


def test_risk_rating_is_explained_in_plain_language(db):
    eng = _engagement(db)
    _scope(db, eng, "allow", "target.example")
    _run(db, eng)

    result = request_report(eng.id, db, _Caller())
    text = _pdf_text(bytes(db.get(Report, uuid.UUID(result["report_id"])).content))

    assert _has_phrase(text, "Severity reflects how much damage a finding could do")


def test_negative_credential_check_still_holds_against_the_reportlab_renderer(db):
    """Re-verifies REQ-REPORT-002 (TC-REPORT-002) against the REQ-REPORT-005
    renderer specifically: a redaction regression in the new layout code -
    e.g. a table cell built from a raw evidence dict instead of
    safe_evidence_items() - must still be caught."""
    eng = _engagement(db)
    _scope(db, eng, "allow", "target.example")
    _run(db, eng)
    _finding(
        db, eng, title="Formatting regression probe", severity="critical",
        evidence={
            "authorization": f"Bearer {BEARER}",
            "cookie": COOKIE,
            "x-api-key": API_KEY,
            "password": PASSWORD,
        },
    )

    result = request_report(eng.id, db, _Caller())
    content = bytes(db.get(Report, uuid.UUID(result["report_id"])).content)
    pages = _pdf_pages(content)
    text = "\n".join(pages)

    for secret in (BEARER, COOKIE, API_KEY, PASSWORD):
        assert secret not in text, f"credential leaked into report text: {secret}"
        assert secret.encode("latin-1") not in content, f"credential leaked into report bytes: {secret}"
    assert "Formatting regression probe" in text


# --- REQ-PIPE-011: the report states coverage ------------------------------

def _plan(db, eng, run, surfaces):
    """surfaces: [(host, port, class, profile, [(check_id, state, reason, detail)])]"""
    from app.models.scan_plan import ScanCheck, ScanSurface

    seq = 1
    for host, port, cls, profile, checks in surfaces:
        surface = ScanSurface(scan_run_id=run.id, engagement_id=eng.id, host=host, port=port, service_class=cls,
                              profile=profile, fingerprint={})
        db.add(surface)
        db.flush()
        for check_id, state, reason, detail in checks:
            db.add(ScanCheck(scan_run_id=run.id, engagement_id=eng.id, surface_id=surface.id, seq=seq, check_id=check_id,
                             tool=check_id.split(":")[0], state=state, reason=reason,
                             outcome_summary={"detail": detail} if detail else {}))
            seq += 1
    db.commit()


def _report_text(db, eng):
    result = request_report(eng.id, db, _Caller())
    return _pdf_text(bytes(db.get(Report, uuid.UUID(result["report_id"])).content))


def test_req_pipe_011_the_report_lists_each_service_and_how_completely_it_was_checked(db):
    eng = _engagement(db)
    _scope(db, eng, "allow", "target.example")
    run = _run(db, eng)
    run.scan_profile = "standard"
    db.commit()
    _plan(db, eng, run, [
        ("target.example", 443, "web", ["nginx", "php"], [
            ("wafw00f", "complete", "web", None), ("ffuf", "complete", "web", None),
            ("nuclei:generic:1of5", "partial", "generic_web", None), ("nuclei:products", "failed", "product:nginx", "nonzero_exit"),
            ("screenshot", "skipped", "switch_off", None),
        ]),
        ("target.example", 80, "web_alias", [], [("nuclei", "skipped", "web_alias_of:target.example:443", None)]),
        ("target.example", 25, "tls_service", [], [("testssl", "complete", "tls_service", None)]),
    ])
    text = _report_text(db, eng)
    assert "Coverage of this run" in text
    assert _has_phrase(text, "standard (checks chosen from what the scan found)")
    assert "target.example:443" in text and "nginx, php" in text
    assert _has_phrase(text, "Web (redirect only)") and _has_phrase(text, "TLS service")
    assert _has_phrase(text, "nuclei:generic:1of5: stopped at its time budget")
    assert _has_phrase(text, "nuclei:products: failed (nonzero exit)")
    assert _has_phrase(text, "only redirects to target.example:443, which is checked there")
    assert "screenshot: skipped" not in text, "a switched-off check is configuration, not a coverage gap"


def test_req_pipe_011_a_partial_or_failed_check_is_stated_in_the_executive_summary(db):
    eng = _engagement(db)
    _scope(db, eng, "allow", "target.example")
    run = _run(db, eng)
    _plan(db, eng, run, [("target.example", 443, "web", [], [
        ("nuclei:generic:1of5", "partial", "generic_web", None), ("ffuf", "partial", "web", None),
        ("nuclei:products", "failed", "x", "nonzero_exit"), ("wafw00f", "complete", "web", None)])])
    text = _report_text(db, eng)
    summary = text.split("2. Risk overview")[0]
    assert _has_phrase(summary, "2 check(s) stopped at their time budget and 1 failed during this run")
    assert _has_phrase(summary, "does NOT mean")


def test_negative_req_pipe_011_a_fully_covered_run_carries_no_warning(db):
    eng = _engagement(db)
    _scope(db, eng, "allow", "target.example")
    run = _run(db, eng)
    _plan(db, eng, run, [("target.example", 443, "web", ["nginx"], [
        ("wafw00f", "complete", "web", None), ("screenshot", "skipped", "switch_off", None)])])
    text = _report_text(db, eng)
    assert "Coverage of this run" in text
    assert "check(s) stopped at their time budget" not in text and "Not fully covered" not in text


def test_negative_req_pipe_011_a_run_without_a_plan_still_produces_a_report(db):
    eng = _engagement(db)
    _scope(db, eng, "allow", "target.example")
    _run(db, eng)
    text = _report_text(db, eng)
    assert "Methodology" in text and "Coverage of this run" not in text


def test_req_pipe_011_thorough_depth_is_named_in_the_coverage_section(db):
    eng = _engagement(db)
    _scope(db, eng, "allow", "target.example")
    run = _run(db, eng)
    run.scan_profile = "thorough"
    db.commit()
    _plan(db, eng, run, [("target.example", 443, "web", [], [("wafw00f", "complete", "web", None)])])
    assert _has_phrase(_report_text(db, eng), "thorough (every template on every web service)")


def test_req_pipe_011_the_plan_of_an_older_run_is_not_mixed_into_the_report_run(db):
    eng = _engagement(db)
    _scope(db, eng, "allow", "target.example")
    old = _run(db, eng, started=dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1))
    _plan(db, eng, old, [("old.example", 443, "web", [], [("ffuf", "failed", "web", "nonzero_exit")])])
    new = _run(db, eng)
    _plan(db, eng, new, [("target.example", 443, "web", [], [("ffuf", "complete", "web", None)])])
    text = _report_text(db, eng)
    assert "target.example:443" in text and "old.example" not in text
    assert "check(s) stopped at their time budget" not in text and "failed (nonzero exit)" not in text
