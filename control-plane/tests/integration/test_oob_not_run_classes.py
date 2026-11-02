"""REQ-OOB-001 (GitHub #76): a run without an interaction server names the template classes it could not run, in the
plan, the report and its summary - and says nothing when the passes ran or were not asked for.

Seen on int (2026-10-20): ten `oob_unavailable` skips read as "interaction server not deployed" and the run looked
complete. The passes that need the server are only the callback-dependent templates; this is what the owner is told."""

from __future__ import annotations

import datetime as dt
import io
import uuid

import pytest
from pypdf import PdfReader

from app import scan_plan
from app.models.engagement import Engagement, ScopeAsset
from app.models.scan_plan import ScanCheck, ScanSurface
from app.models.scan_run import ScanRun
from app.pdf_report import render_report_pdf
from app.report_builder import OOB_NOTE, build_report_model
from tests.integration.owners import make_owner

NOW = dt.datetime.now(dt.timezone.utc)
PARTS = ["generic_a", "generic_b", "generic_c", "cves_recent", "cves_legacy"]
BLIND = "Blind-vulnerability templates (blind injection, SSRF, XXE and similar)"
RECENT = "CVE templates 2023-2026 that confirm through a callback"
LEGACY = "CVE templates 2015-2022 that confirm through a callback"


def _engagement(db) -> Engagement:
    eng = Engagement(title="O", source="own_domain", status="active", owner_user_id=make_owner(db).id,
                     authorized_from=NOW - dt.timedelta(hours=1), authorized_until=NOW + dt.timedelta(days=1))
    db.add(eng)
    db.flush()
    db.add(ScopeAsset(engagement_id=eng.id, rule="allow", asset_type="domain", value="example.test",
                      active_allowed=True, authorization_verified=True))
    db.commit()
    return eng


def _run(db, eng) -> ScanRun:
    started = NOW - dt.timedelta(minutes=30)
    run = ScanRun(engagement_id=eng.id, phase="report", state="done", started_at=started,
                  finished_at=started + dt.timedelta(minutes=10), trigger="manual", scan_profile="standard")
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def _surface(db, eng, run, host, *, state="skipped", reason="oob_unavailable", parts=PARTS, port=443) -> ScanSurface:
    surface = ScanSurface(scan_run_id=run.id, engagement_id=eng.id, host=host, port=port, service_class="web")
    db.add(surface)
    db.flush()
    for seq, part in enumerate(parts, 1):
        db.add(ScanCheck(scan_run_id=run.id, engagement_id=eng.id, surface_id=surface.id, seq=seq, check_id=f"nuclei:oob:{part}", tool="nuclei",
                         state=state, reason=reason, args={"mode": "oob", "part": part}))
    db.commit()
    return surface


def test_each_pass_has_a_class_name_and_the_three_blind_passes_share_one():
    assert scan_plan.oob_class_of("nuclei:oob:generic_a") == BLIND == scan_plan.oob_class_of("nuclei:oob:generic_c")
    assert scan_plan.oob_class_of("nuclei:oob:cves_recent") == RECENT
    assert scan_plan.oob_class_of("nuclei:oob:cves_legacy") == LEGACY


@pytest.mark.parametrize("check_id", ["nuclei:oob:unknown", "nuclei:generic:1of5", "nuclei:products", "ffuf", "nuclei:oob:", "", None,
                                      "nuclei:all:generic_a", "other:oob:cves_recent"])
def test_negative_a_check_that_is_not_an_interaction_server_pass_has_no_class(check_id):
    assert scan_plan.oob_class_of(check_id) is None


def test_the_plan_names_every_class_that_was_skipped_with_the_services_it_was_skipped_on(db):
    eng = _engagement(db)
    run = _run(db, eng)
    _surface(db, eng, run, "a.example.test")
    _surface(db, eng, run, "b.example.test")
    plan = scan_plan.read_plan(db, run.id)
    assert plan["not_run_classes"] == [
        {"label": BLIND, "services": 2}, {"label": RECENT, "services": 2}, {"label": LEGACY, "services": 2},
    ]
    named = {c["check_id"]: c["template_class"] for s in plan["surfaces"] for c in s["checks"]}
    assert named["nuclei:oob:cves_recent"] == RECENT and named["nuclei:oob:generic_b"] == BLIND


def test_the_worker_reads_the_plan_without_the_console_only_extra(db):
    eng = _engagement(db)
    run = _run(db, eng)
    _surface(db, eng, run, "a.example.test")
    assert scan_plan.read_plan(db, run.id, internal=True)["not_run_classes"] == []


@pytest.mark.parametrize("state, reason", [
    ("skipped", "switch_off"),                      # nobody asked for out-of-band testing
    ("skipped", "duplicate_vhost_of:a.example.test"),
    ("complete", "switch_on"),                      # the server was there and the passes ran
    ("failed", "switch_on"),
    ("failed", "oob_unavailable"),                  # only a skipped pass "was not run"
    ("planned", "oob_unavailable"),
])
def test_negative_nothing_is_named_when_the_passes_ran_or_were_not_asked_for(db, state, reason):
    eng = _engagement(db)
    run = _run(db, eng)
    _surface(db, eng, run, "a.example.test", state=state, reason=reason)
    assert scan_plan.read_plan(db, run.id)["not_run_classes"] == []
    model = build_report_model(db, eng, run)
    assert model.coverage is not None and model.coverage.not_run_classes == []
    assert "interaction server" not in (model.executive_summary.coverage_note or "")


def test_a_class_is_named_even_when_only_some_of_its_passes_were_skipped(db):
    eng = _engagement(db)
    run = _run(db, eng)
    _surface(db, eng, run, "a.example.test", parts=["cves_legacy"])
    assert [c["label"] for c in scan_plan.read_plan(db, run.id)["not_run_classes"]] == [LEGACY]


def test_a_skip_on_one_service_does_not_count_for_another(db):
    eng = _engagement(db)
    run = _run(db, eng)
    _surface(db, eng, run, "a.example.test", parts=["cves_recent"])
    _surface(db, eng, run, "b.example.test", parts=["cves_recent"], state="complete", reason="switch_on")
    assert scan_plan.read_plan(db, run.id)["not_run_classes"] == [{"label": RECENT, "services": 1}]


def test_the_report_and_its_summary_list_the_classes_by_name(db):
    eng = _engagement(db)
    run = _run(db, eng)
    _surface(db, eng, run, "a.example.test")
    model = build_report_model(db, eng, run)
    assert model.coverage is not None
    assert model.coverage.not_run_classes == [
        f"{BLIND} (on 1 service)", f"{RECENT} (on 1 service)", f"{LEGACY} (on 1 service)",
    ]
    note = model.executive_summary.coverage_note or ""
    assert OOB_NOTE.format(classes="; ".join(model.coverage.not_run_classes)) in note
    assert "does NOT mean the targets are free of blind vulnerabilities" in note
    lines = model.coverage.rows[0].not_covered
    assert f"nuclei:oob:cves_recent: skipped, {RECENT} not run: interaction server not deployed" in lines


def test_the_pdf_has_a_section_for_the_classes_that_did_not_run(db):
    eng = _engagement(db)
    run = _run(db, eng)
    _surface(db, eng, run, "a.example.test")
    text = "\n".join(page.extract_text() for page in PdfReader(io.BytesIO(render_report_pdf(build_report_model(db, eng, run)))).pages)
    text = " ".join(text.split())
    assert "Template classes not run (no interaction server)" in text
    assert "CVE templates 2023-2026 that confirm through a callback" in text


def test_a_run_whose_passes_ran_has_no_such_section_in_the_pdf(db):
    eng = _engagement(db)
    run = _run(db, eng)
    _surface(db, eng, run, "a.example.test", state="complete", reason="switch_on")
    text = "\n".join(page.extract_text() for page in PdfReader(io.BytesIO(render_report_pdf(build_report_model(db, eng, run)))).pages)
    assert "Template classes not run" not in text
