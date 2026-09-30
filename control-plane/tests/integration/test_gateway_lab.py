"""Gateway-Verifikation gegen das Lab-Setup (ASM_Lab_Umgebung.docx Kap. 1/4).

Deckt beide Testrichtungen ab:
  - Positiv: freigegebene Ziele passieren das Gateway
  - Negativ: das out-of-scope-Ziel (clean-nginx) wird IMMER geblockt

Der Negativ-Test ist der wichtigste Sicherheitsnachweis: erst wenn er
reproduzierbar grün ist, ist die Scope-Durchsetzung belegt.
"""

from __future__ import annotations

import datetime as dt

import pytest

from app.gateway.authorize import ToolCall, authorize


# --------------------------------------------------------------------------
# Negativ-Test: deny-Vorrang (der wichtigste Test)
# --------------------------------------------------------------------------

def test_negative_deny_target_is_blocked(db, lab_engagement):
    """clean-nginx ist deny -> jeder aktive Call MUSS mit explicit_out_of_scope
    abgelehnt werden, obwohl das Ziel im selben Netz sichtbar ist."""
    call = ToolCall(
        engagement_id=lab_engagement.id, tool="httpx", category="fingerprint",
        mode="active", target="clean-nginx", args={"method": "GET"},
    )
    decision = authorize(db, call)
    assert not decision.allowed
    assert decision.reason == "explicit_out_of_scope"


def test_negative_deny_beats_passive_too(db, lab_engagement):
    """Auch ein passiver Call auf das Negativ-Ziel wird geblockt - deny hat
    Vorrang vor allem, nicht nur vor aktiven Grants."""
    call = ToolCall(
        engagement_id=lab_engagement.id, tool="subfinder", category="recon",
        mode="passive", target="clean-nginx",
    )
    decision = authorize(db, call)
    assert not decision.allowed
    assert decision.reason == "explicit_out_of_scope"


def test_unknown_target_out_of_scope(db, lab_engagement):
    call = ToolCall(
        engagement_id=lab_engagement.id, tool="httpx", category="fingerprint",
        mode="active", target="evil.example.com", args={"method": "GET"},
    )
    decision = authorize(db, call)
    assert not decision.allowed
    assert decision.reason == "target_out_of_scope"




def test_domain_allow_authorizes_discovered_subdomain(db):
    from app.models.engagement import Engagement, ScopeAsset, ToolGrant

    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(
        title="domain-scope", source="own_domain", status="active",
        authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(hours=1),
    )
    db.add(eng)
    db.flush()
    db.add(ScopeAsset(
        engagement_id=eng.id, rule="allow", asset_type="domain", value="example.com",
        active_allowed=True, authorization_verified=True,
    ))
    db.add(ToolGrant(engagement_id=eng.id, tool_category="fingerprint", mode="active", requires_manual_approval=False))
    db.commit()

    decision = authorize(db, ToolCall(
        engagement_id=eng.id, tool="httpx", category="fingerprint", mode="active",
        target="app.example.com", args={"method": "GET"},
    ))
    assert decision.allowed, decision.reason


def test_child_domain_deny_overrides_parent_domain_allow(db):
    from app.models.engagement import Engagement, ScopeAsset, ToolGrant

    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(
        title="domain-deny", source="own_domain", status="active",
        authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(hours=1),
    )
    db.add(eng)
    db.flush()
    db.add_all([
        ScopeAsset(engagement_id=eng.id, rule="allow", asset_type="domain", value="example.com", active_allowed=True, authorization_verified=True),
        ScopeAsset(engagement_id=eng.id, rule="deny", asset_type="domain", value="admin.example.com"),
    ])
    db.add(ToolGrant(engagement_id=eng.id, tool_category="fingerprint", mode="active", requires_manual_approval=False))
    db.commit()

    decision = authorize(db, ToolCall(
        engagement_id=eng.id, tool="httpx", category="fingerprint", mode="active",
        target="admin.example.com", args={"method": "GET"},
    ))
    assert not decision.allowed
    assert decision.reason == "explicit_out_of_scope"


# --------------------------------------------------------------------------
# Positiv-Test: freigegebene Ziele passieren
# --------------------------------------------------------------------------

def test_positive_allowed_active_passes(db, lab_engagement):
    call = ToolCall(
        engagement_id=lab_engagement.id, tool="httpx", category="fingerprint",
        mode="active", target="metasploitable2", args={"method": "GET"},
    )
    decision = authorize(db, call)
    assert decision.allowed, decision.reason


def test_positive_passive_always_ok(db, lab_engagement):
    call = ToolCall(
        engagement_id=lab_engagement.id, tool="subfinder", category="recon",
        mode="passive", target="juice-shop",
    )
    decision = authorize(db, call)
    assert decision.allowed, decision.reason


def test_passive_without_grant_blocked(db):
    from app.models.engagement import Engagement, ScopeAsset

    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(
        title="passive-no-grant", source="own_domain", status="active",
        authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(hours=1),
    )
    db.add(eng)
    db.flush()
    db.add(ScopeAsset(
        engagement_id=eng.id, rule="allow", asset_type="domain", value="example.com",
        active_allowed=False, authorization_verified=True,
    ))
    db.commit()

    decision = authorize(db, ToolCall(
        engagement_id=eng.id, tool="subfinder", category="recon", mode="passive", target="example.com",
    ))
    assert not decision.allowed
    assert decision.reason == "no_tool_grant"


def test_passive_mode_requires_passive_registry_tool(db, lab_engagement):
    from app.models.engagement import ToolGrant

    db.add(ToolGrant(
        engagement_id=lab_engagement.id, tool_category="fingerprint", mode="passive",
        requires_manual_approval=False,
    ))
    db.commit()

    decision = authorize(db, ToolCall(
        engagement_id=lab_engagement.id, tool="nmap", category="fingerprint",
        mode="passive", target="metasploitable2",
    ))
    assert not decision.allowed
    assert decision.reason == "passive_not_supported"


# --------------------------------------------------------------------------
# Härtung: Status, Zeitfenster, Argumente, Whitelist
# --------------------------------------------------------------------------

def test_unsafe_arguments_blocked(db, lab_engagement):
    """Whitelisted Tool, aber gefährliche Argumente -> unsafe_arguments (Kap. 3.2)."""
    call = ToolCall(
        engagement_id=lab_engagement.id, tool="nmap", category="fingerprint",
        mode="active", target="metasploitable2",
        args={"flags": ["-sV", "--script=exploit-all"]},
    )
    decision = authorize(db, call)
    assert not decision.allowed
    assert decision.reason == "unsafe_arguments"


def test_non_whitelisted_tool_blocked(db, lab_engagement):
    call = ToolCall(
        engagement_id=lab_engagement.id, tool="masscan", category="fingerprint",
        mode="active", target="metasploitable2",
    )
    decision = authorize(db, call)
    assert not decision.allowed
    assert decision.reason == "tool_not_whitelisted"


def test_inactive_engagement_blocks_everything(db, lab_engagement):
    lab_engagement.status = "paused"
    db.commit()
    call = ToolCall(
        engagement_id=lab_engagement.id, tool="subfinder", category="recon",
        mode="passive", target="metasploitable2",
    )
    decision = authorize(db, call)
    assert not decision.allowed
    assert decision.reason == "engagement_not_active"


def test_outside_time_window_blocked(db, lab_engagement):
    lab_engagement.authorized_until = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)
    db.commit()
    call = ToolCall(
        engagement_id=lab_engagement.id, tool="httpx", category="fingerprint",
        mode="active", target="metasploitable2", args={"method": "GET"},
    )
    decision = authorize(db, call)
    assert not decision.allowed
    assert decision.reason == "outside_time_window"


def test_active_without_grant_blocked(db, lab_engagement):
    """Ohne aktiven Grant fuer die Kategorie -> no_tool_grant.
    (active_allowed am Asset ist true, aber der Grant fehlt.) Kein aktiviertes
    cred-Tool mehr (REQ-COVER-005): der vuln-Grant wird deshalb entfernt."""
    from app.models.engagement import ToolGrant

    db.query(ToolGrant).filter_by(engagement_id=lab_engagement.id, tool_category="vuln").delete()
    db.commit()
    call = ToolCall(
        engagement_id=lab_engagement.id, tool="nuclei", category="vuln",
        mode="active", target="metasploitable2",
    )
    decision = authorize(db, call)
    assert not decision.allowed
    assert decision.reason == "no_tool_grant"


@pytest.mark.parametrize("tool,category,mode", [
    ("amass", "recon", "passive"),
    ("whatweb", "fingerprint", "active"),
    ("sslscan", "fingerprint", "active"),
    ("default-cred-check", "cred", "active"),
])
def test_negative_tools_retired_by_req_cover_005_are_denied(db, lab_engagement, tool, category, mode):
    """REQ-COVER-005: enabled-but-never-used tools left the runtime whitelist."""
    call = ToolCall(
        engagement_id=lab_engagement.id, tool=tool, category=category,
        mode=mode, target="metasploitable2",
    )
    decision = authorize(db, call)
    assert not decision.allowed
    # cred has no grant in this fixture, so it is refused one step earlier.
    assert decision.reason in {"tool_not_whitelisted", "no_tool_grant"}


# --------------------------------------------------------------------------
# Audit-Trail: jede Entscheidung wird hash-verkettet protokolliert
# --------------------------------------------------------------------------

def test_decisions_are_audit_logged_and_hash_chained(db, lab_engagement):
    from app.models.audit import AuditLog

    for target in ("metasploitable2", "clean-nginx"):
        authorize(db, ToolCall(
            engagement_id=lab_engagement.id, tool="httpx", category="fingerprint",
            mode="active", target=target, args={"method": "GET"},
        ))

    rows = db.query(AuditLog).order_by(AuditLog.ts.asc()).all()
    assert len(rows) >= 2
    # Hash-Chain: jeder row_hash referenziert den vorherigen (Kap. 3.4).
    assert rows[0].prev_hash is None
    for prev, cur in zip(rows, rows[1:]):
        assert cur.prev_hash == prev.row_hash
