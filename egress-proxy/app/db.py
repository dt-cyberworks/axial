"""Direkter, lesender DB-Zugriff des Egress-Proxy (Deployment-Architektur Kap. 6).

Der Proxy dupliziert die Scope-Pruefung bewusst redundant zum Scope Gateway
in der control-plane (Kap. 6.2: "Das Gateway kontrolliert, WAS beauftragt
wird; der Proxy kontrolliert, was das Netzwerk tatsaechlich VERLAESST").
Deshalb liest er scope_asset/engagement/bounty_program direkt statt ueber
die control-plane-API - zwei unabhaengige Pruefpfade als Defense-in-Depth.
Nur SELECT: der Proxy schreibt nichts in die DB (Audit-Eintraege gehen als
strukturiertes Log an stdout, s. Deployment Kap. 6.1 "Audit").
"""

import os

from sqlalchemy import create_engine, text

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql+psycopg://asm:asm@localhost:5432/asm")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "development").lower()
if ENVIRONMENT == "production" and ("asm:asm@" in DATABASE_URL or "asm-proxy-dev" in DATABASE_URL):
    raise RuntimeError("insecure production configuration: database_url")

engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)


def load_engagement(engagement_id: str) -> dict | None:
    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT id, status, source, authorized_from, authorized_until, "
                "tcp_port_from, tcp_port_to "
                "FROM engagement WHERE id = :id"
            ),
            {"id": engagement_id},
        ).mappings().first()
    return dict(row) if row else None


def candidate_engagements() -> list[dict]:
    """Aktive, im Zeitfenster liegende Engagements mit ihren allow/deny-Scope-
    Assets - fuer die Host-basierte Engagement-Aufloesung (REQ-EGRESS-001), wenn
    weder ASM_ENGAGEMENT_ID noch der Header gesetzt ist. Das Host-Matching
    (Domain-Suffix/Wildcard/CIDR) macht der Proxy in Python, identisch zu
    evaluate(); hier wird nur roh geladen."""
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT e.id AS engagement_id, s.rule, s.asset_type, s.value, s.path_pattern "
                "FROM engagement e JOIN scope_asset s ON s.engagement_id = e.id "
                "WHERE e.status = 'active' AND now() BETWEEN e.authorized_from AND e.authorized_until"
            )
        ).mappings().all()
    by_eng: dict[str, dict] = {}
    for r in rows:
        eng = by_eng.setdefault(str(r["engagement_id"]), {"engagement_id": str(r["engagement_id"]), "allow": [], "deny": []})
        asset = {"asset_type": r["asset_type"], "value": r["value"], "path_pattern": r["path_pattern"]}
        (eng["allow"] if r["rule"] == "allow" else eng["deny"]).append(asset)
    return list(by_eng.values())


def active_engagements_for_materialized_ip(ip: str) -> list[str]:
    """Aktive, im Zeitfenster liegende Engagements, die diese IP auditiert
    materialisiert haben (resolved_host). Fuer Tools, die per IP verbinden
    (z. B. testssl --ip) - konsistent zur is_materialized_ip-Pruefung in
    evaluate() (REQ-EGRESS-001)."""
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT DISTINCT e.id FROM engagement e "
                "JOIN resolved_host r ON r.engagement_id = e.id "
                "WHERE r.ip_address = :ip AND e.status = 'active' "
                "AND now() BETWEEN e.authorized_from AND e.authorized_until"
            ),
            {"ip": ip},
        ).all()
    return [str(r[0]) for r in rows]


def matching_scope_assets(engagement_id: str, host: str, path: str, rule: str) -> list[dict]:
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT asset_type, value, path_pattern, port_from, port_to FROM scope_asset "
                "WHERE engagement_id = :id AND rule = :rule"
            ),
            {"id": engagement_id, "rule": rule},
        ).mappings().all()
    return [dict(r) for r in rows]


def is_materialized_ip(engagement_id: str, ip: str) -> bool:
    """Wurde diese IP aus einem in-scope-Namen auditiert materialisiert
    (resolved_host, s. control-plane dns_materialization)? Dann darf ein Tool,
    das DNS lokal aufloest und per IP verbindet (z. B. testssl --ip), sie
    erreichen - dieselbe Legitimation wie fuer die nmap-Raw-Egress-Policy."""
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT 1 FROM resolved_host WHERE engagement_id = :id AND ip_address = :ip LIMIT 1"),
            {"id": engagement_id, "ip": ip},
        ).first()
    return row is not None


def bounty_program_for(engagement_id: str) -> dict | None:
    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT max_rps, max_concurrency, ident_header_name, ident_header_value, ua_suffix "
                "FROM bounty_program WHERE engagement_id = :id"
            ),
            {"id": engagement_id},
        ).mappings().first()
    return dict(row) if row else None
