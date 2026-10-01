"""Preflight-Pruefung: kann fuer diese Engagement ueberhaupt ein Scan laufen?

Spiegelt die engagement-weiten Blocking-Bedingungen, die das Scope Gateway
sonst PRO Tool-Call durchsetzt (Status, Zeitfenster, aktive Grants, aktiv
freigegebener Scope, bug_bounty-Ident-Header). Wird VOR dem Enqueue geprueft,
damit ein aussichtsloser Lauf (z. B. ausserhalb des Zeitfensters) gar nicht
erst startet und dann jeden Request blockt (REQ-RUN-002).

Eine Quelle fuer Endpunkt (GET /scan-readiness) und start_scan - so driften die
beiden nie auseinander.
"""

from __future__ import annotations

import dataclasses
import datetime as dt

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.engagement import BountyProgram, Engagement, ScopeAsset, ToolGrant


@dataclasses.dataclass
class Blocker:
    code: str
    message: str
    # GitHub issue #48: where the operator fixes it (a GUI section), or None.
    action: str | None = None


@dataclasses.dataclass
class Readiness:
    ready: bool
    blockers: list[Blocker]


def evaluate(db: Session, engagement_id) -> Readiness:
    blockers: list[Blocker] = []
    eng = db.get(Engagement, engagement_id)
    if eng is None:
        return Readiness(ready=False, blockers=[Blocker("engagement_not_found", "Engagement not found.")])

    if eng.status != "active":
        blockers.append(Blocker(
            "engagement_not_active",
            f"Engagement is '{eng.status}', not 'active'. Activate it before starting a scan.",
        ))

    now = dt.datetime.now(dt.timezone.utc)
    if eng.authorized_from and now < eng.authorized_from:
        blockers.append(Blocker(
            "before_time_window",
            f"The authorized window starts {eng.authorized_from.date()}. Every tool call would be denied until then.",
        ))
    if eng.authorized_until and now > eng.authorized_until:
        blockers.append(Blocker(
            "after_time_window",
            f"The authorized window ended {eng.authorized_until.date()}. Extend the window before scanning.",
        ))

    active_scope = db.scalar(
        select(ScopeAsset.id).where(
            ScopeAsset.engagement_id == eng.id,
            ScopeAsset.rule == "allow",
            ScopeAsset.active_allowed.is_(True),
        ).limit(1)
    )
    if active_scope is None:
        blockers.append(Blocker(
            "no_active_scope",
            "No in-scope asset is marked active-allowed. Active checks would have no valid target.",
        ))

    active_grant = db.scalar(
        select(ToolGrant.engagement_id).where(
            ToolGrant.engagement_id == eng.id, ToolGrant.mode == "active"
        ).limit(1)
    )
    if active_grant is None:
        blockers.append(Blocker(
            "no_active_tool_grant",
            "No tool category is granted for active testing on this engagement. "
            "Grant at least one under Tool grants to run a scan.",
            action="tool_grants",
        ))

    if eng.source == "bug_bounty":
        prog = db.scalar(select(BountyProgram).where(BountyProgram.engagement_id == eng.id))
        # GitHub issue #32: REQ-AUTH-006's 2026-08-12 amendment made the
        # identification header itself optional (some real programs, e.g.
        # Port of Antwerp-Bruges, identify researchers out-of-band) - a
        # bounty_program row must exist (platform/program_ref remain
        # mandatory), but an unset header is no longer itself a blocker.
        if prog is None:
            blockers.append(Blocker(
                "bounty_program_missing",
                "Bug-bounty engagement without a configured program policy. Program policy is required.",
            ))

    return Readiness(ready=len(blockers) == 0, blockers=blockers)
