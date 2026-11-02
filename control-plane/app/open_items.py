"""Retest and open items (REQ-RETEST-001..008, GitHub #75).

What a monitor could not do - a request that needs a person, a check that failed or was skipped - is kept and listed,
so that a person can run exactly that and not the whole engagement again. Nothing here widens what the Scope Gateway
allows: a restricted run is an ordinary run, and a confirmed request is executed through the existing approval claim
path (the gateway re-checks it, and the call must match the stored one byte for byte).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
import re
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import config_resolver, monitoring
from app.config import get_settings
from app.gateway import args_safety
from app.gateway.audit import append_audit_log
from app.gateway.authorize import ToolCall, _tool_grant_for, _tool_requires_manual_approval
from app.models.approval import ApprovalRequest
from app.models.asset import DiscoveredAsset
from app.models.engagement import Engagement
from app.models.finding import Finding
from app.models.open_request import OpenRequest
from app.models.scan_plan import ScanCheck, ScanSurface
from app.models.scan_run import ScanRun
from app.report_redaction import redact_value
from app.tools import registry

logger = logging.getLogger(__name__)

NOT_IN_THIS_RUN = "not_in_this_run"
_SHARD_RE = re.compile(r"^(.*):\d+of\d+$")
_FINISHED_RUN_STATES = ("done", "failed", "aborted")
_RUNS_CONSIDERED = 30

# A check skipped for one of these reasons did not run because of something a person can change (a name that has
# no address yet, a missing grant, a call the gateway refused, an unavailable helper). Every other skip is by
# design - it does not apply, it is switched off, it is a duplicate - and is never an open item.
_RESOLVABLE_SKIPS = (
    "materialized_ip_missing", "no_tool_grant", "gateway_denied:", "oob_unavailable", "raw_egress_unavailable",
    "dependency_never_finished", "dns_rematerialization_failed",
)
_RANK = {"failed": 3, "partial": 2, "did_not_run": 1, "skipped": 1}
_SENSITIVE_HEADERS = {"cookie", "authorization", "proxy-authorization", "x-api-key", "x-auth-token"}


def family(check_id: str) -> str:
    """Shards of one check ('nuclei:generic:2of5') count as the same check ('nuclei:generic')."""
    match = _SHARD_RE.match(check_id or "")
    return match.group(1) if match else check_id


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def max_age() -> dt.timedelta:
    return dt.timedelta(days=get_settings().open_item_max_age_days)


# ---------------------------------------------------------------- held-back requests (REQ-RETEST-004)


def dedupe_key(tool: str, target: str, method: str | None, path: str | None, args: dict) -> str:
    """One key per distinct request: two different POSTs on one host are two items."""
    if tool == "http_request":
        material = [tool, target.lower(), (method or "").upper(), path or "", str(args.get("body") or "")]
    else:
        material = [tool, target.lower(), json.dumps(args, sort_keys=True, default=str)]
    return hashlib.sha256("\x1f".join(material).encode()).hexdigest()


def _request_title(req: OpenRequest) -> str:
    if req.tool == "http_request":
        return f"{req.method or 'GET'} {req.path or '/'} on {req.target}"
    return f"{req.tool} on {req.target}"


def park_request(db: Session, approval: ApprovalRequest, reason: str = "approval_unavailable_unattended") -> OpenRequest | None:
    """Keep the exact call of an approval the worker will not wait for. The caller withdraws the approval either way;
    a failure here is an error in the log and in the audit log, never silent, and falls back to the old one-line
    suggestion so that the person still sees that something was held back."""
    call = dict(approval.tool_call or {})
    tool, target = str(call.get("tool") or ""), str(call.get("target") or "")
    if not tool or not target:
        return None
    args = call.get("args") if isinstance(call.get("args"), dict) else {}
    is_http = tool == "http_request"
    method = str(args.get("method", "GET")).upper() if is_http else None
    path = str(args["path"]) if is_http and args.get("path") is not None else None
    state_changing = args_safety.http_request_is_state_changing(args) if is_http else False
    key = dedupe_key(tool, target, method, path, args)
    rationale = str(call.get("rationale") or "")[:2000]
    try:
        with db.begin_nested():
            previous = db.scalar(
                select(OpenRequest)
                .where(OpenRequest.engagement_id == approval.engagement_id, OpenRequest.dedupe_key == key,
                       OpenRequest.state == "open")
                .with_for_update()
            )
            if previous is not None:
                # The newest identical proposal replaces the older one: its age starts again.
                previous.state, previous.decided_at, previous.decided_by = "superseded", _now(), "superseded"
                monitoring.resolve_inbox_items(db, approval.engagement_id, f"request:{previous.id}", "superseded")
            row = OpenRequest(
                engagement_id=approval.engagement_id, source_run_id=_run_id(call), source_approval_id=approval.id,
                tool=tool, target=target, method=method, path=path, call=call, rationale=rationale,
                risk=call.get("risk") if isinstance(call.get("risk"), dict) else None,
                state_changing=state_changing, reason=reason, dedupe_key=key,
            )
            db.add(row)
            db.flush()
            monitoring.open_inbox_item(
                db, approval.engagement_id, "suggestion", f"request:{row.id}", f"Held back: {_request_title(row)}",
                {"tool": tool, "target": target, "method": method, "path": path, "rationale": rationale[:500],
                 "open_request_id": str(row.id)},
            )
    except Exception as exc:  # noqa: BLE001 - parking must never be what fails the worker's withdrawal
        logger.error("could not keep the held-back request of approval %s: %s", approval.id, exc, exc_info=True)
        append_audit_log(
            db, engagement_id=approval.engagement_id, actor="control-plane", action="open_request_park_failed",
            decision="DENY", reason=type(exc).__name__,
            payload={"approval_id": str(approval.id), "tool": tool, "target": target},
        )
        monitoring.add_suggestion(db, approval.engagement_id, tool[:60], target[:253], rationale)
        db.commit()
        return None
    append_audit_log(
        db, engagement_id=approval.engagement_id, actor="control-plane", action="open_request_parked",
        decision="ALLOW", reason=reason,
        payload={"open_request_id": str(row.id), "approval_id": str(approval.id), "tool": tool, "target": target,
                 "method": method, "path": path, "scan_run_id": str(row.source_run_id) if row.source_run_id else None},
    )
    return row


def _run_id(call: dict) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(call.get("scan_run_id")))
    except (ValueError, TypeError):
        return None


def request_view(req: OpenRequest, now: dt.datetime, reveal: bool = True) -> dict:
    """`reveal` False (a reader who is not the owner or an administrator) leaves out the body and the headers: the
    body of a login is a credential, and everyone who can see the engagement can read this list."""
    args = (req.call or {}).get("args") or {}
    headers = args.get("headers") if isinstance(args.get("headers"), dict) else {}
    safe_headers = {
        str(k): ("[redacted]" if str(k).lower() in _SENSITIVE_HEADERS else redact_value(str(k), str(v)))
        for k, v in headers.items()
    }
    age = now - req.created_at
    return {
        "id": str(req.id), "kind": "request", "host": req.target, "port": None, "check": None, "tool": req.tool,
        "title": _request_title(req), "state": "held_back", "reason": req.reason,
        "needs_confirmation": True, "state_changing": bool(req.state_changing),
        "age_days": round(age.total_seconds() / 86400, 2), "run_id": str(req.source_run_id) if req.source_run_id else None,
        "expired": age > max_age(),
        "request": {
            "target": req.target, "method": req.method, "path": req.path,
            "body": args.get("body") if reveal else None, "body_hidden": bool(args.get("body")) and not reveal,
            "headers": safe_headers if reveal else {}, "rationale": req.rationale, "risk": req.risk,
        },
    }


# ---------------------------------------------------------------- open checks (REQ-RETEST-003)


def _classify(check: ScanCheck, run: ScanRun) -> tuple[str, str] | None:
    """(state, reason) when this check row is something still open, None when it is settled."""
    detail = (check.outcome_summary or {}).get("detail")
    if check.state == "failed":
        return "failed", str(detail or check.reason or "failed")
    if check.state == "partial":
        return "partial", str(detail or check.reason or "partial")
    if check.state == "skipped":
        reason = str(check.reason or "")
        if reason.startswith(_RESOLVABLE_SKIPS):
            return "skipped", reason
        return None
    if check.state in ("planned", "running") and run.state in _FINISHED_RUN_STATES:
        return "did_not_run", "run_ended_early"
    return None


def _needs_confirmation(db: Session, eng: Engagement, tool: str, memo: dict[str, bool]) -> bool:
    """Whether a call of this tool needs a person's approval in this engagement - decided by the gateway's own rule."""
    if tool not in memo:
        spec = registry.get(tool)
        grant = _tool_grant_for(db, eng.id, spec.category, "active") if spec is not None else None
        memo[tool] = bool(_tool_requires_manual_approval(db, eng.id, grant, tool)) if spec is not None else False
    return memo[tool]


def _open_checks(db: Session, eng: Engagement, now: dt.datetime) -> list[dict]:
    runs = db.scalars(
        select(ScanRun)
        .where(ScanRun.engagement_id == eng.id, ScanRun.trigger != "baseline", ScanRun.state.in_(_FINISHED_RUN_STATES))
        .order_by(ScanRun.started_at.desc()).limit(_RUNS_CONSIDERED)
    ).all()
    if not runs:
        return []
    by_run = {r.id: r for r in runs}
    rows = db.execute(
        select(ScanCheck, ScanSurface)
        .join(ScanSurface, ScanCheck.surface_id == ScanSurface.id)
        .where(ScanCheck.scan_run_id.in_(by_run))
    ).all()
    per_run: dict[uuid.UUID, dict[tuple[str, int, str], list[tuple[ScanCheck, ScanSurface]]]] = {}
    for check, surface in rows:
        if check.state == "skipped" and check.reason == NOT_IN_THIS_RUN:
            continue  # left out of a restricted run: says nothing about the check
        key = (surface.host.lower(), surface.port, family(check.check_id))
        per_run.setdefault(check.scan_run_id, {}).setdefault(key, []).append((check, surface))
    seen: set[tuple[str, int, str]] = set()
    memo: dict[str, bool] = {}
    items: list[dict] = []
    for run in runs:  # newest first: the first run that knows a check decides whether it is open
        for key, members in per_run.get(run.id, {}).items():
            if key in seen:
                continue
            seen.add(key)
            worst: tuple[str, str, ScanCheck] | None = None
            for check, _surface in members:
                verdict = _classify(check, run)
                if verdict and (worst is None or _RANK[verdict[0]] > _RANK[worst[0]]):
                    worst = (verdict[0], verdict[1], check)
            if worst is None:
                continue
            host, port, fam = key
            state, reason, check = worst
            started = run.finished_at or run.started_at
            items.append({
                "id": f"check:{host}:{port}:{fam}", "kind": "check", "host": host, "port": port, "check": fam,
                "tool": check.tool, "title": f"{fam} on {host}:{port}", "state": state, "reason": reason,
                "needs_confirmation": _needs_confirmation(db, eng, check.tool, memo), "state_changing": False,
                "age_days": round((now - started).total_seconds() / 86400, 2) if started else None,
                "run_id": str(run.id), "expired": False,
            })
    return items


def list_open(db: Session, eng: Engagement, now: dt.datetime | None = None, reveal: bool = True) -> dict:
    now = now or _now()
    requests = db.scalars(
        select(OpenRequest).where(OpenRequest.engagement_id == eng.id, OpenRequest.state == "open")
        .order_by(OpenRequest.created_at.desc())
    ).all()
    items = _open_checks(db, eng, now) + [request_view(r, now, reveal) for r in requests]
    counts = {
        "total": len(items),
        "checks": sum(1 for i in items if i["kind"] == "check"),
        "requests": sum(1 for i in items if i["kind"] == "request"),
        "needs_confirmation": sum(1 for i in items if i["needs_confirmation"]),
    }
    return {"items": items, "counts": counts}


# ---------------------------------------------------------------- retest of a finding (REQ-RETEST-001)


def retest_plan_for_finding(db: Session, eng: Engagement, finding: Finding) -> dict:
    """What a retest of this finding would run: the check that produced it, on its host - or, when no plan check
    produced it, nothing restricted (the host retest of REQ-MODE-017, said so in words)."""
    asset = db.get(DiscoveredAsset, finding.asset_id) if finding.asset_id else None
    host = asset.value.lower() if asset is not None else None
    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    tool = str(evidence.get("tool") or "")
    port = evidence.get("port") if isinstance(evidence.get("port"), int) else None
    # (the item the run is given, the tool that runs it); the tool decides whether a person's approval is needed.
    plan: list[tuple[dict, str]] = []
    if host is not None:
        if tool == "ffuf":
            deep = str(evidence.get("wordlist") or "") == "raft-medium-dirs"
            plan = [({"host": host, "port": port, "check": "ffuf:deep" if deep else "ffuf"}, "ffuf")]
        elif tool == "testssl":
            plan = [({"host": host, "port": port, "check": "testssl"}, "testssl")]
        elif tool == "nuclei":
            plan = [({"host": host, "port": None, "tool": "nuclei"}, "nuclei")]
        elif tool in ("nmap", "nvd_correlation") or (finding.category == "cve" and not tool):
            plan = [({"host": host, "port": None, "check": "correlate"}, "nmap")]
    memo: dict[str, bool] = {}
    items = []
    for token, runs_tool in plan:
        name = token.get("check") or token.get("tool")
        where = token["host"] + (f":{token['port']}" if token.get("port") else "")
        items.append({
            "id": f"check:{token['host']}:{token.get('port')}:{name}", "kind": "check", "host": token["host"],
            "port": token.get("port"), "check": token.get("check"), "tool": token.get("tool") or runs_tool,
            "title": f"{name} on {where}", "state": "retest", "reason": "retest", "age_days": None, "run_id": None,
            "expired": False, "state_changing": False,
            "needs_confirmation": _needs_confirmation(db, eng, runs_tool, memo),
        })
    return {
        "finding_id": str(finding.id), "host": host, "items": items,
        "fallback": None if items else "host",
        "explanation": (
            "This retest runs only the check that found it, on this host." if items else
            "No single check produced this finding, so the retest runs all checks for this host."
        ),
    }


# ---------------------------------------------------------------- sending a confirmed request (REQ-RETEST-006)


class OpenRequestRefused(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


def load_confirmable(db: Session, eng: Engagement, ids: list[uuid.UUID]) -> list[OpenRequest]:
    """The parked requests a person confirms. Anything that is not an open, unexpired request of this engagement
    refuses the whole start, so that nothing is sent by accident."""
    rows: list[OpenRequest] = []
    now = _now()
    for rid in dict.fromkeys(ids):  # one decision per request, in the order given
        row = db.scalar(select(OpenRequest).where(OpenRequest.id == rid).with_for_update())
        if row is None or row.engagement_id != eng.id:
            raise OpenRequestRefused(404, "held-back request not found for this engagement")
        if row.state != "open":
            raise OpenRequestRefused(409, f"held-back request is already '{row.state}'")
        if now - row.created_at > max_age():
            row.state, row.decided_at, row.decided_by = "expired", now, "expired"
            monitoring.resolve_inbox_items(db, eng.id, f"request:{row.id}", "expired")
            db.commit()
            raise OpenRequestRefused(409, "held-back request has expired; the monitor will propose it again if it still matters")
        rows.append(row)
    return rows


def confirm_requests(db: Session, eng: Engagement, run: ScanRun, rows: list[OpenRequest], user_email: str) -> list[ApprovalRequest]:
    """'Send this request' is the approval: one approved approval per request, bound to the exact stored call with
    this run's id. The worker claims it through the unchanged claim path, which re-checks the gateway."""
    timeout = config_resolver.effective_approval_timeout_seconds(db, eng.id)
    approvals: list[ApprovalRequest] = []
    for row in rows:
        payload = dict(row.call or {})
        payload.pop("engagement_id", None)
        payload["scan_run_id"] = run.id
        stored = ToolCall(engagement_id=eng.id, **payload).as_jsonable()
        now = _now()
        approval = ApprovalRequest(
            engagement_id=eng.id, tool_call=stored, state="approved", approved_by=user_email, approved_at=now,
            expires_at=now + dt.timedelta(seconds=timeout),
        )
        db.add(approval)
        db.flush()
        row.state, row.decided_at, row.decided_by = "sent", now, user_email
        row.sent_run_id, row.sent_approval_id = run.id, approval.id
        monitoring.resolve_inbox_items(db, eng.id, f"request:{row.id}", user_email)
        approvals.append(approval)
        summary = {"open_request_id": str(row.id), "approval_id": str(approval.id), "tool": row.tool,
                   "target": row.target, "method": row.method, "path": row.path, "scan_run_id": str(run.id)}
        append_audit_log(
            db, engagement_id=eng.id, actor=f"user:{user_email}", action="approval", decision="ALLOW",
            reason="manual_approval",
            payload={"approval_id": str(approval.id), "tool_call": stored, "scan_run_id": str(run.id),
                     "via": "open_request"},
        )
        append_audit_log(
            db, engagement_id=eng.id, actor=f"user:{user_email}", action="open_request_confirmed", decision="ALLOW",
            reason="individual_confirmation", payload=summary,
        )
    return approvals


def reject_request(db: Session, eng: Engagement, request_id: uuid.UUID, user_email: str) -> OpenRequest:
    row = db.scalar(select(OpenRequest).where(OpenRequest.id == request_id).with_for_update())
    if row is None or row.engagement_id != eng.id:
        raise OpenRequestRefused(404, "held-back request not found for this engagement")
    if row.state != "open":
        raise OpenRequestRefused(409, f"held-back request is already '{row.state}'")
    row.state, row.decided_at, row.decided_by = "rejected", _now(), user_email
    monitoring.resolve_inbox_items(db, eng.id, f"request:{row.id}", user_email)
    append_audit_log(
        db, engagement_id=eng.id, actor=f"user:{user_email}", action="open_request_rejected", decision="DENY",
        reason="rejected_by_person",
        payload={"open_request_id": str(row.id), "tool": row.tool, "target": row.target, "method": row.method,
                 "path": row.path},
    )
    return row


def reconcile_sent(db: Session, run: ScanRun) -> int:
    """After a run: a confirmed request whose approval was not consumed (the gateway denied it, the approval expired,
    the run was stopped) is open again with the reason - 'Not sent - still open', never lost and never a failure."""
    rows = db.scalars(select(OpenRequest).where(OpenRequest.sent_run_id == run.id, OpenRequest.state == "sent")).all()
    reopened = 0
    for row in rows:
        approval = db.get(ApprovalRequest, row.sent_approval_id) if row.sent_approval_id else None
        if approval is not None and approval.state == "consumed":
            continue
        reason = (approval.execution_error or approval.state) if approval is not None else "approval_missing"
        row.state, row.decided_at, row.decided_by = "open", None, None
        row.reason = f"not_sent:{reason}"[:200]
        if approval is not None and approval.state in ("approved", "requested"):
            approval.state = "cancelled"
            approval.execution_error = "run_ended"
        monitoring.open_inbox_item(
            db, row.engagement_id, "suggestion", f"request:{row.id}", f"Held back: {_request_title(row)}",
            {"tool": row.tool, "target": row.target, "method": row.method, "path": row.path,
             "rationale": row.rationale[:500], "open_request_id": str(row.id)},
        )
        append_audit_log(
            db, engagement_id=row.engagement_id, actor="control-plane", action="open_request_not_sent", decision="DENY",
            reason=reason[:200], payload={"open_request_id": str(row.id), "scan_run_id": str(run.id)},
        )
        reopened += 1
    return reopened


def _selected_checks(db: Session, run: ScanRun, token: dict) -> list[ScanCheck]:
    rows = db.execute(
        select(ScanCheck, ScanSurface).join(ScanSurface, ScanCheck.surface_id == ScanSurface.id)
        .where(ScanCheck.scan_run_id == run.id)
    ).all()
    out = []
    for check, surface in rows:
        if surface.host.lower() != str(token.get("host", "")).lower():
            continue
        if token.get("port") is not None and surface.port != token["port"]:
            continue
        if check.state == "skipped" and check.reason == NOT_IN_THIS_RUN:
            continue
        if token.get("check"):
            if family(check.check_id) != family(token["check"]):
                continue
        elif token.get("tool") and check.tool != token["tool"]:
            continue
        out.append(check)
    return out


def retest_complete(db: Session, run: ScanRun, finding: Finding) -> bool:
    """REQ-RETEST-001: did the checks that produced this finding all run to the end on this restricted run?

    A finding no plan check produced has no restricted tokens; its retest is a run of the host and the run's own
    health decides. The correlation (`correlate`) is not a plan check; the run's health covers it."""
    eng = db.get(Engagement, run.engagement_id)
    tokens = retest_plan_for_finding(db, eng, finding)["items"] if eng is not None else []
    for token in tokens:
        if token.get("check") == "correlate":
            continue
        checks = _selected_checks(db, run, token)
        if not checks or any(c.state != "complete" for c in checks):
            return False
    return True
