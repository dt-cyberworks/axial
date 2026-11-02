"""Test accounts: dedicated accounts the owner enters into an engagement so the agent can test behind a login
(REQ-TESTACCT-001..009, GitHub #89, R4).

The model sees the real credentials (decision D1). Everything between the model and the target is therefore deterministic and does not
depend on the model's cooperation:

  * the secret is stored Fernet-encrypted under its own key, is never returned by any endpoint and is erased when the engagement ends;
  * an account is bound to the hosts the owner assigned to it and to no others (D8); `host_verdict` is the one definition of "usable",
    used by the agent's context, the console's list and the Scope Gateway rule (`gateway/credential_rule.py`);
  * everything the platform stores holds the placeholder `{{testaccount:<label>}}` instead of the value (`scrub_*`); the worker puts the
    real value back only at the last step before a request leaves for the target.

This module imports the gateway's host matcher lazily: the gateway imports this module for its credential rule.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import re
import uuid
from dataclasses import dataclass
from urllib.parse import quote, quote_plus

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import crypto
from app.config import get_settings
from app.gateway.audit import append_audit_log
from app.models.asset import DiscoveredAsset
from app.models.dns_record import DnsRecord
from app.models.engagement import Engagement, ScopeAsset
from app.models.test_account import LoginConsent, TestAccount, TestAccountHost, TestAccountLoginAttempt
from app.models.user import User

ATTESTATION_VERSION = "2026-11-01"
CONSENT_WORDING_VERSION = "2026-11-01"
CONSENT_WORDING = (
    "The scanner will sign in with these accounts on exactly these hosts, on each scheduled run, using the provider-hosted language "
    "model that receives the credentials (never a host that is held, denied or flagged). It will not change data through the session."
)
KINDS = ("login_form", "login_json", "basic", "header_token")
LOGIN_KINDS = ("login_form", "login_json")
MAX_ACCOUNTS = 4
MAX_HOSTS_PER_ACCOUNT = 50
MIN_SECRET_LENGTH = 8      # a shorter secret would make the value search match ordinary text
MAX_SECRET_LENGTH = 512
MAX_LOGINS_PER_HOST_PER_RUN = 2
MAX_LOGINS_PER_RUN = 20
SUSPEND_AFTER_FAILED_RUNS = 2
LABEL_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
# The worker adds the encoding the value was found in (`{{testaccount:shop|url}}`) so that putting it back gives the same bytes.
PLACEHOLDER_RE = re.compile(r"\{\{testaccount:([A-Za-z0-9_-]{1,40})(?:\|[a-z0-9]{1,8})?\}\}")
TERMINAL_STATUSES = ("completed", "revoked")

# Why a host is not usable for an account, in the words the agent and the console use.
REASON_TEXT = {
    "not_assigned": "not assigned to this account",
    "not_authorized": "no attested allow rule that permits active testing covers it",
    "denied": "blocked by a deny rule",
    "held_for_review": "held for review",
    "possible_takeover": "possible subdomain takeover",
    "suspended_after_rejected_logins": "login was rejected on two runs in a row",
    "account_suspended": "the account is suspended",
    "account_erased": "the account was erased",
}


class TestAccountError(Exception):
    __test__ = False

    def __init__(self, status: int, code: str, detail: str | None = None):
        super().__init__(code)
        self.status, self.code, self.detail = status, code, detail or code


class CipherUnavailable(RuntimeError):
    """No usable TESTACCOUNT_ENCRYPTION_KEY. Never answered by storing plaintext or by using another key."""


# ----------------------------------------------------------------------------------------------------------- the secret at rest


def _cipher():
    settings = get_settings()
    if not settings.testaccount_encryption_key:
        raise CipherUnavailable("TESTACCOUNT_ENCRYPTION_KEY is not set")
    previous = [k for k in settings.testaccount_encryption_key_previous.split(",") if k.strip()]
    try:
        return crypto.build_cipher(settings.testaccount_encryption_key, previous)
    except ValueError as exc:
        raise CipherUnavailable("TESTACCOUNT_ENCRYPTION_KEY is malformed") from exc


def encrypt_secret(plain: str) -> str:
    return crypto.encrypt(_cipher(), plain)


def decrypt_secret(token: str) -> str:
    return crypto.decrypt(_cipher(), token)


# ---------------------------------------------------------------------------------------------------------------- hosts and rules


def normalize_host(value: str) -> str:
    return (value or "").strip().lower().rstrip(".")


def placeholder(label: str) -> str:
    return "{{testaccount:%s}}" % label


def _gateway():
    from app.gateway import authorize as gateway   # lazy: the gateway imports this module

    return gateway


def engagement_hosts(db: Session, eng: Engagement) -> list[str]:
    """The concrete hosts the engagement knows (in-scope discovered assets) or names (an allow row with a plain host or address)."""
    hosts: set[str] = set()
    for asset in db.scalars(select(DiscoveredAsset).where(DiscoveredAsset.engagement_id == eng.id, DiscoveredAsset.in_scope.is_(True))):
        if asset.asset_type in ("domain", "ip"):
            hosts.add(normalize_host(asset.value))
    for rule in db.scalars(select(ScopeAsset).where(ScopeAsset.engagement_id == eng.id, ScopeAsset.rule == "allow")):
        if rule.asset_type in ("domain", "ip") and "*" not in rule.value:
            hosts.add(normalize_host(rule.value))
    return sorted(h for h in hosts if h)


def _covering_allow_rules(db: Session, eng: Engagement, host: str) -> list[ScopeAsset]:
    gw = _gateway()
    return [r for r in db.scalars(select(ScopeAsset).where(ScopeAsset.engagement_id == eng.id, ScopeAsset.rule == "allow"))
            if gw._matches_asset_value(host, r)]


def validate_assignable(db: Session, eng: Engagement, host: str) -> str:
    """A concrete host the engagement knows or covers and no deny rule blocks (REQ-TESTACCT-001)."""
    host = normalize_host(host)
    if not host or "*" in host or "/" in host or " " in host:
        raise TestAccountError(422, "testaccount_host_not_allowed", f"{host or '(empty)'} is not a concrete host")
    if _gateway()._matching_rules(db, eng.id, host, None, "deny"):
        raise TestAccountError(422, "testaccount_host_not_allowed", f"{host} is blocked by a deny rule")
    if not _covering_allow_rules(db, eng, host):
        raise TestAccountError(422, "testaccount_host_not_allowed", f"{host} is not in this engagement's scope")
    return host


@dataclass(frozen=True)
class HostVerdict:
    host: str
    usable: bool
    reason: str | None = None

    @property
    def reason_text(self) -> str | None:
        return REASON_TEXT.get(self.reason or "", self.reason)


def host_verdict(db: Session, eng: Engagement, account: TestAccount, host: str,
                 assignments: dict[str, TestAccountHost] | None = None) -> HostVerdict:
    """THE definition of usable (REQ-TESTACCT-004): assigned to the account, the account active, an attested allow rule that permits
    active testing covers the host, no deny rule, not held for review, not a possible takeover, not suspended on it."""
    from app.gateway import hold_rule

    host = normalize_host(host)
    if assignments is None:
        assignments = {a.host: a for a in db.scalars(select(TestAccountHost).where(TestAccountHost.account_id == account.id))}
    assignment = assignments.get(host)
    if assignment is None:
        return HostVerdict(host, False, "not_assigned")
    if account.state == "erased":
        return HostVerdict(host, False, "account_erased")
    if account.state != "active":
        return HostVerdict(host, False, "account_suspended")
    covering = _covering_allow_rules(db, eng, host)
    if not any(r.active_allowed and r.authorization_verified for r in covering):
        return HostVerdict(host, False, "not_authorized")
    if _gateway()._matching_rules(db, eng.id, host, None, "deny"):
        return HostVerdict(host, False, "denied")
    if hold_rule.is_held_host(db, eng.id, host):
        return HostVerdict(host, False, "held_for_review")
    takeover = db.scalar(select(DnsRecord.id).where(
        DnsRecord.engagement_id == eng.id, func.lower(DnsRecord.fqdn).in_((host, host + ".")), DnsRecord.takeover_suspected.is_(True)).limit(1))
    if takeover is not None:
        return HostVerdict(host, False, "possible_takeover")
    if assignment.suspended_at is not None:
        return HostVerdict(host, False, "suspended_after_rejected_logins")
    return HostVerdict(host, True)


def where_usable(db: Session, eng: Engagement, account: TestAccount) -> dict:
    """{can: [host], cannot: [{host, reason, reason_text}]}: the same lists for the agent, the console and the tests."""
    assignments = {a.host: a for a in db.scalars(select(TestAccountHost).where(TestAccountHost.account_id == account.id))}
    can, cannot = [], []
    for host in sorted(set(assignments) | set(engagement_hosts(db, eng))):
        verdict = host_verdict(db, eng, account, host, assignments)
        if verdict.usable:
            can.append(host)
        else:
            cannot.append({"host": host, "reason": verdict.reason, "reason_text": verdict.reason_text})
    return {"can": can, "cannot": cannot}


# --------------------------------------------------------------------------------------------------------------- reading


def accounts_of(db: Session, engagement_id: uuid.UUID) -> list[TestAccount]:
    return list(db.scalars(select(TestAccount).where(TestAccount.engagement_id == engagement_id).order_by(TestAccount.created_at, TestAccount.label)))


def account_by_label(db: Session, engagement_id: uuid.UUID, label: str) -> TestAccount | None:
    return db.scalar(select(TestAccount).where(TestAccount.engagement_id == engagement_id, TestAccount.label == label))


def assignments_of(db: Session, account: TestAccount) -> list[TestAccountHost]:
    return list(db.scalars(select(TestAccountHost).where(TestAccountHost.account_id == account.id).order_by(TestAccountHost.host)))


def effective_login_path(account: TestAccount, assignment: TestAccountHost | None) -> str | None:
    return (assignment.login_path if assignment is not None and assignment.login_path else None) or account.login_path


def view(db: Session, eng: Engagement, account: TestAccount) -> dict:
    """The read model: never the secret, not even its length (REQ-TESTACCT-002)."""
    where = where_usable(db, eng, account)
    hosts = [{
        "host": a.host, "login_path": a.login_path, "last_outcome": a.last_outcome,
        "last_outcome_at": a.last_outcome_at.isoformat() if a.last_outcome_at else None,
        "suspended": a.suspended_at is not None, "suspended_reason": a.suspended_reason,
    } for a in assignments_of(db, account)]
    return {
        "id": str(account.id), "label": account.label, "role": account.role, "kind": account.kind, "login_path": account.login_path,
        "header_name": account.header_name, "username": account.username, "state": account.state,
        "suspended_reason": account.suspended_reason, "secret_set": account.secret_enc is not None,
        "secret_set_at": account.secret_set_at.isoformat() if account.secret_set_at else None,
        "attested_at": account.attested_at.isoformat() if account.attested_at else None,
        "hosts": hosts, "can_use_on": where["can"], "cannot_use_on": where["cannot"],
    }


def host_choices(db: Session, eng: Engagement) -> list[dict]:
    from app.gateway import hold_rule

    out = []
    for host in engagement_hosts(db, eng):
        denied = _gateway()._matching_rules(db, eng.id, host, None, "deny")
        covered = bool(_covering_allow_rules(db, eng, host))
        takeover = db.scalar(select(DnsRecord.id).where(
            DnsRecord.engagement_id == eng.id, func.lower(DnsRecord.fqdn).in_((host, host + ".")), DnsRecord.takeover_suspected.is_(True)).limit(1))
        out.append({"host": host, "held": hold_rule.is_held_host(db, eng.id, host), "denied_by": denied[0].value if denied else None,
                    "takeover_suspected": takeover is not None, "covered": covered})
    return out


# ------------------------------------------------------------------------------------------------------------------ writing


def _audit(db: Session, eng: Engagement, user: User, action: str, payload: dict) -> None:
    append_audit_log(db, engagement_id=eng.id, actor=f"user:{user.email}", action=action, decision="ALLOW", reason="operator_action", payload=payload)


def _forget(db: Session) -> None:
    db.info.pop("_testaccount_secrets", None)


def _check_writable(eng: Engagement) -> None:
    if eng.status in TERMINAL_STATUSES:
        raise TestAccountError(409, "testaccount_engagement_closed", "the engagement has ended; its accounts were erased")


def _validate_fields(kind: str, label: str, role: str, login_path: str | None, username: str | None, secret: str | None) -> None:
    if not LABEL_RE.match(label or ""):
        raise TestAccountError(422, "testaccount_label_invalid", "the label is 1 to 40 letters, digits, - or _")
    if not (role or "").strip() or len(role) > 40:
        raise TestAccountError(422, "testaccount_role_invalid", "the role is 1 to 40 characters")
    if kind not in KINDS:
        raise TestAccountError(422, "testaccount_kind_invalid", f"kind must be one of {', '.join(KINDS)}")
    if kind in LOGIN_KINDS:
        if not login_path or not login_path.startswith("/") or "?" in login_path or "#" in login_path or " " in login_path:
            raise TestAccountError(422, "testaccount_login_path_invalid", "the login path starts with / and has no query")
    if kind != "header_token" and not (username or "").strip():
        raise TestAccountError(422, "testaccount_username_required", "this kind of account needs a username")
    if secret is not None and not MIN_SECRET_LENGTH <= len(secret) <= MAX_SECRET_LENGTH:
        raise TestAccountError(422, "testaccount_secret_invalid", f"the secret has {MIN_SECRET_LENGTH} to {MAX_SECRET_LENGTH} characters")


def create(db: Session, eng: Engagement, user: User, *, label: str, role: str, kind: str, username: str | None, secret: str,
           login_path: str | None, header_name: str | None, hosts: list[dict], attested: bool) -> TestAccount:
    _check_writable(eng)
    _validate_fields(kind, label, role, login_path, username, secret)
    if not attested:
        raise TestAccountError(422, "testaccount_attestation_required")
    if account_by_label(db, eng.id, label) is not None:
        raise TestAccountError(409, "testaccount_label_taken", "an account with this label exists")
    if len(accounts_of(db, eng.id)) >= MAX_ACCOUNTS:
        raise TestAccountError(409, "testaccount_limit", f"at most {MAX_ACCOUNTS} accounts per engagement")
    wanted = _validated_hosts(db, eng, hosts)
    try:
        token = encrypt_secret(secret)
    except CipherUnavailable as exc:
        raise TestAccountError(503, "testaccount_cipher_unavailable", str(exc)) from exc
    now = dt.datetime.now(dt.timezone.utc)
    account = TestAccount(
        engagement_id=eng.id, label=label, role=role.strip(), kind=kind, login_path=login_path if kind in LOGIN_KINDS else None,
        header_name=(header_name or None) if kind == "header_token" else None, username=(username or "").strip() or None,
        secret_enc=token, secret_set_at=now, attested_by=user.id, attested_at=now, attestation_version=ATTESTATION_VERSION,
    )
    db.add(account)
    db.flush()
    _assign(db, eng, user, account, wanted)
    _forget(db)
    _audit(db, eng, user, "testaccount_created", {"label": label, "role": account.role, "kind": kind, "hosts": sorted(wanted)})
    db.commit()
    db.refresh(account)
    return account


def _validated_hosts(db: Session, eng: Engagement, hosts: list[dict]) -> dict[str, str | None]:
    """Everything is checked BEFORE anything is written, so a refused request leaves nothing behind."""
    if len(hosts) > MAX_HOSTS_PER_ACCOUNT:
        raise TestAccountError(422, "testaccount_limit", f"at most {MAX_HOSTS_PER_ACCOUNT} hosts per account")
    wanted: dict[str, str | None] = {}
    for entry in hosts:
        host = validate_assignable(db, eng, entry["host"])
        path = entry.get("login_path") or None
        if path and (not path.startswith("/") or "?" in path or " " in path):
            raise TestAccountError(422, "testaccount_login_path_invalid", "a login path starts with / and has no query")
        wanted[host] = path
    return wanted


def _assign(db: Session, eng: Engagement, user: User, account: TestAccount, wanted: dict[str, str | None]) -> None:
    existing = {a.host: a for a in assignments_of(db, account)}
    for host, row in existing.items():
        if host not in wanted:
            db.delete(row)
    for host, path in wanted.items():
        if host in existing:
            existing[host].login_path = path
        else:
            db.add(TestAccountHost(account_id=account.id, host=host, login_path=path, assigned_by=user.id, attestation_version=ATTESTATION_VERSION))
    db.flush()


def set_hosts(db: Session, eng: Engagement, user: User, account: TestAccount, hosts: list[dict], *, attested: bool, consent: bool) -> TestAccount:
    _check_writable(eng)
    before = {a.host for a in assignments_of(db, account)}
    wanted = _validated_hosts(db, eng, hosts)
    added = set(wanted) - before
    if added and not attested:
        raise TestAccountError(422, "testaccount_attestation_required", "assigning a further host repeats the attestation")
    _assign(db, eng, user, account, wanted)
    after = {a.host for a in assignments_of(db, account)}
    _forget(db)
    _audit(db, eng, user, "testaccount_hosts_changed", {"label": account.label, "added": sorted(after - before), "removed": sorted(before - after)})
    db.commit()
    if consent and eng.operating_mode == "monitoring" and eng.status in ("active", "paused"):
        give_consent(db, eng, user)   # the owner ticked the consent in the same action as the change of hosts
    db.refresh(account)
    return account


def replace_secret(db: Session, eng: Engagement, user: User, account: TestAccount, secret: str) -> TestAccount:
    _check_writable(eng)
    if account.state == "erased":
        raise TestAccountError(409, "testaccount_erased", "an erased account cannot be revived; enter a new one")
    _validate_fields(account.kind, account.label, account.role, account.login_path, account.username, secret)
    try:
        account.secret_enc = encrypt_secret(secret)
    except CipherUnavailable as exc:
        raise TestAccountError(503, "testaccount_cipher_unavailable", str(exc)) from exc
    account.secret_set_at = dt.datetime.now(dt.timezone.utc)
    account.state, account.suspended_reason = "active", None
    for assignment in assignments_of(db, account):
        assignment.failed_runs, assignment.suspended_at, assignment.suspended_reason = 0, None, None
    _forget(db)
    _audit(db, eng, user, "testaccount_secret_replaced", {"label": account.label})
    db.commit()
    db.refresh(account)
    return account


def resume(db: Session, eng: Engagement, user: User, account: TestAccount) -> TestAccount:
    """The owner lifts a suspension without replacing the secret."""
    _check_writable(eng)
    account.state, account.suspended_reason = ("active" if account.state != "erased" else "erased"), None
    for assignment in assignments_of(db, account):
        assignment.failed_runs, assignment.suspended_at, assignment.suspended_reason = 0, None, None
    _audit(db, eng, user, "testaccount_resumed", {"label": account.label})
    db.commit()
    db.refresh(account)
    return account


def delete(db: Session, eng: Engagement, user: User, account: TestAccount) -> None:
    label = account.label
    db.delete(account)
    _forget(db)
    _audit(db, eng, user, "testaccount_deleted", {"label": label})
    db.commit()


# --------------------------------------------------------------------------------------------------------------------- consent


def current_pairs(db: Session, eng: Engagement) -> list[dict]:
    pairs = []
    for account in accounts_of(db, eng.id):
        if account.state == "erased" or account.kind not in LOGIN_KINDS:
            continue
        for assignment in assignments_of(db, account):
            pairs.append({"label": account.label, "host": assignment.host, "login_path": effective_login_path(account, assignment)})
    return pairs


def latest_consent(db: Session, engagement_id: uuid.UUID) -> LoginConsent | None:
    return db.scalar(select(LoginConsent).where(LoginConsent.engagement_id == engagement_id, LoginConsent.revoked_at.is_(None))
                     .order_by(LoginConsent.given_at.desc(), LoginConsent.id.desc()).limit(1))


def consent_covers(db: Session, engagement_id: uuid.UUID, account: TestAccount, host: str, login_path: str | None) -> LoginConsent | None:
    """The newest un-revoked consent of the current wording that names this (account, host, login path)."""
    for row in db.scalars(select(LoginConsent).where(LoginConsent.engagement_id == engagement_id, LoginConsent.revoked_at.is_(None))
                          .order_by(LoginConsent.given_at.desc())):
        if row.wording_version != CONSENT_WORDING_VERSION:
            continue
        if any(p.get("label") == account.label and p.get("host") == host and p.get("login_path") == login_path for p in row.pairs):
            return row
    return None


def give_consent(db: Session, eng: Engagement, user: User) -> LoginConsent:
    """Appended, never edited. A monitor's consent to log in with its accounts, on exactly the hosts assigned to them now."""
    if eng.operating_mode != "monitoring":
        raise TestAccountError(409, "login_consent_not_applicable", "only a monitoring engagement needs a login consent")
    _check_writable(eng)
    pairs = current_pairs(db, eng)
    row = LoginConsent(engagement_id=eng.id, given_by=user.id, wording_version=CONSENT_WORDING_VERSION, pairs=pairs)
    db.add(row)
    _audit(db, eng, user, "login_consent_given", {"pairs": [{"label": p["label"], "host": p["host"]} for p in pairs], "wording": CONSENT_WORDING_VERSION})
    db.commit()
    db.refresh(row)
    return row


def revoke_consent(db: Session, eng: Engagement, user: User) -> int:
    now = dt.datetime.now(dt.timezone.utc)
    rows = list(db.scalars(select(LoginConsent).where(LoginConsent.engagement_id == eng.id, LoginConsent.revoked_at.is_(None))))
    for row in rows:
        row.revoked_at, row.revoked_by = now, user.id
    _audit(db, eng, user, "login_consent_revoked", {"revoked": len(rows)})
    db.commit()
    return len(rows)


def activation_problems(db: Session, eng: Engagement) -> list[str]:
    """REQ-TESTACCT-006/009: a monitor whose accounts have a login pair that no current consent covers cannot be activated."""
    if eng.operating_mode != "monitoring":
        return []
    for account in accounts_of(db, eng.id):
        if account.state == "erased" or account.kind not in LOGIN_KINDS:
            continue
        for assignment in assignments_of(db, account):
            if consent_covers(db, eng.id, account, assignment.host, effective_login_path(account, assignment)) is None:
                return ["login_consent_required"]
    return []


def authorization_lines(db: Session, eng: Engagement) -> list[dict] | None:
    """REQ-TESTACCT-009: what the authorization document states about the engagement's test accounts - never the secret. None when there
    is none, so a document signed before this feature existed keeps its checksum. Erased accounts are history and are not listed."""
    out = []
    for account in accounts_of(db, eng.id):
        if account.state == "erased":
            continue
        who = db.get(User, account.attested_by) if account.attested_by else None
        out.append({
            "label": account.label, "role": account.role, "kind": account.kind, "username": account.username,
            "hosts": sorted(a.host for a in assignments_of(db, account)),
            "attested_by": who.display_name if who is not None else None,
            "attested_at": account.attested_at.isoformat() if account.attested_at else None,
        })
    return out or None


def consent_view(db: Session, eng: Engagement) -> dict:
    row = latest_consent(db, eng.id)
    pairs = current_pairs(db, eng)
    uncovered = [p for p in pairs if (acct := account_by_label(db, eng.id, p["label"])) is not None
                 and consent_covers(db, eng.id, acct, p["host"], p["login_path"]) is None]
    return {
        "applicable": eng.operating_mode == "monitoring", "current": row is not None and row.wording_version == CONSENT_WORDING_VERSION,
        "given_at": row.given_at.isoformat() if row else None, "wording_version": CONSENT_WORDING_VERSION,
        "pairs": pairs, "uncovered": uncovered,
    }


# ----------------------------------------------------------------------------------------------------------- erase at the end


def erase_engagement(db: Session, engagement_id: uuid.UUID, *, reason: str, actor: str = "system") -> int:
    """Nulls every ciphertext (not just flags it), marks the accounts erased and revokes the consents. Idempotent."""
    now = dt.datetime.now(dt.timezone.utc)
    erased = 0
    for account in accounts_of(db, engagement_id):
        if account.secret_enc is not None or account.state != "erased":
            account.secret_enc, account.state = None, "erased"
            erased += 1
    for row in db.scalars(select(LoginConsent).where(LoginConsent.engagement_id == engagement_id, LoginConsent.revoked_at.is_(None))):
        row.revoked_at = now
    if erased:
        append_audit_log(db, engagement_id=engagement_id, actor=actor, action="testaccounts_erased", decision="ALLOW", reason=reason,
                         payload={"accounts": erased})
    _forget(db)
    db.commit()
    return erased


def erase_expired(db: Session) -> int:
    """Housekeeping: accounts of an engagement that ended or whose window closed lose their secret (REQ-TESTACCT-002)."""
    now = dt.datetime.now(dt.timezone.utc)
    ids = db.scalars(
        select(TestAccount.engagement_id).join(Engagement, Engagement.id == TestAccount.engagement_id)
        .where(TestAccount.state != "erased", (Engagement.status.in_(TERMINAL_STATUSES)) | (Engagement.authorized_until < now)).distinct()
    ).all()
    return sum(erase_engagement(db, eid, reason="engagement_ended") for eid in ids)


# --------------------------------------------------------------------- finding the secret in text (gateway rule, scrubbing)


def secret_forms(account: TestAccount, secret: str) -> list[str]:
    """The plain value and the encodings the platform composes or recognizes, longest first (so a long encoding is replaced whole)."""
    forms = {secret, quote(secret, safe=""), quote_plus(secret), json.dumps(secret)[1:-1],
             base64.b64encode(secret.encode()).decode(), base64.urlsafe_b64encode(secret.encode()).decode().rstrip("=")}
    if account.username:
        raw = f"{account.username}:{secret}".encode()
        forms.update({base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode().rstrip("=")})
    return sorted((f for f in forms if len(f) >= MIN_SECRET_LENGTH), key=len, reverse=True)


def known_secrets(db: Session, engagement_id: uuid.UUID) -> list[tuple[TestAccount, str]]:
    """(account, plaintext secret) of the engagement's readable, un-erased accounts. Cached per session; flushed on every write."""
    cache = db.info.setdefault("_testaccount_secrets", {})
    if engagement_id in cache:
        return cache[engagement_id]
    out: list[tuple[TestAccount, str]] = []
    for account in db.scalars(select(TestAccount).where(TestAccount.engagement_id == engagement_id, TestAccount.secret_enc.is_not(None))):
        try:
            out.append((account, decrypt_secret(account.secret_enc)))
        except Exception:  # noqa: BLE001 - no key, wrong key or a corrupt token: the secret cannot be searched for
            continue
    cache[engagement_id] = out
    return out


def _leaves(value, out: list[str]) -> None:
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for k, v in value.items():
            out.append(str(k))
            _leaves(v, out)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _leaves(v, out)
    elif value is not None and not isinstance(value, (bool, int, float)):
        out.append(str(value))


def find_uses(db: Session, engagement_id: uuid.UUID, *values) -> tuple[list[TestAccount], list[str]]:
    """The accounts a request refers to, by placeholder or by value (plain or any recognized encoding), and the labels of
    placeholders that name no account of this engagement."""
    leaves: list[str] = []
    for value in values:
        _leaves(value, leaves)
    if not leaves:
        return [], []
    text = "\n".join(leaves)
    labels = set(PLACEHOLDER_RE.findall(text))
    used: dict[uuid.UUID, TestAccount] = {}
    unknown: list[str] = []
    for label in sorted(labels):
        account = account_by_label(db, engagement_id, label)
        if account is None:
            unknown.append(label)
        else:
            used[account.id] = account
    for account, secret in known_secrets(db, engagement_id):
        if account.id in used:
            continue
        if any(form in text for form in secret_forms(account, secret)):
            used[account.id] = account
    return list(used.values()), unknown


def scrub_text(db: Session, engagement_id: uuid.UUID, text: str) -> str:
    """Every known secret, in any recognized form, replaced by its placeholder."""
    if not text:
        return text
    for account, secret in known_secrets(db, engagement_id):
        for form in secret_forms(account, secret):
            if form in text:
                text = text.replace(form, placeholder(account.label))
    return text


def scrub_json(db: Session, engagement_id: uuid.UUID, value):
    if not known_secrets(db, engagement_id):
        return value
    if isinstance(value, str):
        return scrub_text(db, engagement_id, value)
    if isinstance(value, dict):
        return {k: scrub_json(db, engagement_id, v) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub_json(db, engagement_id, v) for v in value]
    if isinstance(value, tuple):
        return tuple(scrub_json(db, engagement_id, v) for v in value)
    return value


# --------------------------------------------------------------------------------------------------------- logins and outcomes


def login_attempts(db: Session, account: TestAccount, host: str, run_id: uuid.UUID | None) -> tuple[int, int]:
    """(attempts on this host in this run, attempts over all hosts in this run)."""
    if run_id is None:
        return 0, 0
    base = select(func.count()).select_from(TestAccountLoginAttempt).where(
        TestAccountLoginAttempt.account_id == account.id, TestAccountLoginAttempt.scan_run_id == run_id)
    return db.scalar(base.where(TestAccountLoginAttempt.host == host)) or 0, db.scalar(base) or 0


def record_login_attempt(db: Session, account: TestAccount, host: str, run_id: uuid.UUID | None) -> None:
    db.add(TestAccountLoginAttempt(account_id=account.id, scan_run_id=run_id, host=host))
    db.flush()


def fold_outcomes(db: Session, eng: Engagement, outcomes: list[dict]) -> dict:
    """The worker's per-(account, host) outcomes of one run: `session_established`, `rejected`, `not_attempted`. A rejection counts
    toward a suspension on that host after two runs in a row (REQ-TESTACCT-007); a success resets it.
    Returns {lost: [{label, host, outcome}], regained: [...] , suspended: [...]} for the caller (run health, change events)."""
    now = dt.datetime.now(dt.timezone.utc)
    lost, regained, suspended = [], [], []
    established_labels: set[str] = set()
    for item in outcomes:
        account = account_by_label(db, eng.id, str(item.get("label", "")))
        host = normalize_host(str(item.get("host", "")))
        outcome = str(item.get("outcome", ""))
        if account is None or outcome not in ("session_established", "rejected", "not_attempted"):
            continue
        row = db.scalar(select(TestAccountHost).where(TestAccountHost.account_id == account.id, TestAccountHost.host == host))
        if row is None:
            continue
        previous = row.last_outcome
        if outcome != "not_attempted":
            row.last_outcome, row.last_outcome_at = outcome, now
        if outcome == "rejected":
            row.failed_runs += 1
            lost.append({"label": account.label, "host": host, "outcome": outcome})
            if row.failed_runs >= SUSPEND_AFTER_FAILED_RUNS and row.suspended_at is None:
                row.suspended_at, row.suspended_reason = now, "login rejected on two runs in a row"
                suspended.append({"label": account.label, "host": host})
        elif outcome == "session_established":
            row.failed_runs = 0
            established_labels.add(account.label)
            if previous == "rejected":
                regained.append({"label": account.label, "host": host})
    for account in accounts_of(db, eng.id):
        hosts = assignments_of(db, account)
        if hosts and all(h.suspended_at is not None for h in hosts) and account.state == "active":
            account.state, account.suspended_reason = "suspended", "login rejected on every assigned host"
    db.commit()
    return {"lost": lost, "regained": regained, "suspended": suspended}


def agent_accounts(db: Session, eng: Engagement) -> list[dict]:
    """What a run of this engagement is given (REQ-TESTACCT-003): the active accounts with the real value (D1) and the two lists."""
    if eng.status != "active":
        return []
    out = []
    secrets = {a.id: s for a, s in known_secrets(db, eng.id)}
    for account in accounts_of(db, eng.id):
        if account.state != "active" or account.id not in secrets:
            continue
        where = where_usable(db, eng, account)
        assignments = {a.host: a for a in assignments_of(db, account)}
        out.append({
            "label": account.label, "role": account.role, "kind": account.kind, "username": account.username,
            "secret": secrets[account.id], "header_name": account.header_name, "login_path": account.login_path,
            "login_paths": {h: effective_login_path(account, a) for h, a in assignments.items()},
            "can_use_on": where["can"], "cannot_use_on": where["cannot"],
        })
    return out
