"""Human authentication and authorization (REQ-IAM-002..007).

Two dependencies, wired ONCE on the public router (app/api/__init__.py),
cover every current and future public endpoint without per-route changes:
  - require_user: resolves the caller's session to a real User (or, only
    outside production, the legacy shared operator token) - REQ-IAM-002.
  - enforce_engagement_ownership: for any request whose path carries an
    engagement_id, checks the caller owns it (or is admin) BEFORE the
    handler runs - REQ-IAM-007. It inspects request.path_params, which
    Starlette populates during routing, before dependency resolution -
    so this works for every /engagements/{engagement_id}/... route
    (engagements, findings, stream) without touching those handlers.
"""

from __future__ import annotations

import uuid
from secrets import compare_digest
from urllib.parse import urlsplit

from fastapi import Cookie, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from app import auth_service
from app.config import get_settings
from app.db.base import get_db
from app.models.engagement import Engagement
from app.models.user import User
from app.rate_limit import _is_trusted_proxy

# Non-persisted identity for the legacy shared-token path (REQ-IAM-002: kept
# only outside production, for dev/test workflows that predate individual
# accounts). Fixed, obviously-synthetic id - never written to the DB, never
# used anywhere that writes to account_audit_log (whose actor_user_id is a
# real FK).
_LEGACY_TOKEN_USER = User(
    id=uuid.UUID("00000000-0000-0000-0000-000000000000"),
    email="legacy-token@dev", display_name="Legacy shared token", role="admin", status="active",
    must_change_password=False, password_hash="",
)


def _raw_session_token(
    authorization: str | None, session_cookie: str | None,
) -> str | None:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return session_cookie


CSRF_HEADER = "x-requested-with"
CSRF_HEADER_VALUE = "asm-console"
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def _origin_host(value: str) -> str | None:
    try:
        return (urlsplit(value).netloc or None) if value and value != "null" else None
    except ValueError:
        return None


def _allowed_hosts(request: Request) -> set[str]:
    hosts = {request.headers.get("host", "").lower()}
    forwarded = request.headers.get("x-forwarded-host")
    if forwarded and request.client and _is_trusted_proxy(request.client.host):
        hosts.add(forwarded.split(",")[0].strip().lower())
    for origin in get_settings().csrf_trusted_origins.split(","):
        host = _origin_host(origin.strip())
        if host:
            hosts.add(host.lower())
    hosts.discard("")
    return hosts


def enforce_csrf(request: Request) -> None:
    """REQ-IAM-019: a state-changing request that the browser authenticated by
    itself (the session cookie) must prove it came from the console."""
    if request.method.upper() in _SAFE_METHODS:
        return
    if request.headers.get(CSRF_HEADER, "").lower() != CSRF_HEADER_VALUE:
        raise HTTPException(403, "missing anti-CSRF header")
    claimed = request.headers.get("origin") or request.headers.get("referer")
    if claimed is not None:
        host = _origin_host(claimed)
        if host is None or host.lower() not in _allowed_hosts(request):
            raise HTTPException(403, "request origin not allowed")


def require_operator(
    authorization: str | None = Header(default=None),
    x_asm_operator_token: str | None = Header(default=None),
    asm_operator_session: str | None = Cookie(default=None),
) -> str:
    """Legacy shared-token check, preserved standalone for the handful of
    non-production/test call sites that still reference it directly."""
    expected = get_settings().operator_api_token
    bearer = None
    if authorization and authorization.lower().startswith("bearer "):
        bearer = authorization[7:].strip()
    header_token = x_asm_operator_token if isinstance(x_asm_operator_token, str) else None
    cookie_token = asm_operator_session if isinstance(asm_operator_session, str) else None
    supplied = bearer or header_token or cookie_token
    if not expected or not supplied or not compare_digest(supplied, expected):
        raise HTTPException(401, "operator authentication required", headers={"WWW-Authenticate": "Bearer"})
    return "operator"


def require_user(
    request: Request,
    authorization: str | None = Header(default=None),
    session: str | None = Cookie(default=None),
    x_asm_operator_token: str | None = Header(default=None),
    asm_operator_session: str | None = Cookie(default=None),
    db: Session = Depends(get_db),
) -> User:
    # Cheap, no-DB check first (auth must run before database access - a
    # legacy-token caller, or no caller at all, must never require a live DB
    # connection just to be told 401/200). Real per-user sessions inevitably
    # need the DB (server-side, revocable - REQ-IAM-005), checked second.
    if get_settings().environment.lower() != "production":
        expected = get_settings().operator_api_token
        legacy_bearer = authorization[7:].strip() if authorization and authorization.lower().startswith("bearer ") else None
        supplied = legacy_bearer or x_asm_operator_token or asm_operator_session
        if expected and supplied and compare_digest(supplied, expected):
            return _LEGACY_TOKEN_USER

    raw_token = _raw_session_token(authorization, session)
    if raw_token:
        user = auth_service.resolve_session(db, raw_token)
        if user is not None:
            if not (authorization and authorization.lower().startswith("bearer ")):
                enforce_csrf(request)  # only the ambient cookie credential needs it
            return user

    raise HTTPException(401, "authentication required", headers={"WWW-Authenticate": "Bearer"})


def require_admin(user: User = Depends(require_user)) -> User:
    if user.role != "admin":
        raise HTTPException(403, "admin role required")
    return user


def enforce_engagement_ownership(
    request: Request, user: User = Depends(require_user), db: Session = Depends(get_db),
) -> None:
    raw = request.path_params.get("engagement_id")
    if raw is None:
        return
    try:
        engagement_id = uuid.UUID(str(raw))
    except ValueError:
        return  # malformed id: let the handler's own validation produce the error
    if user.role == "admin":
        return
    eng = db.get(Engagement, engagement_id)
    if eng is None or eng.owner_user_id != user.id:
        raise HTTPException(404, "engagement not found")
