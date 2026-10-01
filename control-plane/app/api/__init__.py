from fastapi import APIRouter, Depends

from app.api.admin import router as admin_router
from app.api.approvals import router as approvals_router
from app.api.auth import router as auth_router
from app.api.discovery_artifacts import router as discovery_artifacts_router
from app.api.engagements import router as engagements_router
from app.api.findings import router as findings_router
from app.api.internal import router as internal_router
from app.api.openwire_callback import router as openwire_callback_router
from app.api.portfolio import router as portfolio_router
from app.api.settings import router as settings_router
from app.api.stream import router as stream_router
from app.api.tools import router as tools_router
from app.security import enforce_engagement_access, require_admin, require_user

api_router = APIRouter()
api_router.include_router(auth_router)
# REQ-IAM-002/022/023: every route here requires an authenticated user, and every
# route whose path carries an engagement_id is additionally access-checked: any
# signed-in user may read it, only its owner or an admin may change it - both
# wired once, covering every current and future route in these routers without
# per-endpoint changes.
public_router = APIRouter(dependencies=[Depends(require_user), Depends(enforce_engagement_access)])
public_router.include_router(engagements_router)
public_router.include_router(approvals_router)
public_router.include_router(findings_router)
public_router.include_router(discovery_artifacts_router)
# REQ-PORTFOLIO-001: no engagement_id in its path, so the access check above
# does not apply (and it only reads: every signed-in user sees every engagement).
public_router.include_router(portfolio_router)
public_router.include_router(stream_router)
public_router.include_router(tools_router)
api_router.include_router(public_router)
api_router.include_router(admin_router, dependencies=[Depends(require_admin)])
# REQ-IAM-013: global settings (LLM endpoint and key, tool and scan policy,
# agent prompt and budgets) affect every user's engagements, so they are
# admin-only at the API - hiding the page in the console is not enough.
api_router.include_router(settings_router, dependencies=[Depends(require_admin)])
api_router.include_router(internal_router)
# REQ-AGENT-027: deliberately unauthenticated - fetched by a PROBED TARGET,
# never by an operator or the worker. No dependency on require_user or the
# internal token, unlike every other router above.
api_router.include_router(openwire_callback_router)
