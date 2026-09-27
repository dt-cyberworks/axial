from fastapi import APIRouter, Depends

from app.api.admin import router as admin_router
from app.api.approvals import router as approvals_router
from app.api.auth import router as auth_router
from app.api.engagements import router as engagements_router
from app.api.findings import router as findings_router
from app.api.internal import router as internal_router
from app.api.openwire_callback import router as openwire_callback_router
from app.api.settings import router as settings_router
from app.api.stream import router as stream_router
from app.api.tools import router as tools_router
from app.security import enforce_engagement_ownership, require_admin, require_user

api_router = APIRouter()
api_router.include_router(auth_router)
# REQ-IAM-002/007: every route here requires an authenticated user, and every
# route whose path carries an engagement_id is additionally ownership-checked
# (admin bypasses) - both wired once, covering every current and future route
# in these routers without per-endpoint changes.
public_router = APIRouter(dependencies=[Depends(require_user), Depends(enforce_engagement_ownership)])
public_router.include_router(engagements_router)
public_router.include_router(approvals_router)
public_router.include_router(findings_router)
public_router.include_router(stream_router)
public_router.include_router(tools_router)
public_router.include_router(settings_router)
api_router.include_router(public_router)
api_router.include_router(admin_router, dependencies=[Depends(require_admin)])
api_router.include_router(internal_router)
# REQ-AGENT-027: deliberately unauthenticated - fetched by a PROBED TARGET,
# never by an operator or the worker. No dependency on require_user or the
# internal token, unlike every other router above.
api_router.include_router(openwire_callback_router)
