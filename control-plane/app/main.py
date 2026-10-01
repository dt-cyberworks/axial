import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import api_router
from app.config import get_settings
from app.mfa import MfaKeyUnavailable

settings = get_settings()
log = logging.getLogger("uvicorn.error")

if not settings.mfa_encryption_key.strip():
    # REQ-INSTALL-004: without this the stack is healthy and /health is green, yet
    # nobody can finish MFA enrollment. Say so in the logs where an installer looks.
    log.warning(
        "MFA_ENCRYPTION_KEY is empty: MFA enrollment and sign-in will answer 503 until it is set. "
        "Run `make env` (or set a Fernet key in .env) and restart the control-plane."
    )
app = FastAPI(
    title="ASM Control Plane",
    description="Orchestrator + Scope Gateway. See docs/spec/ for the full architecture specification.",
    version="0.1.0",
    docs_url=None if settings.environment.lower() == "production" else "/docs",
    redoc_url=None if settings.environment.lower() == "production" else "/redoc",
    openapi_url=None if settings.environment.lower() == "production" else "/openapi.json",
)

# Dev-Default: Operator-Konsole (Vite) laeuft auf 5173 (CORS_ALLOWED_ORIGINS ueberschreibt es).
# In Produktion kommen Konsole und API von einer Origin; dort ist keine weitere noetig.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list(),
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

app.include_router(api_router)


@app.exception_handler(MfaKeyUnavailable)
async def _mfa_key_unavailable(_request: Request, exc: MfaKeyUnavailable) -> JSONResponse:
    # REQ-INSTALL-004: a missing or malformed MFA key is a configuration problem the
    # operator can fix, not a server bug: 503 with an actionable message (it names
    # the setting, never a key or secret), and nothing is stored.
    return JSONResponse(status_code=503, content={"detail": str(exc)})


@app.get("/health")
def health():
    return {"status": "ok"}
