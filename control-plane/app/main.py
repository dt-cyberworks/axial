from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import api_router
from app.config import get_settings

settings = get_settings()
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


@app.get("/health")
def health():
    return {"status": "ok"}
