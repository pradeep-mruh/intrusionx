"""
IntrusionX FastAPI application entry point.

Configures the application, registers routers, and sets up startup/shutdown
lifecycle events.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.health import router as health_router
from app.core.config import settings

app = FastAPI(
    title="IntrusionX",
    description=(
        "Evidence-driven cyber attack investigation and reconstruction platform. "
        "Evidence → Relationships → Reconstruction → Investigation → Human Validation."
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ---------------------------------------------------------------------------
# CORS — in development allow the Vite dev server origin
# ---------------------------------------------------------------------------

_allowed_origins: list[str] = ["http://localhost:5173"]

if settings.environment != "development":
    # In production, restrict origins to known frontend domains only.
    # Do not use allow_origins=["*"] in production.
    _allowed_origins = []

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

app.include_router(health_router)
