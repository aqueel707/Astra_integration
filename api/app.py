"""
FastAPI application factory — creates and configures the main API app.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config.settings import get_settings
from db.engine import init_db, close_db


# ---------------------------------------------------------------------------
# Lifespan — runs on startup/shutdown
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: init DB, print banner. Shutdown: close DB."""
    settings = get_settings()

    print(r"""
    ╔═╗╔═╗╔╦╗╦═╗╔═╗
    ╠═╣╚═╗ ║ ╠╦╝╠═╣
    ╩ ╩╚═╝ ╩ ╩╚═╩ ╩
    """)
    print(f"    v{settings.version} | {settings.app_env}")
    print(f"    API:       http://localhost:{settings.api_port}")
    print(f"    API Docs:  http://localhost:{settings.api_port}/docs")
    print(f"    Dashboard: http://localhost:{settings.dashboard_port}")
    print()

    # Init database
    await init_db()

    # Resolve the streaming backend at startup so the deploy log states which
    # one is live. Picking it lazily on first publish meant a misconfiguration
    # only showed up as an empty dashboard, with nothing in the logs to explain it.
    from streaming.backend import get_backend
    print(f"    Streaming: {get_backend().name}")
    print()

    yield

    # Cleanup
    from streaming.backend import close_backend
    from streaming.manager import get_ws_manager
    await get_ws_manager().shutdown()
    await close_backend()
    await close_db()


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------
_DEFAULT_ORIGINS = (
    "https://astra-dashboard-qu4c.onrender.com",
    "http://localhost:8050",
    "http://127.0.0.1:8050",
)


def _allowed_origins() -> list[str]:
    """CORS origins, overridable without a code change.

    The dashboard hostname used to be compiled in, so any rename broke the UI
    with an opaque browser-side CORS failure — while every other
    deployment-specific value already came from the environment.
    """
    raw = os.environ.get("ASTRA_ALLOWED_ORIGINS", "")
    origins = [o.strip() for o in raw.split(",") if o.strip()]
    return origins or list(_DEFAULT_ORIGINS)


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.version,
        description="AI-driven cybersecurity training simulator",
        lifespan=lifespan,
    )

    # CORS — allow dashboard to call API
    # CORS — restrict to the dashboard origin(s). Auth is a bearer token in a
    # header (not cookies), so credentialed CORS isn't needed — and
    # allow_origins=["*"] with allow_credentials=True is invalid anyway.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_allowed_origins(),
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Security headers — common headers + strict CSP for the JSON API
    from security_headers import apply_to_fastapi
    apply_to_fastapi(app)

    # Rate limiting (Redis-backed, global; see api/rate_limit.py)
    from api.rate_limit import init_rate_limiter
    init_rate_limiter(app)

    # Register routers
    _register_routers(app)

    return app


# ---------------------------------------------------------------------------
# Router registration
# ---------------------------------------------------------------------------
def _register_routers(app: FastAPI) -> None:
    """Mount all API routers."""
    # Block 1
    from api.routers.health import router as health_router
    from api.routers.sessions import router as sessions_router
    from api.routers.scenarios import router as scenarios_router

    # Block 4 (Detection Engine)
    from api.routers.detection import router as detection_router
    from api.routers.alerts import router as alerts_router

    # Block 6 (Streaming + Logs/Scoring/MITRE)
    from api.routers.logs import router as logs_router
    from api.routers.scoring import router as scoring_router
    from api.routers.mitre import router as mitre_router

    from api.routers.progress import router as progress_router
    from api.routers.reports import router as reports_router

    app.include_router(health_router, tags=["Health"])
    app.include_router(sessions_router, prefix="/sessions", tags=["Sessions"])
    app.include_router(scenarios_router, prefix="/scenarios", tags=["Scenarios"])
    app.include_router(detection_router, prefix="/detection", tags=["Detection Rules"])
    app.include_router(alerts_router, prefix="/alerts", tags=["Alerts"])
    app.include_router(logs_router, prefix="/logs", tags=["Logs"])
    app.include_router(scoring_router, prefix="/scoring", tags=["Scoring"])
    app.include_router(mitre_router, prefix="/mitre", tags=["MITRE ATT&CK"])
    app.include_router(progress_router, prefix="/progress", tags=["Progress"])
    app.include_router(reports_router, prefix="/reports", tags=["Reports"])

    # Block 2 (attacks) and the Pentester decision-tree mode.
    #
    # These were wrapped in try/except: a typo in either module removed the
    # whole feature and the app still booted reporting healthy, with the
    # failure visible only as a missing route. Neither is optional, so an
    # import error should stop the process while someone is watching.
    from api.routers.attacks import router as attacks_router
    from api.routers.pentester import router as pentester_router

    app.include_router(attacks_router, prefix="/attacks", tags=["Attacks"])
    app.include_router(pentester_router, prefix="/pentester", tags=["Pentester"])
