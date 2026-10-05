"""
Health check endpoints — verify API and database are running.
"""

import logging

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from db.engine import get_engine

logger = logging.getLogger("astra.health")
router = APIRouter()


@router.get("/health")
async def health_check():
    return {"status": "ok", "service": "astra-api"}


@router.get("/ready")
async def readiness_check():
    """Check that the database is reachable."""
    try:
        engine = get_engine()
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return {"status": "ready", "database": "connected"}
    except Exception as e:
        # This endpoint is unauthenticated, and asyncpg/SQLAlchemy errors carry
        # host, port, database and role. Log the detail; return a bare status.
        logger.exception("[health] readiness check failed: %s", e)
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "database": "unavailable"},
        )
