"""
Health check endpoint.

Returns the operational status of the API server and its database connection.
Used by Docker Compose health checks and monitoring.
"""

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session

router = APIRouter(tags=["health"])

VERSION = "0.1.0"


@router.get("/health")
async def health_check(session: AsyncSession = Depends(get_session)) -> dict[str, str]:
    """
    Return the health status of the backend and its database connection.

    Response fields:
    - status: "ok" if the API server is running
    - database: "connected" if PostgreSQL is reachable, "disconnected" otherwise
    - version: API version string
    """
    database_status = "disconnected"
    try:
        await session.execute(text("SELECT 1"))
        database_status = "connected"
    except Exception:
        pass

    return {
        "status": "ok",
        "database": database_status,
        "version": VERSION,
    }
