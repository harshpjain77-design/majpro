"""Health check and service status endpoints."""

import time
from fastapi import APIRouter
from backend.api.dependencies import storage_sink
from backend.api.schemas import HealthResponse

router = APIRouter(tags=["Health"])

START_TIME = time.time()


@router.get("/health", response_model=HealthResponse)
@router.get("/api/v1/health", response_model=HealthResponse)
@router.get("/api/v1/system/health", response_model=HealthResponse)
async def get_health() -> HealthResponse:
    """Return health status, database connectivity, and total stored events."""
    db_ok = storage_sink.check_health()
    events_count = storage_sink.count_events() if db_ok else 0
    uptime = round(time.time() - START_TIME, 2)

    return HealthResponse(
        status="ok" if db_ok else "degraded",
        version="0.1.0",
        database="connected" if db_ok else "unreachable",
        events_stored=events_count,
        uptime_seconds=uptime,
    )
