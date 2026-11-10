"""Incident management, correlation trigger, and deduplication metrics API endpoints."""

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.api.dependencies import incident_repo, storage_sink, verify_api_key
from backend.correlation.schemas import (
    AnalystNote,
    AnalystNoteCreateRequest,
    CorrelateResponse,
    DeduplicationMetrics,
    Incident,
    IncidentStatusUpdateRequest,
    PaginatedIncidentsResponse,
)
from backend.detection.config import default_config
from backend.detection.engine import DetectionEngine

logger = logging.getLogger("IncidentsAPI")

router = APIRouter(
    prefix="/api/v1/incidents",
    tags=["Incidents"],
    dependencies=[Depends(verify_api_key)],
)

detection_engine = DetectionEngine(config=default_config)


@router.get("", response_model=PaginatedIncidentsResponse)
async def list_incidents(
    status: Optional[str] = Query(None, description="Filter by status: NEW, INVESTIGATING, RESOLVED, CLOSED"),
    severity: Optional[str] = Query(None, description="Filter by severity: low, medium, high, critical"),
    start_time: Optional[str] = Query(None, description="Filter incidents active after start_time (UTC ISO-8601)"),
    end_time: Optional[str] = Query(None, description="Filter incidents active before end_time (UTC ISO-8601)"),
    limit: int = Query(50, ge=1, le=500, description="Page limit"),
    offset: int = Query(0, ge=0, description="Page offset"),
) -> PaginatedIncidentsResponse:
    """Retrieve paginated incidents ordered by risk score descending."""
    incidents, total = incident_repo.list_incidents(
        status=status,
        severity=severity,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        offset=offset,
    )
    return PaginatedIncidentsResponse(
        total=total,
        limit=limit,
        offset=offset,
        incidents=incidents,
    )


@router.get("/metrics/deduplication", response_model=DeduplicationMetrics)
async def get_deduplication_metrics() -> DeduplicationMetrics:
    """Retrieve operational alert reduction and deduplication metrics."""
    return incident_repo.get_deduplication_metrics()


@router.get("/{incident_id}", response_model=Incident)
async def get_incident(incident_id: str) -> Incident:
    """Retrieve full incident details including chronological timeline and analyst notes."""
    incident = incident_repo.get_incident(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found.",
        )
    return incident


@router.patch("/{incident_id}/status", response_model=Incident)
async def update_incident_status(
    incident_id: str,
    payload: IncidentStatusUpdateRequest,
) -> Incident:
    """Update incident status following validated SOC lifecycle transitions."""
    try:
        updated = incident_repo.update_status(
            incident_id=incident_id,
            new_status=payload.status,
            analyst=payload.analyst,
        )
        return updated
    except KeyError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post("/{incident_id}/notes", response_model=AnalystNote, status_code=status.HTTP_201_CREATED)
async def add_analyst_note(
    incident_id: str,
    payload: AnalystNoteCreateRequest,
) -> AnalystNote:
    """Attach an analyst investigation note to an incident."""
    try:
        note = incident_repo.add_note(
            incident_id=incident_id,
            author=payload.author,
            content=payload.content,
        )
        return note
    except KeyError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


@router.post("/correlate", response_model=CorrelateResponse)
async def trigger_correlation(
    start_time: Optional[str] = Query(None, description="Start time window to evaluate"),
    end_time: Optional[str] = Query(None, description="End time window to evaluate"),
    limit: int = Query(1000, ge=1, le=5000, description="Max events to pull from storage"),
) -> CorrelateResponse:
    """Evaluate detection rules on stored events, deduplicate alerts, cluster into incidents, and persist."""
    # 1. Evaluate detection rules on repository events
    raw_alerts = detection_engine.evaluate_from_repository(
        repo=storage_sink,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
    )

    # 2. Run deduplication and incident correlation
    incidents = incident_repo.correlate_and_persist(
        alerts=raw_alerts,
        event_repo=storage_sink,
    )

    metrics = incident_repo.get_deduplication_metrics()

    return CorrelateResponse(
        raw_alerts_processed=len(raw_alerts),
        deduplicated_alerts_created=metrics.deduplicated_alerts_emitted,
        incidents_created_or_updated=len(incidents),
        deduplication_ratio=metrics.deduplication_ratio,
        incidents=incidents,
    )
