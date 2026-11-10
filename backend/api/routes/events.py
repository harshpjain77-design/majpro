"""Event query, multi-field search, pagination, and aggregation endpoints."""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.api.dependencies import check_rate_limit, get_agent_info, storage_sink, verify_api_key
from backend.api.routes.ingest import ingest_events
from backend.api.schemas import AgentInfo, BatchIngestRequest, IngestResponse
from backend.storage.models import (
    EventFilter,
    EventSummaryResponse,
    PaginatedEventsResponse,
    PaginationParams,
)
from collectors.common.schemas import SecurityEvent
from typing import List, Union

router = APIRouter(
    prefix="/api/v1/events",
    tags=["Events"],
    dependencies=[Depends(verify_api_key)],
)


@router.post("", response_model=IngestResponse, status_code=status.HTTP_200_OK)
async def post_event(
    payload: Union[BatchIngestRequest, SecurityEvent, List[SecurityEvent]],
    agent_info: AgentInfo = Depends(get_agent_info),
    _rate_check: None = Depends(check_rate_limit),
) -> IngestResponse:
    """Ingest event(s) directly via POST /api/v1/events."""
    return await ingest_events(payload=payload, agent_info=agent_info, _rate_check=_rate_check)


@router.post("/batch", response_model=IngestResponse, status_code=status.HTTP_200_OK)
async def post_event_batch(
    request: BatchIngestRequest,
    agent_info: AgentInfo = Depends(get_agent_info),
    _rate_check: None = Depends(check_rate_limit),
) -> IngestResponse:
    """Batch ingest events directly via POST /api/v1/events/batch."""
    return await ingest_events(payload=request, agent_info=agent_info, _rate_check=_rate_check)



@router.get("", response_model=PaginatedEventsResponse)
async def search_events(
    start_time: Optional[str] = Query(None, description="Start timestamp (UTC ISO-8601)"),
    end_time: Optional[str] = Query(None, description="End timestamp (UTC ISO-8601)"),
    host: Optional[str] = Query(None, description="Filter by source host"),
    source_host: Optional[str] = Query(None, description="Filter by source host (alias)"),
    username: Optional[str] = Query(None, description="Filter by username"),
    ip: Optional[str] = Query(None, description="Filter by source IP"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP (alias)"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    q: Optional[str] = Query(None, description="Free text substring in raw event"),
    query: Optional[str] = Query(None, description="Free text substring (alias)"),
    sort_by: Optional[str] = Query("ingested_at", description="Sort field: ingested_at, timestamp, source_ip, severity, host"),
    sort_dir: Optional[str] = Query("desc", description="Sort direction: asc or desc"),
    limit: int = Query(50, ge=1, le=1000, description="Max items per page"),
    offset: int = Query(0, ge=0, description="Page offset"),
) -> PaginatedEventsResponse:
    """Search and filter security events with multi-field filtering and pagination."""
    effective_host = host or source_host
    effective_ip = ip or source_ip
    effective_q = q or query

    try:
        filters = EventFilter(
            start_time=start_time,
            end_time=end_time,
            source_host=effective_host,
            username=username,
            source_ip=effective_ip,
            event_type=event_type,
            severity=severity,
            search_term=effective_q,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid search filter parameter: {e}",
        )

    pagination = PaginationParams(limit=limit, offset=offset)
    return storage_sink.search_events(
        filters=filters,
        pagination=pagination,
        sort_by=sort_by or "ingested_at",
        sort_dir=sort_dir or "desc",
    )


@router.get("/summary/counts", response_model=EventSummaryResponse)
async def get_summary_counts(
    start_time: Optional[str] = Query(None, description="Start timestamp (UTC ISO-8601)"),
    end_time: Optional[str] = Query(None, description="End timestamp (UTC ISO-8601)"),
) -> EventSummaryResponse:
    """Retrieve event aggregations by severity, type, host, and chronological time series."""
    try:
        # Validate timestamp formats if present
        filters = EventFilter(start_time=start_time, end_time=end_time)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid time-range format: {e}",
        )

    return storage_sink.get_summary_counts(
        start_time=filters.start_time,
        end_time=filters.end_time,
    )


@router.get("/{event_id}", response_model=SecurityEvent)
async def get_event(event_id: str) -> SecurityEvent:
    """Retrieve full structured SecurityEvent by event_id."""
    event = storage_sink.get_event_by_id(event_id=event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event with ID '{event_id}' not found.",
        )
    return event


@router.get("/{event_id}/raw")
async def get_raw_event(event_id: str):
    """Retrieve the original unparsed raw event evidence text/XML."""
    raw = storage_sink.get_raw_event(event_id=event_id)
    if raw is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event with ID '{event_id}' not found.",
        )
    return {"event_id": event_id, "raw_event": raw}
