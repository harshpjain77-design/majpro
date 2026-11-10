"""Authenticated event ingestion routes."""

import logging
from typing import List, Union
from fastapi import APIRouter, Depends, HTTPException, status

from backend.api.config import settings
from backend.api.dependencies import check_rate_limit, get_agent_info, incident_repo, storage_sink, verify_api_key
from backend.api.schemas import AgentInfo, BatchIngestRequest, IngestResponse
from backend.detection.config import default_config
from backend.detection.engine import DetectionEngine
from collectors.common.schemas import SecurityEvent

logger = logging.getLogger("IngestRoute")

router = APIRouter(
    prefix="/api/v1/ingest",
    tags=["Ingestion"],
    dependencies=[Depends(verify_api_key)],
)

detection_engine = DetectionEngine(config=default_config)


@router.post("", response_model=IngestResponse, status_code=status.HTTP_200_OK)
async def ingest_events(
    payload: Union[BatchIngestRequest, SecurityEvent, List[SecurityEvent]],
    agent_info: AgentInfo = Depends(get_agent_info),
    _rate_check: None = Depends(check_rate_limit),
) -> IngestResponse:
    """Ingest one or multiple normalized security events with authentication and deduplication."""
    # Normalize payload into a list of events
    if isinstance(payload, BatchIngestRequest):
        events = payload.events
        agent_id = payload.agent_id or agent_info.agent_id
    elif isinstance(payload, list):
        events = payload
        agent_id = agent_info.agent_id
    else:
        events = [payload]
        agent_id = agent_info.agent_id

    if not events:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload contains zero events to ingest.",
        )

    if len(events) > settings.MAX_BATCH_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Batch size of {len(events)} exceeds maximum permitted {settings.MAX_BATCH_SIZE}.",
        )

    from datetime import datetime, timezone

    now_utc = datetime.now(timezone.utc)
    now_iso = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    for ev in events:
        try:
            # Check clock skew: if event timestamp is > 5 minutes in the future, clamp to observed_at or now_iso
            ev_dt = datetime.fromisoformat(ev.timestamp.replace("Z", "+00:00"))
            if (ev_dt - now_utc).total_seconds() > 300:
                logger.warning(
                    f"Clock skew detected on host {ev.source_host}: event timestamp {ev.timestamp} is in the future. Clamping to {ev.observed_at or now_iso}"
                )
                ev.timestamp = ev.observed_at or now_iso
        except Exception:
            pass

    try:
        ingested, duplicates, ingested_ids = storage_sink.insert_batch(
            events=events,
            agent_id=agent_id,
        )
    except Exception as e:
        logger.error(f"Storage error during ingestion: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal storage error during event ingestion.",
        )

    # Real-time threat detection and incident correlation pass
    if ingested > 0:
        try:
            alerts = detection_engine.evaluate_events(events)
            if alerts:
                incident_repo.correlate_and_persist(alerts=alerts, event_repo=storage_sink)
        except Exception as det_err:
            logger.warning(f"Detection evaluation on ingest (non-fatal): {det_err}")

    return IngestResponse(
        status="success",
        ingested_count=ingested,
        duplicate_count=duplicates,
        failed_count=0,
        event_ids=ingested_ids,
        errors=[],
    )


@router.post("/batch", response_model=IngestResponse, status_code=status.HTTP_200_OK)
async def ingest_batch(
    request: BatchIngestRequest,
    agent_info: AgentInfo = Depends(get_agent_info),
    _rate_check: None = Depends(check_rate_limit),
) -> IngestResponse:
    """Dedicated batch ingestion endpoint."""
    return await ingest_events(
        payload=request,
        agent_info=agent_info,
        _rate_check=_rate_check,
    )
