"""Pydantic schemas for Ingestion API requests and responses."""

from typing import List, Optional
from pydantic import BaseModel, Field

from collectors.common.schemas import SecurityEvent


class BatchIngestRequest(BaseModel):
    """Payload for submitting a batch of normalized security events."""

    events: List[SecurityEvent] = Field(
        ...,
        min_length=1,
        description="Array of validated SecurityEvent objects",
    )
    agent_id: Optional[str] = Field(
        default=None,
        description="Optional agent identifier submitting this batch",
    )
    collector_version: Optional[str] = Field(
        default=None,
        description="Emitting collector version",
    )


class IngestResponse(BaseModel):
    """Structured response indicating event ingestion outcome."""

    status: str = Field(
        ...,
        description="'success', 'partial_success', or 'error'",
    )
    ingested_count: int = Field(
        ...,
        description="Number of newly persisted unique events",
    )
    duplicate_count: int = Field(
        ...,
        description="Number of duplicate events detected and ignored",
    )
    failed_count: int = Field(
        default=0,
        description="Number of invalid or unprocessable records",
    )
    event_ids: List[str] = Field(
        default_factory=list,
        description="List of ingested event IDs",
    )
    errors: List[str] = Field(
        default_factory=list,
        description="List of descriptive failure messages if any",
    )


class HealthResponse(BaseModel):
    """Health check response schema."""

    status: str = Field(default="ok", description="'ok' or 'degraded'")
    version: str = Field(default="0.1.0", description="API service version")
    database: str = Field(..., description="'connected' or 'unreachable'")
    events_stored: int = Field(..., description="Total count of security events stored")
    uptime_seconds: float = Field(..., description="Service uptime in seconds")


class AgentInfo(BaseModel):
    """Agent context extracted from request headers or body."""

    agent_id: str
    agent_version: Optional[str] = None
    client_ip: Optional[str] = None
