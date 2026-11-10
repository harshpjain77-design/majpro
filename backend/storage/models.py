"""Pydantic models for storage queries, filters, pagination, and aggregations."""

from typing import Dict, List, Optional
from pydantic import BaseModel, Field, field_validator
from collectors.common.schemas import SecurityEvent
from collectors.common.normalization import normalize_utc_timestamp


class EventFilter(BaseModel):
    """Filter parameters for querying stored security events."""

    start_time: Optional[str] = Field(
        default=None,
        description="Inclusive start timestamp in UTC ISO-8601 (e.g. 2026-10-15T00:00:00Z)",
    )
    end_time: Optional[str] = Field(
        default=None,
        description="Inclusive end timestamp in UTC ISO-8601 (e.g. 2026-10-15T23:59:59Z)",
    )
    source_host: Optional[str] = Field(default=None, description="Exact or case-insensitive hostname filter")
    username: Optional[str] = Field(default=None, description="Target or subject account username")
    source_ip: Optional[str] = Field(default=None, description="Source IPv4 or IPv6 address")
    event_type: Optional[str] = Field(default=None, description="Normalized event type category")
    severity: Optional[str] = Field(default=None, description="Severity: informational, low, medium, high, critical")
    search_term: Optional[str] = Field(
        default=None,
        description="Free-text substring to search within raw_event text",
    )

    @field_validator("start_time", "end_time")
    @classmethod
    def validate_timestamp_format(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        s = v.strip()
        if not s:
            return None
        return normalize_utc_timestamp(s)


class PaginationParams(BaseModel):
    """Pagination query parameters."""

    limit: int = Field(default=50, ge=1, le=1000, description="Max number of records to return (1-1000)")
    offset: int = Field(default=0, ge=0, description="Zero-based index of the first record to return")


class PaginatedEventsResponse(BaseModel):
    """Paginated collection of security events."""

    total: int = Field(..., description="Total number of records matching the filter criteria")
    limit: int = Field(..., description="Requested limit")
    offset: int = Field(..., description="Requested offset")
    has_more: bool = Field(..., description="Whether additional records exist beyond current page")
    events: List[SecurityEvent] = Field(default_factory=list, description="Array of matching SecurityEvent objects")


class TimeSeriesBucket(BaseModel):
    """Time-series histogram count bucket."""

    bucket: str = Field(..., description="Bucket timestamp in UTC ISO-8601")
    count: int = Field(..., description="Number of events in this time interval")


class EventSummaryResponse(BaseModel):
    """Aggregated event metrics and distributions."""

    total_events: int = Field(..., description="Total matching events")
    by_severity: Dict[str, int] = Field(default_factory=dict, description="Count distribution by severity")
    by_event_type: Dict[str, int] = Field(default_factory=dict, description="Count distribution by event type")
    by_source_host: Dict[str, int] = Field(default_factory=dict, description="Count distribution by source host")
    time_series: List[TimeSeriesBucket] = Field(
        default_factory=list,
        description="Chronological event count distribution",
    )
