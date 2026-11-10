"""Schemas and data models for alert deduplication, incident management, and timelines."""

from datetime import datetime, timezone
from enum import Enum
import hashlib
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, ConfigDict, Field

from backend.detection.schemas import Alert


class IncidentStatus(str, Enum):
    """Lifecycle status states for security incidents."""

    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


# Permitted state transitions enforcing SOC triage workflows
VALID_TRANSITIONS: Dict[IncidentStatus, Set[IncidentStatus]] = {
    IncidentStatus.NEW: {IncidentStatus.INVESTIGATING, IncidentStatus.CLOSED},
    IncidentStatus.INVESTIGATING: {IncidentStatus.RESOLVED, IncidentStatus.CLOSED},
    IncidentStatus.RESOLVED: {IncidentStatus.CLOSED, IncidentStatus.INVESTIGATING},
    IncidentStatus.CLOSED: {IncidentStatus.INVESTIGATING},
}


class TimelineEntry(BaseModel):
    """Chronological milestone in an incident's forensic timeline."""

    model_config = ConfigDict(extra="allow")

    entry_id: str = Field(..., description="Unique timeline entry identifier")
    timestamp: str = Field(..., description="Event or action timestamp (UTC ISO-8601)")
    entry_type: str = Field(
        ...,
        description="Entry category: 'alert', 'event', 'status_change', 'note', 'mitigation'",
    )
    description: str = Field(..., description="Human-readable explanation of the milestone")
    source_id: Optional[str] = Field(
        default=None,
        description="Linked alert_id, event_id, or note_id",
    )
    severity: str = Field(
        default="medium",
        description="Severity associated with the milestone: low, medium, high, critical, info",
    )
    entities: Dict[str, Any] = Field(
        default_factory=dict,
        description="Entities associated with this milestone",
    )


class AnalystNote(BaseModel):
    """Human analyst investigation note attached to an incident."""

    model_config = ConfigDict(extra="allow")

    note_id: str = Field(..., description="Unique note identifier")
    author: str = Field(..., description="Analyst identifier or username")
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        description="Timestamp note was recorded (UTC ISO-8601)",
    )
    content: str = Field(..., description="Analyst observations and findings")


class DeduplicatedAlert(BaseModel):
    """Aggregated alert record representing one or more alert occurrences with identical fingerprint."""

    model_config = ConfigDict(extra="allow")

    dedup_id: str = Field(..., description="Unique deduplication group identifier")
    fingerprint: str = Field(..., description="Deduplication fingerprint")
    rule_id: str = Field(..., description="Associated detection rule ID")
    rule_name: str = Field(..., description="Human-readable rule name")
    severity: str = Field(..., description="Highest observed severity")
    occurrence_count: int = Field(default=1, ge=1, description="Number of deduplicated alert firings")
    first_seen: str = Field(..., description="Earliest observed timestamp (UTC ISO-8601)")
    last_seen: str = Field(..., description="Most recent observed timestamp (UTC ISO-8601)")
    primary_alert_id: str = Field(..., description="Initial alert ID that seeded the deduplication window")
    contributing_alert_ids: List[str] = Field(
        default_factory=list,
        description="List of all alert IDs collapsed into this aggregate",
    )
    related_event_ids: List[str] = Field(
        default_factory=list,
        description="Deduplicated list of underlying raw event IDs providing evidence",
    )
    entities: Dict[str, Any] = Field(
        default_factory=dict,
        description="Targeted or originating entities",
    )
    explanation: str = Field(..., description="Aggregated narrative explanation")
    supporting_evidence: Dict[str, Any] = Field(
        default_factory=dict,
        description="Merged forensic metrics and failure tallies",
    )
    risk_score: float = Field(
        default=50.0,
        ge=0.0,
        le=100.0,
        description="Calculated risk prioritization score",
    )


class Incident(BaseModel):
    """Correlated security incident uniting related alerts, events, and entities."""

    model_config = ConfigDict(extra="allow", validate_assignment=True)

    incident_id: str = Field(..., description="Unique incident identifier (e.g. inc_<hash>)")
    title: str = Field(..., description="High-level descriptive title")
    severity: str = Field(..., description="Overall incident severity: low, medium, high, critical")
    status: IncidentStatus = Field(default=IncidentStatus.NEW, description="Triage lifecycle state")
    risk_score: float = Field(
        default=50.0,
        ge=0.0,
        le=100.0,
        description="Deterministic risk prioritization score (0 - 100)",
    )
    first_seen: str = Field(..., description="Earliest contributing event timestamp (UTC ISO-8601)")
    last_seen: str = Field(..., description="Latest contributing event timestamp (UTC ISO-8601)")
    entities: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="Consolidated entities: source_ips, usernames, hosts",
    )
    related_alert_ids: List[str] = Field(
        default_factory=list,
        description="IDs of alerts contributing to this incident",
    )
    related_event_ids: List[str] = Field(
        default_factory=list,
        description="IDs of raw events providing forensic evidence",
    )
    distinct_rules: List[str] = Field(
        default_factory=list,
        description="List of distinct rule IDs triggered (e.g. RULE-001, RULE-002)",
    )
    timeline: List[TimelineEntry] = Field(
        default_factory=list,
        description="Chronological event and alert timeline",
    )
    analyst_notes: List[AnalystNote] = Field(
        default_factory=list,
        description="Analyst investigation notes and audit history",
    )
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        description="Incident creation timestamp (UTC ISO-8601)",
    )
    updated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        description="Incident last updated timestamp (UTC ISO-8601)",
    )

    def transition_to(self, new_status: IncidentStatus, analyst: str = "system") -> None:
        """Validate and execute a lifecycle state transition, appending a timeline entry."""
        if new_status == self.status:
            return

        allowed = VALID_TRANSITIONS.get(self.status, set())
        if new_status not in allowed:
            allowed_names = [s.value for s in allowed]
            raise ValueError(
                f"Invalid status transition from {self.status.value} to {new_status.value}. "
                f"Permitted transitions: {allowed_names}"
            )

        old_status = self.status
        self.status = new_status
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.updated_at = now_utc

        # Record timeline milestone
        entry_hasher = hashlib.sha256()
        entry_hasher.update(self.incident_id.encode())
        entry_hasher.update(now_utc.encode())
        entry_hasher.update(new_status.value.encode())
        entry_id = f"tml_{entry_hasher.hexdigest()[:16]}"

        self.timeline.append(
            TimelineEntry(
                entry_id=entry_id,
                timestamp=now_utc,
                entry_type="status_change",
                description=f"Status changed from {old_status.value} to {new_status.value} by {analyst}",
                source_id=self.incident_id,
                severity="info",
                entities={"analyst": analyst},
            )
        )

    def add_note(self, author: str, content: str) -> AnalystNote:
        """Attach an analyst note and record corresponding timeline entry."""
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.updated_at = now_utc

        note_hasher = hashlib.sha256()
        note_hasher.update(self.incident_id.encode())
        note_hasher.update(now_utc.encode())
        note_hasher.update(content.encode())
        note_id = f"not_{note_hasher.hexdigest()[:16]}"

        note = AnalystNote(
            note_id=note_id,
            author=author,
            created_at=now_utc,
            content=content,
        )
        self.analyst_notes.append(note)

        # Also add to timeline
        self.timeline.append(
            TimelineEntry(
                entry_id=f"tml_{note_id}",
                timestamp=now_utc,
                entry_type="note",
                description=f"Analyst note by {author}: {content[:80]}{'...' if len(content) > 80 else ''}",
                source_id=note_id,
                severity="info",
                entities={"author": author},
            )
        )
        return note


class DeduplicationMetrics(BaseModel):
    """Performance metrics reflecting alert volume reduction through deduplication and correlation."""

    total_alerts_received: int = Field(..., description="Total raw alerts submitted to deduplicator")
    deduplicated_alerts_emitted: int = Field(..., description="Alerts remaining after deduplication")
    raw_alert_reduction_count: int = Field(
        ...,
        description="Number of redundant alerts suppressed (received - emitted)",
    )
    deduplication_ratio: float = Field(
        ...,
        description="Alert reduction percentage (0.0 to 1.0, e.g. 0.85 = 85% noise reduction)",
    )
    total_incidents_created: int = Field(
        default=0,
        description="Number of distinct incidents synthesized from correlated alerts",
    )


class IncidentFilter(BaseModel):
    """Query filter parameters for incident search."""

    status: Optional[str] = None
    severity: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    username: Optional[str] = None
    source_ip: Optional[str] = None
    host: Optional[str] = None


class IncidentStatusUpdateRequest(BaseModel):
    """Request payload to modify an incident's triage status."""

    status: IncidentStatus = Field(..., description="Target status: NEW, INVESTIGATING, RESOLVED, CLOSED")
    analyst: str = Field(default="analyst", description="Analyst making the transition")


class AnalystNoteCreateRequest(BaseModel):
    """Request payload to append an analyst note to an incident."""

    author: str = Field(..., min_length=1, description="Analyst username or name")
    content: str = Field(..., min_length=1, description="Investigation findings or notes")


class PaginatedIncidentsResponse(BaseModel):
    """Paginated response containing matching incidents."""

    total: int = Field(..., description="Total count matching query filters")
    limit: int = Field(..., description="Page size limit")
    offset: int = Field(..., description="Page offset")
    incidents: List[Incident] = Field(..., description="List of incidents")


class CorrelateResponse(BaseModel):
    """Response returned upon running alert correlation."""

    raw_alerts_processed: int
    deduplicated_alerts_created: int
    incidents_created_or_updated: int
    deduplication_ratio: float
    incidents: List[Incident]
