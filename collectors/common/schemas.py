"""Canonical event schema definitions for AI Cyber Defense Platform."""

from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


class Severity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(str, Enum):
    AUTHENTICATION_SUCCESS = "authentication_success"
    AUTHENTICATION_FAILURE = "authentication_failure"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SESSION_LOGOFF = "session_logoff"
    ACCOUNT_LOCKOUT = "account_lockout"
    ACCOUNT_CREATED = "account_created"
    ACCOUNT_DELETED = "account_deleted"
    SERVICE_EVENT = "service_event"
    UNKNOWN = "unknown"


class SecurityEvent(BaseModel):
    """Canonical normalized security event schema conforming to specification v1.0."""

    model_config = ConfigDict(
        extra="allow",
        populate_by_name=True,
        validate_assignment=True,
    )

    schema_version: str = Field(default="1.0", description="Schema specification version")
    event_id: str = Field(
        ...,
        description="Deterministic unique event fingerprint or deduplication identifier",
    )
    timestamp: str = Field(
        ...,
        description="Event generation timestamp in UTC ISO-8601 format (YYYY-MM-DDTHH:MM:SSZ)",
    )
    observed_at: str = Field(
        ...,
        description="Collector ingestion observation timestamp in UTC ISO-8601 format",
    )
    source_host: str = Field(
        ...,
        description="Hostname or FQDN where the event was recorded",
    )
    source_type: str = Field(
        ...,
        description="Log source category, e.g. linux_auth, systemd_journal, windows_security",
    )
    event_type: str = Field(
        ...,
        description="Normalized category of the security event",
    )
    username: Optional[str] = Field(
        default=None,
        description="Subject or target account username, or null if unauthenticated/missing",
    )
    source_ip: Optional[str] = Field(
        default=None,
        description="Originating source IPv4 or IPv6 address, or null",
    )
    destination_ip: Optional[str] = Field(
        default=None,
        description="Target destination IPv4 or IPv6 address, or null",
    )
    windows_event_id: Optional[int] = Field(
        default=None,
        description="Windows Security Event ID (e.g. 4624, 4625, 4672) if applicable",
    )
    severity: str = Field(
        default=Severity.INFORMATIONAL.value,
        description="Normalized severity: informational, low, medium, high, critical",
    )
    raw_event: str = Field(
        ...,
        description="Original unmodified raw log text, syslog line, or Windows event XML",
    )
    collector_version: str = Field(
        default="0.1.0",
        description="Version string of the emitting collector agent",
    )
    metadata: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Optional auxiliary structured attributes (e.g. logon_type, record_number)",
    )
    ingested_at: Optional[str] = Field(
        default=None,
        description="Authoritative SIEM arrival timestamp in UTC ISO-8601",
    )

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        valid = {s.value for s in Severity}
        if v.lower() not in valid:
            return Severity.INFORMATIONAL.value
        return v.lower()

    @field_validator("event_id", "source_host", "source_type", "event_type", "raw_event")
    @classmethod
    def validate_non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Field cannot be empty or blank")
        return v

    def to_jsonl(self) -> str:
        """Serialize event to a single-line compact JSON string."""
        return self.model_dump_json(exclude_none=False)
