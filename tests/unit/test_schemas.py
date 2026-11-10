"""Unit tests for canonical SecurityEvent schema validation."""

import json
import pytest
from pydantic import ValidationError

from collectors.common.schemas import EventType, SecurityEvent, Severity


def test_valid_security_event():
    """Verify that a compliant event dictionary instantiates and serializes correctly."""
    event = SecurityEvent(
        schema_version="1.0",
        event_id="evt_test1234567890abcdef",
        timestamp="2026-10-14T22:00:00Z",
        observed_at="2026-10-14T22:00:01Z",
        source_host="kali-target",
        source_type="linux_auth",
        event_type=EventType.AUTHENTICATION_FAILURE.value,
        username="admin",
        source_ip="192.168.1.100",
        destination_ip=None,
        windows_event_id=None,
        severity=Severity.MEDIUM.value,
        raw_event="Failed password for invalid user admin from 192.168.1.100 port 45000 ssh2",
        collector_version="0.1.0",
        metadata={"port": 45000, "is_invalid_user": True},
    )

    assert event.schema_version == "1.0"
    assert event.event_id == "evt_test1234567890abcdef"
    assert event.username == "admin"
    assert event.severity == "medium"
    assert event.metadata["port"] == 45000

    # Test JSONL serialization
    jsonl = event.to_jsonl()
    assert isinstance(jsonl, str)
    decoded = json.loads(jsonl)
    assert decoded["event_id"] == "evt_test1234567890abcdef"
    assert decoded["source_ip"] == "192.168.1.100"
    assert decoded["destination_ip"] is None


def test_reject_empty_required_fields():
    """Verify that blank or empty required fields raise a validation error."""
    with pytest.raises(ValidationError):
        SecurityEvent(
            schema_version="1.0",
            event_id="   ",  # Invalid empty ID
            timestamp="2026-10-14T22:00:00Z",
            observed_at="2026-10-14T22:00:01Z",
            source_host="host1",
            source_type="linux_auth",
            event_type="test",
            raw_event="some raw event",
        )


def test_severity_normalization():
    """Verify that non-standard severity strings fallback gracefully to informational."""
    event = SecurityEvent(
        schema_version="1.0",
        event_id="evt_valid123",
        timestamp="2026-10-14T22:00:00Z",
        observed_at="2026-10-14T22:00:01Z",
        source_host="host1",
        source_type="linux_auth",
        event_type="test",
        raw_event="some raw event",
        severity="NON_STANDARD_SEVERITY_LEVEL",
    )
    assert event.severity == Severity.INFORMATIONAL.value


def test_null_missing_values_allowed():
    """Verify that optional attributes default safely to None without errors."""
    event = SecurityEvent(
        schema_version="1.0",
        event_id="evt_minimal123",
        timestamp="2026-10-14T22:00:00Z",
        observed_at="2026-10-14T22:00:01Z",
        source_host="host1",
        source_type="windows_security",
        event_type="unknown",
        raw_event="minimal raw event",
    )
    assert event.username is None
    assert event.source_ip is None
    assert event.destination_ip is None
    assert event.windows_event_id is None
    assert event.metadata == {}
