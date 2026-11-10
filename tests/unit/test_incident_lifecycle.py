"""Unit tests for Incident lifecycle state machine, analyst notes, and persistence."""

import os
import tempfile
import pytest

from backend.correlation.repository import IncidentRepository
from backend.correlation.schemas import Incident, IncidentStatus, TimelineEntry


def create_base_incident(incident_id: str = "inc_test_001") -> Incident:
    """Helper creating a valid base Incident object."""
    return Incident(
        incident_id=incident_id,
        title="Test Security Incident",
        severity="high",
        status=IncidentStatus.NEW,
        risk_score=75.0,
        first_seen="2026-10-15T01:00:00Z",
        last_seen="2026-10-15T01:30:00Z",
        entities={"source_ips": ["192.168.1.10"], "usernames": ["admin"], "hosts": ["srv1"]},
        related_alert_ids=["alt_001", "alt_002"],
        related_event_ids=["evt_001", "evt_002"],
        distinct_rules=["RULE-001", "RULE-002"],
        timeline=[
            TimelineEntry(
                entry_id="tml_001",
                timestamp="2026-10-15T01:00:00Z",
                entry_type="alert",
                description="Brute force alert",
                source_id="alt_001",
                severity="medium",
            )
        ],
        analyst_notes=[],
        created_at="2026-10-15T01:30:00Z",
        updated_at="2026-10-15T01:30:00Z",
    )


def test_incident_valid_status_transitions():
    """Verify standard lifecycle transitions: NEW -> INVESTIGATING -> RESOLVED -> CLOSED."""
    inc = create_base_incident()
    assert inc.status == IncidentStatus.NEW

    # Transition: NEW -> INVESTIGATING
    inc.transition_to(IncidentStatus.INVESTIGATING, analyst="analyst_alice")
    assert inc.status == IncidentStatus.INVESTIGATING
    assert len(inc.timeline) == 2
    assert inc.timeline[-1].entry_type == "status_change"
    assert "analyst_alice" in inc.timeline[-1].description

    # Transition: INVESTIGATING -> RESOLVED
    inc.transition_to(IncidentStatus.RESOLVED, analyst="analyst_alice")
    assert inc.status == IncidentStatus.RESOLVED
    assert len(inc.timeline) == 3

    # Transition: RESOLVED -> CLOSED
    inc.transition_to(IncidentStatus.CLOSED, analyst="analyst_alice")
    assert inc.status == IncidentStatus.CLOSED
    assert len(inc.timeline) == 4

    # Reopening: CLOSED -> INVESTIGATING
    inc.transition_to(IncidentStatus.INVESTIGATING, analyst="lead_bob")
    assert inc.status == IncidentStatus.INVESTIGATING
    assert len(inc.timeline) == 5


def test_incident_invalid_status_transitions():
    """Verify prohibited transitions raise ValueError."""
    inc = create_base_incident()

    # Prohibited: NEW -> RESOLVED directly without investigation
    with pytest.raises(ValueError, match="Invalid status transition"):
        inc.transition_to(IncidentStatus.RESOLVED)

    # Move to CLOSED
    inc.transition_to(IncidentStatus.CLOSED)

    # Prohibited: CLOSED -> RESOLVED directly
    with pytest.raises(ValueError, match="Invalid status transition"):
        inc.transition_to(IncidentStatus.RESOLVED)


def test_incident_add_note():
    """Adding an analyst note appends to notes list and timeline."""
    inc = create_base_incident()

    note = inc.add_note(
        author="sec_analyst_1",
        content="Host isolated from network; credential revoked.",
    )

    assert len(inc.analyst_notes) == 1
    assert inc.analyst_notes[0].author == "sec_analyst_1"
    assert "Host isolated" in inc.analyst_notes[0].content

    # Check timeline reflection
    assert len(inc.timeline) == 2
    assert inc.timeline[-1].entry_type == "note"
    assert inc.timeline[-1].source_id == note.note_id


def test_incident_repository_crud():
    """Test full persistent SQLite CRUD operations for incidents."""
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tmp:
        db_path = tmp.name

    try:
        repo = IncidentRepository(db_path=db_path)
        inc = create_base_incident("inc_repo_test")

        # 1. Save incident
        repo.save_incident(inc)

        # 2. Get incident by ID
        fetched = repo.get_incident("inc_repo_test")
        assert fetched is not None
        assert fetched.incident_id == "inc_repo_test"
        assert fetched.title == inc.title
        assert fetched.status == IncidentStatus.NEW
        assert fetched.risk_score == 75.0
        assert len(fetched.timeline) == 1
        assert fetched.entities["usernames"] == ["admin"]

        # 3. Add note via repository
        note = repo.add_note("inc_repo_test", "analyst_carol", "Confirmed true positive SSH brute force.")
        assert note.author == "analyst_carol"

        # 4. Update status via repository
        updated = repo.update_status("inc_repo_test", IncidentStatus.INVESTIGATING, analyst="analyst_carol")
        assert updated.status == IncidentStatus.INVESTIGATING

        # 5. Fetch updated record
        refetched = repo.get_incident("inc_repo_test")
        assert refetched.status == IncidentStatus.INVESTIGATING
        assert len(refetched.analyst_notes) == 1
        assert len(refetched.timeline) == 3  # Initial alert + note + status_change

        # 6. List incidents with filtering
        incidents, total = repo.list_incidents(status="INVESTIGATING", severity="high")
        assert total == 1
        assert len(incidents) == 1
        assert incidents[0].incident_id == "inc_repo_test"

        # List with non-matching filter
        empty_list, empty_total = repo.list_incidents(status="CLOSED")
        assert empty_total == 0
        assert len(empty_list) == 0

    finally:
        repo.close()
        if os.path.exists(db_path):
            os.remove(db_path)
