"""Integration tests for Incident and Deduplication REST API endpoints."""

import os
import tempfile
import pytest
from fastapi.testclient import TestClient

from backend.api.config import settings
from backend.api.dependencies import incident_repo, storage_sink
from backend.api.main import app
from backend.correlation.schemas import Incident, IncidentStatus, TimelineEntry

VALID_KEY = next(iter(settings.VALID_API_KEYS))
AUTH_HEADERS = {"X-API-Key": VALID_KEY}


@pytest.fixture(autouse=True)
def isolated_incident_db():
    """Ensure clean temporary SQLite database for incidents in each test."""
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tmp:
        db_path = tmp.name

    original_db_path = incident_repo.db_path
    original_sink_db = storage_sink.db_path

    incident_repo.db_path = db_path
    incident_repo._conn = None
    incident_repo._init_db()

    storage_sink.db_path = db_path
    storage_sink._conn = None
    storage_sink._init_db()

    yield

    if incident_repo._conn:
        incident_repo._conn.close()
        incident_repo._conn = None
    if storage_sink._conn:
        storage_sink._conn.close()
        storage_sink._conn = None

    incident_repo.db_path = original_db_path
    storage_sink.db_path = original_sink_db

    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except Exception:
            pass


def test_incidents_api_unauthenticated_rejected():
    """Unauthenticated requests must receive HTTP 401 Unauthorized."""
    client = TestClient(app)
    resp = client.get("/api/v1/incidents")
    assert resp.status_code == 401


def test_incidents_api_list_and_get():
    """Test listing incidents and retrieving single incident with timeline."""
    client = TestClient(app)

    # Seed an incident into the repo
    inc = Incident(
        incident_id="inc_api_001",
        title="API Test Incident",
        severity="high",
        status=IncidentStatus.NEW,
        risk_score=70.0,
        first_seen="2026-10-15T01:00:00Z",
        last_seen="2026-10-15T01:15:00Z",
        entities={"source_ips": ["192.168.1.55"], "usernames": ["alice"], "hosts": ["web-srv"]},
        related_alert_ids=["alt_001"],
        related_event_ids=["evt_001"],
        distinct_rules=["RULE-001"],
        timeline=[
            TimelineEntry(
                entry_id="tml_001",
                timestamp="2026-10-15T01:00:00Z",
                entry_type="alert",
                description="Brute force alert",
                severity="medium",
            )
        ],
        analyst_notes=[],
        created_at="2026-10-15T01:15:00Z",
        updated_at="2026-10-15T01:15:00Z",
    )
    incident_repo.save_incident(inc)

    # 1. List incidents
    resp = client.get("/api/v1/incidents", headers=AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["incidents"][0]["incident_id"] == "inc_api_001"

    # Filter by non-existent status
    resp_filtered = client.get("/api/v1/incidents?status=CLOSED", headers=AUTH_HEADERS)
    assert resp_filtered.json()["total"] == 0

    # 2. Get specific incident
    resp_get = client.get("/api/v1/incidents/inc_api_001", headers=AUTH_HEADERS)
    assert resp_get.status_code == 200
    inc_data = resp_get.json()
    assert inc_data["incident_id"] == "inc_api_001"
    assert len(inc_data["timeline"]) == 1

    # 3. Get non-existent incident
    resp_404 = client.get("/api/v1/incidents/inc_nonexistent", headers=AUTH_HEADERS)
    assert resp_404.status_code == 404


def test_incidents_api_status_update_and_notes():
    """Test updating status and appending analyst notes via API."""
    client = TestClient(app)

    inc = Incident(
        incident_id="inc_status_test",
        title="Status Transition Test",
        severity="medium",
        status=IncidentStatus.NEW,
        risk_score=50.0,
        first_seen="2026-10-15T02:00:00Z",
        last_seen="2026-10-15T02:10:00Z",
        entities={"source_ips": ["10.0.0.99"], "usernames": ["bob"], "hosts": ["srv2"]},
        related_alert_ids=["alt_002"],
        related_event_ids=["evt_002"],
        distinct_rules=["RULE-001"],
        timeline=[],
        analyst_notes=[],
        created_at="2026-10-15T02:10:00Z",
        updated_at="2026-10-15T02:10:00Z",
    )
    incident_repo.save_incident(inc)

    # 1. Valid status transition: NEW -> INVESTIGATING
    resp_patch = client.patch(
        "/api/v1/incidents/inc_status_test/status",
        headers=AUTH_HEADERS,
        json={"status": "INVESTIGATING", "analyst": "triage_analyst"},
    )
    assert resp_patch.status_code == 200
    assert resp_patch.json()["status"] == "INVESTIGATING"

    # 2. Invalid status transition: INVESTIGATING -> INVALID_STATE
    resp_bad = client.patch(
        "/api/v1/incidents/inc_status_test/status",
        headers=AUTH_HEADERS,
        json={"status": "UNKNOWN_STATUS"},
    )
    assert resp_bad.status_code == 422  # Pydantic enum validation failure

    # 3. Add analyst note
    resp_note = client.post(
        "/api/v1/incidents/inc_status_test/notes",
        headers=AUTH_HEADERS,
        json={"author": "analyst_alice", "content": "Confirmed brute-force scanner; blocked source IP."},
    )
    assert resp_note.status_code == 201
    note_data = resp_note.json()
    assert note_data["author"] == "analyst_alice"
    assert "Confirmed brute-force" in note_data["content"]

    # Verify timeline reflects the status update and note
    resp_get = client.get("/api/v1/incidents/inc_status_test", headers=AUTH_HEADERS)
    timeline = resp_get.json()["timeline"]
    assert len(timeline) == 2
    types = [t["entry_type"] for t in timeline]
    assert "status_change" in types
    assert "note" in types


def test_incidents_api_correlate_and_metrics():
    """Test correlation trigger endpoint and deduplication metrics retrieval."""
    client = TestClient(app)

    # Ingest 5 failed logon events from same IP to trigger RULE-001
    events = [
        {
            "schema_version": "1.0",
            "event_id": f"evt_corr_test_{i}",
            "timestamp": f"2026-10-15T03:{i:02d}:00Z",
            "observed_at": f"2026-10-15T03:{i:02d}:01Z",
            "source_host": "kali-target",
            "source_type": "linux_auth",
            "event_type": "authentication_failure",
            "username": "root",
            "source_ip": "192.168.1.180",
            "severity": "medium",
            "raw_event": f"Oct 15 03:{i:02d}:00 kali-target sshd: Failed password for root from 192.168.1.180",
        }
        for i in range(5)
    ]
    resp_ingest = client.post("/api/v1/ingest/batch", headers=AUTH_HEADERS, json={"events": events})
    assert resp_ingest.status_code == 200

    # Trigger correlation
    resp_corr = client.post("/api/v1/incidents/correlate", headers=AUTH_HEADERS)
    assert resp_corr.status_code == 200
    corr_data = resp_corr.json()
    assert corr_data["raw_alerts_processed"] >= 1
    assert corr_data["incidents_created_or_updated"] >= 1
    assert len(corr_data["incidents"]) >= 1

    # Check deduplication metrics
    resp_metrics = client.get("/api/v1/incidents/metrics/deduplication", headers=AUTH_HEADERS)
    assert resp_metrics.status_code == 200
    metrics = resp_metrics.json()
    assert metrics["total_alerts_received"] >= 1
    assert metrics["total_incidents_created"] >= 1
