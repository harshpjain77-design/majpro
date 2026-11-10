"""End-to-End integration test for the Kali Linux log collection, ingestion, detection, and correlation pipeline.

Simulates the full lifecycle:
1. Raw Linux /var/log/auth.log parsing
2. Batch event shipping over HTTP/FastAPI
3. SQLite repository persistence and verification
4. Deterministic threat detection (RULE-001 Brute Force & RULE-002 Failed Followed By Success)
5. Incident correlation, deduplication, and lifecycle state
"""

import pytest
from fastapi.testclient import TestClient

from backend.api.config import settings
from backend.api.dependencies import EventStorageSink, IncidentRepository
from backend.api.main import create_app
from collectors.common.schemas import SecurityEvent
from collectors.linux.parsers import parse_linux_auth_line


@pytest.fixture
def e2e_client(tmp_path, monkeypatch):
    """Set up an isolated database and test client for end-to-end verification."""
    test_db = tmp_path / "e2e_soc.sqlite"
    api_key = "kali-e2e-test-key"

    monkeypatch.setattr(settings, "DATABASE_PATH", str(test_db))
    monkeypatch.setattr(settings, "VALID_API_KEYS", {api_key})
    monkeypatch.setattr(settings, "MAX_BATCH_SIZE", 100)

    test_sink = EventStorageSink(db_path=str(test_db))
    test_incidents = IncidentRepository(db_path=str(test_db))

    monkeypatch.setattr("backend.api.dependencies.storage_sink", test_sink)
    monkeypatch.setattr("backend.api.dependencies.incident_repo", test_incidents)
    monkeypatch.setattr("backend.api.routes.ingest.storage_sink", test_sink)
    monkeypatch.setattr("backend.api.routes.events.storage_sink", test_sink)
    monkeypatch.setattr("backend.api.routes.alerts.storage_sink", test_sink)
    monkeypatch.setattr("backend.api.routes.incidents.storage_sink", test_sink)
    monkeypatch.setattr("backend.api.routes.incidents.incident_repo", test_incidents)

    app = create_app()
    with TestClient(app) as tc:
        yield tc, api_key

    test_sink.close()


def test_kali_collector_to_incident_full_pipeline(e2e_client):
    client, api_key = e2e_client
    headers = {
        "X-API-Key": api_key,
        "X-Agent-ID": "kali-collector-agent-01",
        "X-Agent-Version": "0.1.0",
    }

    # Step 1: Raw auth.log lines simulating an attack from 198.51.100.42 targeting admin
    raw_lines = [
        "Oct 20 14:00:01 kali-victim sshd[30101]: Failed password for admin from 198.51.100.42 port 44101 ssh2\n",
        "Oct 20 14:00:15 kali-victim sshd[30102]: Failed password for admin from 198.51.100.42 port 44102 ssh2\n",
        "Oct 20 14:00:30 kali-victim sshd[30103]: Failed password for admin from 198.51.100.42 port 44103 ssh2\n",
        "Oct 20 14:00:45 kali-victim sshd[30104]: Failed password for admin from 198.51.100.42 port 44104 ssh2\n",
        "Oct 20 14:01:00 kali-victim sshd[30105]: Failed password for admin from 198.51.100.42 port 44105 ssh2\n",
        "Oct 20 14:01:20 kali-victim sshd[30106]: Accepted password for admin from 198.51.100.42 port 44106 ssh2\n",
    ]

    # Step 2: Parse raw lines using the Kali Linux parser
    parsed_events = []
    for line in raw_lines:
        ev = parse_linux_auth_line(
            raw_line=line,
            default_host="kali-victim",
            collector_version="0.1.0",
        )
        assert ev is not None
        assert isinstance(ev, SecurityEvent)
        parsed_events.append(ev)

    assert len(parsed_events) == 6
    assert parsed_events[0].username == "admin"
    assert parsed_events[0].source_ip == "198.51.100.42"
    assert parsed_events[0].event_type == "authentication_failure"
    assert parsed_events[5].event_type == "authentication_success"

    # Step 3: Ingest batch via POST /api/v1/events/batch
    batch_payload = {
        "events": [e.model_dump(mode="json") for e in parsed_events],
        "agent_id": "kali-collector-agent-01",
        "collector_version": "0.1.0",
    }

    ingest_res = client.post("/api/v1/events/batch", json=batch_payload, headers=headers)
    assert ingest_res.status_code == 200, f"Ingest failed: {ingest_res.text}"
    ingest_data = ingest_res.json()
    assert ingest_data["status"] == "success"
    assert ingest_data["ingested_count"] == 6
    assert ingest_data["duplicate_count"] == 0

    # Verify idempotency: re-sending the same batch yields duplicate_count == 6
    reingest_res = client.post("/api/v1/events/batch", json=batch_payload, headers=headers)
    assert reingest_res.status_code == 200
    reingest_data = reingest_res.json()
    assert reingest_data["ingested_count"] == 0
    assert reingest_data["duplicate_count"] == 6

    # Step 4: Verify storage via GET /api/v1/events
    events_res = client.get("/api/v1/events?limit=50", headers=headers)
    assert events_res.status_code == 200
    events_data = events_res.json()
    assert len(events_data["events"]) == 6
    assert events_data["total"] == 6

    # Step 5: Verify detection engine generated alerts via GET /api/v1/alerts
    alerts_res = client.get("/api/v1/alerts", headers=headers)
    assert alerts_res.status_code == 200
    alerts = alerts_res.json()
    assert len(alerts) >= 2

    rule_ids = {a["rule_id"] for a in alerts}
    assert "RULE-001" in rule_ids, "Single source brute force rule should have fired"
    assert "RULE-002" in rule_ids, "Failed followed by success rule should have fired"

    # Verify alert fields
    rule_001_alert = next(a for a in alerts if a["rule_id"] == "RULE-001")
    assert rule_001_alert["entities"]["source_ip"] == "198.51.100.42"
    assert len(rule_001_alert["related_event_ids"]) == 5

    rule_002_alert = next(a for a in alerts if a["rule_id"] == "RULE-002")
    assert rule_002_alert["entities"]["username"] == "admin"

    # Step 6: Correlate into incidents via POST /api/v1/incidents/correlate
    correlate_res = client.post("/api/v1/incidents/correlate", headers=headers)
    assert correlate_res.status_code == 200
    corr_data = correlate_res.json()
    assert corr_data["raw_alerts_processed"] >= 2
    assert corr_data["incidents_created_or_updated"] >= 1

    # Step 7: Verify incident retrieval via GET /api/v1/incidents
    incidents_res = client.get("/api/v1/incidents", headers=headers)
    assert incidents_res.status_code == 200
    inc_data = incidents_res.json()
    assert inc_data["total"] >= 1
    incident = inc_data["incidents"][0]

    assert incident["status"] == "NEW"
    entity_ips = incident["entities"].get("source_ips", [])
    entity_users = incident["entities"].get("usernames", [])
    assert "198.51.100.42" in entity_ips or "admin" in entity_users
    assert incident["risk_score"] > 0

    # Step 8: Verify detailed incident fetch with timeline via GET /api/v1/incidents/{id}
    inc_id = incident["incident_id"]
    detail_res = client.get(f"/api/v1/incidents/{inc_id}", headers=headers)
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["incident_id"] == inc_id
    assert len(detail["timeline"]) >= 1
    assert len(detail["related_alert_ids"]) >= 1
