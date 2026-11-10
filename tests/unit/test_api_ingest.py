"""Unit tests for Central Ingestion event submission, validation, and deduplication."""

import pytest
from fastapi.testclient import TestClient

from backend.api.config import settings
from backend.api.main import create_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    test_db = tmp_path / "test_ingest.sqlite"
    monkeypatch.setattr(settings, "DATABASE_PATH", str(test_db))
    monkeypatch.setattr(settings, "VALID_API_KEYS", {"valid-key-xyz"})
    monkeypatch.setattr(settings, "MAX_BATCH_SIZE", 10)

    from backend.api.dependencies import EventStorageSink
    test_sink = EventStorageSink(db_path=str(test_db))
    monkeypatch.setattr("backend.api.dependencies.storage_sink", test_sink)
    monkeypatch.setattr("backend.api.routes.ingest.storage_sink", test_sink)

    app = create_app()
    with TestClient(app) as tc:
        yield tc
    test_sink.close()


def _valid_event(event_id: str = "evt_sample_1", user: str = "alice") -> dict:
    return {
        "schema_version": "1.0",
        "event_id": event_id,
        "timestamp": "2026-10-15T00:00:00Z",
        "observed_at": "2026-10-15T00:00:01Z",
        "source_host": "kali-host",
        "source_type": "linux_auth",
        "event_type": "authentication_success",
        "username": user,
        "source_ip": "192.168.1.50",
        "raw_event": f"Accepted password for {user}",
        "collector_version": "0.1.0",
    }


def test_ingest_single_event(client):
    headers = {"X-API-Key": "valid-key-xyz", "X-Agent-ID": "kali-collector-01"}
    res = client.post("/api/v1/ingest", json=_valid_event("evt_single_1"), headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["ingested_count"] == 1
    assert data["duplicate_count"] == 0
    assert data["event_ids"] == ["evt_single_1"]


def test_ingest_duplicate_event(client):
    headers = {"X-API-Key": "valid-key-xyz"}
    ev = _valid_event("evt_dup_test")

    # Ingest first time: 1 ingested
    res1 = client.post("/api/v1/ingest", json=ev, headers=headers)
    assert res1.status_code == 200
    assert res1.json()["ingested_count"] == 1

    # Ingest second time: 0 ingested, 1 duplicate
    res2 = client.post("/api/v1/ingest", json=ev, headers=headers)
    assert res2.status_code == 200
    assert res2.json()["ingested_count"] == 0
    assert res2.json()["duplicate_count"] == 1


def test_ingest_batch_endpoint(client):
    headers = {"X-API-Key": "valid-key-xyz"}
    batch = {
        "events": [_valid_event(f"evt_batch_{i}") for i in range(3)],
        "agent_id": "win-agent-01",
    }
    res = client.post("/api/v1/ingest/batch", json=batch, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["ingested_count"] == 3
    assert data["duplicate_count"] == 0
    assert len(data["event_ids"]) == 3


def test_ingest_empty_batch_rejected(client):
    headers = {"X-API-Key": "valid-key-xyz"}
    res = client.post("/api/v1/ingest", json=[], headers=headers)
    assert res.status_code == 400
    assert "Payload contains zero events" in res.json()["detail"]


def test_ingest_batch_size_limit_exceeded(client):
    headers = {"X-API-Key": "valid-key-xyz"}
    # Limit is 10 in fixture
    batch = [_valid_event(f"evt_overflow_{i}") for i in range(12)]
    res = client.post("/api/v1/ingest", json=batch, headers=headers)
    assert res.status_code == 400
    assert "exceeds maximum permitted" in res.json()["detail"]


def test_ingest_malformed_schema_validation(client):
    headers = {"X-API-Key": "valid-key-xyz"}
    # Missing required 'raw_event' and 'source_host'
    malformed = {
        "schema_version": "1.0",
        "event_id": "evt_malformed_1",
        "timestamp": "2026-10-15T00:00:00Z",
        "observed_at": "2026-10-15T00:00:01Z",
        "event_type": "authentication_success",
    }
    res = client.post("/api/v1/ingest", json=malformed, headers=headers)
    assert res.status_code == 422
    data = res.json()
    assert data["status"] == "error"
    assert "errors" in data
    assert any("source_host" in err for err in data["errors"])
