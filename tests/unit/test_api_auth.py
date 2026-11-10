"""Unit tests for Central Ingestion API authentication mechanisms."""

import pytest
from fastapi.testclient import TestClient

from backend.api.config import settings
from backend.api.main import create_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    test_db = tmp_path / "test_auth.sqlite"
    monkeypatch.setattr(settings, "DATABASE_PATH", str(test_db))
    monkeypatch.setattr(settings, "VALID_API_KEYS", {"secret-token-123"})

    # Reinitialize app with patched settings
    from backend.api.dependencies import EventStorageSink, storage_sink
    test_sink = EventStorageSink(db_path=str(test_db))
    monkeypatch.setattr("backend.api.dependencies.storage_sink", test_sink)
    monkeypatch.setattr("backend.api.routes.ingest.storage_sink", test_sink)

    app = create_app()
    with TestClient(app) as tc:
        yield tc
    test_sink.close()


def test_unauthenticated_request_rejected(client):
    """Requests without authentication headers must be rejected with HTTP 401."""
    res = client.post("/api/v1/ingest", json=[])
    assert res.status_code == 401
    assert "Unauthorized" in res.json()["detail"]


def test_invalid_api_key_rejected(client):
    """Requests with wrong credentials must return HTTP 401."""
    res = client.post(
        "/api/v1/ingest",
        json=[],
        headers={"X-API-Key": "incorrect-secret-key"},
    )
    assert res.status_code == 401


def test_valid_x_api_key_accepted(client):
    """Requests with correct X-API-Key header pass authentication."""
    event_payload = {
        "schema_version": "1.0",
        "event_id": "evt_auth_test_1",
        "timestamp": "2026-10-15T00:00:00Z",
        "observed_at": "2026-10-15T00:00:01Z",
        "source_host": "kali",
        "source_type": "linux_auth",
        "event_type": "authentication_success",
        "raw_event": "raw auth test",
    }
    res = client.post(
        "/api/v1/ingest",
        json=event_payload,
        headers={"X-API-Key": "secret-token-123"},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "success"
    assert res.json()["ingested_count"] == 1


def test_valid_bearer_token_accepted(client):
    """Requests with valid Bearer token pass authentication."""
    event_payload = {
        "schema_version": "1.0",
        "event_id": "evt_auth_test_2",
        "timestamp": "2026-10-15T00:00:00Z",
        "observed_at": "2026-10-15T00:00:01Z",
        "source_host": "win-srv",
        "source_type": "windows_security",
        "event_type": "authentication_failure",
        "raw_event": "raw bearer test",
    }
    res = client.post(
        "/api/v1/ingest",
        json=event_payload,
        headers={"Authorization": "Bearer secret-token-123"},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "success"
    assert res.json()["ingested_count"] == 1
