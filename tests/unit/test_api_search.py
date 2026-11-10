"""Unit tests for the event search, retrieval, and aggregation API endpoints."""

import pytest
from fastapi.testclient import TestClient

from backend.api.config import settings
from backend.api.main import create_app
from backend.storage.sqlite_repository import SQLiteEventRepository
from collectors.common.schemas import EventType, SecurityEvent, Severity


@pytest.fixture
def client_with_data(tmp_path, monkeypatch):
    test_db = tmp_path / "test_api_search.sqlite"
    monkeypatch.setattr(settings, "DATABASE_PATH", str(test_db))
    monkeypatch.setattr(settings, "VALID_API_KEYS", {"search-key-123"})

    test_sink = SQLiteEventRepository(db_path=str(test_db))
    monkeypatch.setattr("backend.api.dependencies.storage_sink", test_sink)
    monkeypatch.setattr("backend.api.routes.ingest.storage_sink", test_sink)
    monkeypatch.setattr("backend.api.routes.events.storage_sink", test_sink)
    monkeypatch.setattr("backend.api.routes.health.storage_sink", test_sink)

    # Populate sample events
    events = [
        SecurityEvent(
            schema_version="1.0",
            event_id="e_api_1",
            timestamp="2026-10-15T10:00:00Z",
            observed_at="2026-10-15T10:00:01Z",
            source_host="kali-box",
            source_type="linux_auth",
            event_type=EventType.AUTHENTICATION_SUCCESS.value,
            username="analyst1",
            source_ip="192.168.1.50",
            severity=Severity.LOW.value,
            raw_event="Accepted password for analyst1",
            collector_version="0.1.0",
        ),
        SecurityEvent(
            schema_version="1.0",
            event_id="e_api_2",
            timestamp="2026-10-15T11:00:00Z",
            observed_at="2026-10-15T11:00:01Z",
            source_host="win-server",
            source_type="windows_security",
            event_type=EventType.AUTHENTICATION_FAILURE.value,
            username="admin",
            source_ip="10.0.0.99",
            severity=Severity.HIGH.value,
            raw_event="EventID 4625 Logon Failure",
            collector_version="0.1.0",
        ),
    ]
    test_sink.insert_batch(events)

    app = create_app()
    with TestClient(app) as tc:
        yield tc
    test_sink.close()


def test_search_unauthenticated_rejected(client_with_data):
    res = client_with_data.get("/api/v1/events")
    assert res.status_code == 401


def test_search_all_events(client_with_data):
    headers = {"X-API-Key": "search-key-123"}
    res = client_with_data.get("/api/v1/events", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 2
    assert len(data["events"]) == 2
    assert data["has_more"] is False


def test_search_with_filtering(client_with_data):
    headers = {"X-API-Key": "search-key-123"}

    # Filter by username
    res = client_with_data.get("/api/v1/events?username=admin", headers=headers)
    assert res.status_code == 200
    assert res.json()["total"] == 1
    assert res.json()["events"][0]["event_id"] == "e_api_2"

    # Filter by source_host
    res = client_with_data.get("/api/v1/events?host=kali-box", headers=headers)
    assert res.status_code == 200
    assert res.json()["total"] == 1
    assert res.json()["events"][0]["event_id"] == "e_api_1"

    # Free-text search term in raw_event
    res = client_with_data.get("/api/v1/events?q=4625", headers=headers)
    assert res.status_code == 200
    assert res.json()["total"] == 1
    assert res.json()["events"][0]["event_id"] == "e_api_2"


def test_search_pagination_validation(client_with_data):
    headers = {"X-API-Key": "search-key-123"}

    # Invalid limit < 1
    res = client_with_data.get("/api/v1/events?limit=0", headers=headers)
    assert res.status_code == 422

    # Invalid negative offset
    res = client_with_data.get("/api/v1/events?offset=-1", headers=headers)
    assert res.status_code == 422


def test_get_event_by_id(client_with_data):
    headers = {"X-API-Key": "search-key-123"}

    # Found
    res = client_with_data.get("/api/v1/events/e_api_1", headers=headers)
    assert res.status_code == 200
    assert res.json()["event_id"] == "e_api_1"
    assert res.json()["username"] == "analyst1"

    # Not found -> 404
    res_404 = client_with_data.get("/api/v1/events/nonexistent_id", headers=headers)
    assert res_404.status_code == 404
    assert "not found" in res_404.json()["detail"].lower()


def test_get_raw_event_endpoint(client_with_data):
    headers = {"X-API-Key": "search-key-123"}

    res = client_with_data.get("/api/v1/events/e_api_2/raw", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["event_id"] == "e_api_2"
    assert "Logon Failure" in data["raw_event"]

    # 404 on missing
    res_404 = client_with_data.get("/api/v1/events/missing_raw/raw", headers=headers)
    assert res_404.status_code == 404


def test_get_summary_counts_endpoint(client_with_data):
    headers = {"X-API-Key": "search-key-123"}

    res = client_with_data.get("/api/v1/events/summary/counts", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["total_events"] == 2
    assert "low" in data["by_severity"]
    assert "high" in data["by_severity"]
    assert len(data["time_series"]) >= 1
