"""Unit tests for Central Ingestion health check endpoints."""

import pytest
from fastapi.testclient import TestClient

from backend.api.main import create_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    test_db = tmp_path / "test_health.sqlite"
    from backend.api.dependencies import EventStorageSink
    test_sink = EventStorageSink(db_path=str(test_db))
    monkeypatch.setattr("backend.api.dependencies.storage_sink", test_sink)
    monkeypatch.setattr("backend.api.routes.health.storage_sink", test_sink)

    app = create_app()
    with TestClient(app) as tc:
        yield tc
    test_sink.close()


def test_health_endpoints(client):
    """Verify /health and /api/v1/health endpoints return status ok and database connected."""
    for path in ["/health", "/api/v1/health"]:
        res = client.get(path)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert data["version"] == "0.1.0"
        assert data["database"] == "connected"
        assert data["events_stored"] == 0
        assert data["uptime_seconds"] >= 0.0
