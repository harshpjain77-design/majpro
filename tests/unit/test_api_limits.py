"""Unit tests for request payload size limits and rate limiting."""

import pytest
from fastapi.testclient import TestClient

from backend.api.config import settings
from backend.api.dependencies import rate_limiter
from backend.api.main import create_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    test_db = tmp_path / "test_limits.sqlite"
    monkeypatch.setattr(settings, "DATABASE_PATH", str(test_db))
    monkeypatch.setattr(settings, "VALID_API_KEYS", {"limit-key-123"})
    # Set tight limits for testing
    monkeypatch.setattr(settings, "MAX_REQUEST_BYTES", 1024)  # 1 KB limit
    monkeypatch.setattr(rate_limiter, "limit", 3)  # 3 requests allowed
    monkeypatch.setattr(rate_limiter, "window_seconds", 60)
    rate_limiter.reset()

    from backend.api.dependencies import EventStorageSink
    test_sink = EventStorageSink(db_path=str(test_db))
    monkeypatch.setattr("backend.api.dependencies.storage_sink", test_sink)
    monkeypatch.setattr("backend.api.routes.ingest.storage_sink", test_sink)

    app = create_app()
    with TestClient(app) as tc:
        yield tc
    test_sink.close()
    rate_limiter.reset()


def _make_event(event_id: str) -> dict:
    return {
        "schema_version": "1.0",
        "event_id": event_id,
        "timestamp": "2026-10-15T00:00:00Z",
        "observed_at": "2026-10-15T00:00:01Z",
        "source_host": "host1",
        "source_type": "linux_auth",
        "event_type": "authentication_success",
        "raw_event": "raw log",
    }


def test_request_size_limit_exceeded(client):
    """Requests exceeding MAX_REQUEST_BYTES must be rejected with HTTP 413."""
    headers = {
        "X-API-Key": "limit-key-123",
        "Content-Length": "2048",  # Exceeds 1024
    }
    res = client.post("/api/v1/ingest", json=_make_event("evt_size_1"), headers=headers)
    assert res.status_code == 413
    assert "Payload too large" in res.json()["detail"]


def test_rate_limiting_enforced(client):
    """Requests exceeding rate limiter threshold must return HTTP 429 with Retry-After header."""
    headers = {
        "X-API-Key": "limit-key-123",
        "X-Agent-ID": "agent-rate-test",
    }

    # First 3 requests: succeed
    for i in range(3):
        res = client.post("/api/v1/ingest", json=_make_event(f"evt_rate_{i}"), headers=headers)
        assert res.status_code == 200

    # 4th request: rate limit exceeded!
    res4 = client.post("/api/v1/ingest", json=_make_event("evt_rate_4"), headers=headers)
    assert res4.status_code == 429
    assert "Rate limit exceeded" in res4.json()["detail"]
    assert "Retry-After" in res4.headers
    assert int(res4.headers["Retry-After"]) >= 1
