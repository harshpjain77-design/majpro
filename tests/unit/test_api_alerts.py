"""Unit tests for detection and alerts API endpoints."""

import pytest
from fastapi.testclient import TestClient

from backend.api.config import settings
from backend.api.main import create_app
from backend.storage.sqlite_repository import SQLiteEventRepository
from collectors.common.schemas import EventType, SecurityEvent


@pytest.fixture
def client_with_attack_data(tmp_path, monkeypatch):
    test_db = tmp_path / "test_api_alerts.sqlite"
    monkeypatch.setattr(settings, "DATABASE_PATH", str(test_db))
    monkeypatch.setattr(settings, "VALID_API_KEYS", {"alerts-key-123"})

    test_sink = SQLiteEventRepository(db_path=str(test_db))
    monkeypatch.setattr("backend.api.dependencies.storage_sink", test_sink)
    monkeypatch.setattr("backend.api.routes.ingest.storage_sink", test_sink)
    monkeypatch.setattr("backend.api.routes.events.storage_sink", test_sink)
    monkeypatch.setattr("backend.api.routes.alerts.storage_sink", test_sink)

    # Insert events that trigger RULE-001 (5 failures from 192.168.100.99)
    events = [
        SecurityEvent(
            schema_version="1.0",
            event_id=f"e_bf_{i}",
            timestamp=f"2026-10-15T14:0{i}:00Z",
            observed_at=f"2026-10-15T14:0{i}:01Z",
            source_host="kali-target",
            source_type="linux_auth",
            event_type=EventType.AUTHENTICATION_FAILURE.value,
            username="admin",
            source_ip="192.168.100.99",
            raw_event=f"Failed password for admin {i}",
        )
        for i in range(5)
    ]
    test_sink.insert_batch(events)

    app = create_app()
    with TestClient(app) as tc:
        yield tc
    test_sink.close()


def test_detection_rules_list(client_with_attack_data):
    headers = {"X-API-Key": "alerts-key-123"}
    res = client_with_attack_data.get("/api/v1/detection/rules", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "rules" in data
    assert len(data["rules"]) == 5


def test_detection_evaluate_endpoint(client_with_attack_data):
    headers = {"X-API-Key": "alerts-key-123"}
    res = client_with_attack_data.post(
        "/api/v1/detection/evaluate?start_time=2026-10-15T14:00:00Z&end_time=2026-10-15T14:30:00Z",
        headers=headers,
    )
    assert res.status_code == 200
    alerts = res.json()
    assert len(alerts) >= 1
    assert alerts[0]["rule_id"] == "RULE-001"
    assert alerts[0]["entities"]["source_ip"] == "192.168.100.99"
    assert len(alerts[0]["related_event_ids"]) == 5
