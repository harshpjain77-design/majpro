"""Unit and integration tests for Entity Explorer API endpoints."""

import pytest
from fastapi.testclient import TestClient

from backend.api.config import settings
from backend.api.main import create_app
from backend.storage.sqlite_repository import SQLiteEventRepository
from collectors.common.schemas import EventType, SecurityEvent


@pytest.fixture
def client_with_entity_data(tmp_path, monkeypatch):
    test_db = tmp_path / "test_api_entities.sqlite"
    monkeypatch.setattr(settings, "DATABASE_PATH", str(test_db))
    monkeypatch.setattr(settings, "VALID_API_KEYS", {"entities-key-123"})

    test_sink = SQLiteEventRepository(db_path=str(test_db))
    monkeypatch.setattr("backend.api.dependencies.storage_sink", test_sink)
    monkeypatch.setattr("backend.api.routes.ingest.storage_sink", test_sink)
    monkeypatch.setattr("backend.api.routes.events.storage_sink", test_sink)
    monkeypatch.setattr("backend.api.routes.entities.storage_sink", test_sink)

    events = [
        # Privileged admin on host-win-01 from internal IP
        SecurityEvent(
            schema_version="1.0",
            event_id="ent_01",
            timestamp="2026-10-15T10:00:00Z",
            observed_at="2026-10-15T10:00:01Z",
            source_host="host-win-01",
            source_type="windows_security",
            event_type=EventType.AUTHENTICATION_SUCCESS.value,
            username="Administrator",
            source_ip="192.168.1.50",
            raw_event="An account was successfully logged on: Administrator",
        ),
        # Failed login on admin from external IP 203.0.113.195
        SecurityEvent(
            schema_version="1.0",
            event_id="ent_02",
            timestamp="2026-10-15T10:05:00Z",
            observed_at="2026-10-15T10:05:01Z",
            source_host="srv-linux-prod",
            source_type="systemd_journal",
            event_type=EventType.AUTHENTICATION_FAILURE.value,
            username="root",
            source_ip="203.0.113.195",
            raw_event="Failed password for root from 203.0.113.195 port 22 ssh2",
        ),
        # Service account on linux host
        SecurityEvent(
            schema_version="1.0",
            event_id="ent_03",
            timestamp="2026-10-15T10:10:00Z",
            observed_at="2026-10-15T10:10:01Z",
            source_host="srv-linux-prod",
            source_type="systemd_journal",
            event_type=EventType.AUTHENTICATION_SUCCESS.value,
            username="deploy_svc",
            source_ip="10.0.0.5",
            raw_event="Accepted publickey for deploy_svc from 10.0.0.5",
        ),
    ]
    test_sink.insert_batch(events)

    app = create_app()
    with TestClient(app) as tc:
        yield tc
    test_sink.close()


def test_entities_endpoint_unauthorized(client_with_entity_data):
    res = client_with_entity_data.get("/api/v1/entities")
    assert res.status_code == 401


def test_entities_endpoint_summary_and_lists(client_with_entity_data):
    headers = {"X-API-Key": "entities-key-123"}
    res = client_with_entity_data.get("/api/v1/entities", headers=headers)
    assert res.status_code == 200
    data = res.json()

    # Verify Summary
    assert "summary" in data
    summary = data["summary"]
    assert summary["total_entities"] >= 3
    assert summary["endpoint_hosts"] == 2
    assert summary["privileged_accounts"] >= 2  # Administrator and root
    assert summary["attack_ips"] >= 1  # 203.0.113.195 is external

    # Verify Users
    users = data["users"]
    assert len(users) == 3
    user_names = [u["username"] for u in users]
    assert "Administrator" in user_names
    assert "root" in user_names
    assert "deploy_svc" in user_names

    # Check classifications
    admin = next(u for u in users if u["username"] == "Administrator")
    assert admin["account_type"] == "privileged"
    assert "host-win-01" in admin["hosts"]

    deploy = next(u for u in users if u["username"] == "deploy_svc")
    assert deploy["account_type"] == "service"

    # Verify IPs
    ips = data["ips"]
    assert len(ips) == 3
    external_ip = next(ip for ip in ips if ip["ip"] == "203.0.113.195")
    assert external_ip["scope"] == "external"

    internal_ip = next(ip for ip in ips if ip["ip"] == "192.168.1.50")
    assert internal_ip["scope"] == "internal"

    # Verify Hosts
    hosts = data["hosts"]
    assert len(hosts) == 2
    win_host = next(h for h in hosts if h["hostname"] == "host-win-01")
    assert win_host["os_type"] == "windows"

    linux_host = next(h for h in hosts if h["hostname"] == "srv-linux-prod")
    assert linux_host["os_type"] == "linux"


def test_entities_search_and_tier_filter(client_with_entity_data):
    headers = {"X-API-Key": "entities-key-123"}

    # Search filter
    res = client_with_entity_data.get("/api/v1/entities?q=deploy", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert len(data["users"]) == 1
    assert data["users"][0]["username"] == "deploy_svc"

    # IP Search filter
    res_ip = client_with_entity_data.get("/api/v1/entities?q=203.0.113", headers=headers)
    assert res_ip.status_code == 200
    assert len(res_ip.json()["ips"]) == 1
    assert res_ip.json()["ips"][0]["ip"] == "203.0.113.195"


def test_entity_detail_endpoints(client_with_entity_data):
    headers = {"X-API-Key": "entities-key-123"}

    # User Detail
    res_user = client_with_entity_data.get("/api/v1/entities/user/Administrator", headers=headers)
    assert res_user.status_code == 200
    user_detail = res_user.json()
    assert user_detail["entity_type"] == "user"
    assert user_detail["identifier"] == "Administrator"
    assert len(user_detail["recent_events"]) >= 1
    assert len(user_detail["recommended_actions"]) >= 1
    assert user_detail["recommended_actions"][0]["action_type"] == "lock_account"

    # IP Detail
    res_ip = client_with_entity_data.get("/api/v1/entities/ip/203.0.113.195", headers=headers)
    assert res_ip.status_code == 200
    ip_detail = res_ip.json()
    assert ip_detail["entity_type"] == "ip"
    assert ip_detail["identifier"] == "203.0.113.195"
    assert len(ip_detail["recent_events"]) >= 1
    assert any(a["action_type"] == "block_ip" for a in ip_detail["recommended_actions"])

    # Host Detail
    res_host = client_with_entity_data.get("/api/v1/entities/host/srv-linux-prod", headers=headers)
    assert res_host.status_code == 200
    host_detail = res_host.json()
    assert host_detail["entity_type"] == "host"
    assert host_detail["identifier"] == "srv-linux-prod"
    assert len(host_detail["recent_events"]) >= 2
    assert any(a["action_type"] == "isolate_host" for a in host_detail["recommended_actions"])

    # Invalid Entity Type
    res_inv = client_with_entity_data.get("/api/v1/entities/printer/laserjet4", headers=headers)
    assert res_inv.status_code == 400
