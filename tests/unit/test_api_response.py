"""Integration and API unit tests for response routes."""

import pytest
from fastapi.testclient import TestClient

from backend.api.main import create_app
from backend.correlation.schemas import Incident, IncidentStatus
from backend.api.dependencies import incident_repo, get_response_engine


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


@pytest.fixture
def api_headers():
    return {
        "Content-Type": "application/json",
        "X-API-Key": "test-collector-api-key-replace-in-production",
    }


def test_response_api_unauthorized_rejected(client):
    res = client.get("/api/v1/response/safety/status")
    assert res.status_code == 401


def test_response_api_safety_status(client, api_headers):
    res = client.get("/api/v1/response/safety/status", headers=api_headers)
    assert res.status_code == 200
    data = res.json()
    assert "dry_run" in data
    assert data["dry_run"] is True
    assert "127.0.0.1" in data["protected_ips"]
    assert "root" in data["protected_users"]
    assert "rate_limit_per_minute" in data


def test_response_api_propose_approve_execute_lifecycle(client, api_headers):
    # 1. Propose action
    payload = {
        "incident_id": "inc_api_test_01",
        "action_type": "block_ip",
        "target": "198.51.100.99",
        "priority": "high",
        "reason": "Test response proposing IP block",
    }
    res = client.post("/api/v1/response/propose", json=payload, headers=api_headers)
    assert res.status_code == 201
    action = res.json()
    action_id = action["action_id"]
    assert action["status"] == "PROPOSED"
    assert action["requires_approval"] is True
    assert action["target"] == "198.51.100.99"

    # 2. Cannot execute unapproved action
    exec_res = client.post(f"/api/v1/response/actions/{action_id}/execute", headers=api_headers)
    assert exec_res.status_code == 400

    # 3. Approve action
    appr_payload = {
        "analyst_name": "lead_soc_analyst",
        "comment": "Verified against threat intel feed"
    }
    appr_res = client.post(f"/api/v1/response/actions/{action_id}/approve", json=appr_payload, headers=api_headers)
    assert appr_res.status_code == 200
    appr_data = appr_res.json()
    assert appr_data["status"] == "APPROVED"
    assert appr_data["approved_by"] == "lead_soc_analyst"

    # 4. Execute approved action
    exec_res2 = client.post(f"/api/v1/response/actions/{action_id}/execute", headers=api_headers)
    assert exec_res2.status_code == 200
    exec_data = exec_res2.json()
    assert exec_data["status"] == "SIMULATED"
    assert exec_data["dry_run"] is True
    assert exec_data["rollback_available"] is True

    # 5. Rollback action
    rb_payload = {
        "analyst_name": "lead_soc_analyst",
        "comment": "Incident resolved; restore access"
    }
    rb_res = client.post(f"/api/v1/response/actions/{action_id}/rollback", json=rb_payload, headers=api_headers)
    assert rb_res.status_code == 200
    rb_data = rb_res.json()
    assert rb_data["status"] == "ROLLED_BACK"


def test_response_api_protected_ip_rejected(client, api_headers):
    payload = {
        "incident_id": "inc_api_test_02",
        "action_type": "block_ip",
        "target": "127.0.0.1",
        "reason": "Attacker injected loopback address in log",
    }
    res = client.post("/api/v1/response/propose", json=payload, headers=api_headers)
    assert res.status_code == 201
    data = res.json()
    assert data["status"] == "REJECTED"
    assert "protected allowlist" in data["error_message"]


def test_response_api_protected_user_rejected(client, api_headers):
    payload = {
        "incident_id": "inc_api_test_03",
        "action_type": "lock_account",
        "target": "root",
        "reason": "Attacker targeted root; attempting to lock root",
    }
    res = client.post("/api/v1/response/propose", json=payload, headers=api_headers)
    assert res.status_code == 201
    data = res.json()
    assert data["status"] == "REJECTED"
    assert "protected allowlist" in data["error_message"]


def test_response_api_list_actions_and_filter(client, api_headers):
    res = client.get("/api/v1/response/actions", headers=api_headers)
    assert res.status_code == 200
    data = res.json()
    assert "total" in data
    assert "actions" in data
    assert isinstance(data["actions"], list)


def test_response_api_stage_incident_response(client, api_headers):
    # Seed an incident in incident_repo
    test_inc = Incident(
        incident_id="inc_stage_test_99",
        title="Multiple SSH Brute Force Attempts",
        severity="high",
        status=IncidentStatus.NEW,
        risk_score=78,
        first_seen="2026-10-14T12:00:00Z",
        last_seen="2026-10-14T12:05:00Z",
        entities={"source_ips": ["203.0.113.200"], "usernames": ["victim_user_1"], "hosts": ["srv-auth"]},
        related_alert_ids=["alt_test_01"],
        related_event_ids=["evt_test_01"],
        distinct_rules=["RULE-001"],
        timeline=[],
        analyst_notes=[],
        created_at="2026-10-14T12:00:00Z",
        updated_at="2026-10-14T12:05:00Z",
    )
    incident_repo.save_incident(test_inc)

    res = client.post(f"/api/v1/response/stage_incident/{test_inc.incident_id}", headers=api_headers)
    assert res.status_code == 200
    staged = res.json()
    assert isinstance(staged, list)
    assert len(staged) > 0
    # Check that at least one action was staged with target 203.0.113.200
    targets = [a["target"] for a in staged]
    assert "203.0.113.200" in targets
