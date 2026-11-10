"""Unit tests for the Controlled Automated Response Engine, Safety Guardrails, and Policies."""

import pytest
from backend.ai.schemas import RecommendationEntry
from backend.response.config import ResponseConfig
from backend.response.engine import ResponseEngine
from backend.response.handlers import BlockIPHandler, LockAccountHandler
from backend.response.policy import PolicyEngine
from backend.response.repository import SQLiteResponseRepository
from backend.response.safety import SafetyGuard
from backend.response.schemas import (
    ActionPriority,
    ActionStatus,
    ActionType,
    ResponseActionProposal,
)


@pytest.fixture
def response_config():
    return ResponseConfig(
        dry_run=True,
        auto_execution_enabled=False,
        auto_execution_risk_threshold=85,
        max_actions_per_minute_per_target=3,
        audit_log_path="",  # disable file writing in unit tests
    )


@pytest.fixture
def in_memory_repo():
    return SQLiteResponseRepository(db_path=":memory:", audit_log_path="")


@pytest.fixture
def response_engine(response_config, in_memory_repo):
    return ResponseEngine(
        config=response_config,
        repository=in_memory_repo,
    )


# 1. Safety Guardrail & Allowlist Tests
def test_safety_guard_protects_loopback_and_gateways(response_config):
    safety = SafetyGuard(response_config)

    # Protected IPs
    for ip in ["127.0.0.1", "127.0.0.5", "::1", "localhost", "192.168.1.1", "8.8.8.8", "1.1.1.1"]:
        valid, err = safety.validate_target(ActionType.BLOCK_IP, ip)
        assert not valid, f"Expected {ip} to be protected by allowlist"
        assert "protected allowlist" in err

    # Valid hostile external IP
    valid, err = safety.validate_target(ActionType.BLOCK_IP, "203.0.113.100")
    assert valid
    assert err is None


def test_safety_guard_protects_system_accounts(response_config):
    safety = SafetyGuard(response_config)

    # Protected usernames
    for user in ["root", "administrator", "admin", "system", "guest", "daemon", "nobody"]:
        valid, err = safety.validate_target(ActionType.LOCK_ACCOUNT, user)
        assert not valid, f"Expected {user} to be protected by allowlist"
        assert "protected allowlist" in err

    # Valid hostile test user
    valid, err = safety.validate_target(ActionType.LOCK_ACCOUNT, "test_attacker_account")
    assert valid
    assert err is None


def test_safety_guard_defends_against_command_injection(response_config):
    safety = SafetyGuard(response_config)

    malicious_targets = [
        "192.168.1.50; rm -rf /",
        "attacker && touch /tmp/pwned",
        "`whoami`",
        "user | cat /etc/passwd",
        "test\nDROP TABLE",
        "host$VAR",
    ]

    for target in malicious_targets:
        valid, err = safety.validate_target(ActionType.BLOCK_IP, target)
        assert not valid
        assert "disallowed characters" in err


def test_safety_guard_rate_limiting(response_config):
    safety = SafetyGuard(response_config)
    target = "198.51.100.22"

    # Limit is 3 per minute in test config
    for _ in range(3):
        allowed, err = safety.check_rate_limit(target)
        assert allowed
        safety.record_action_executed(target)

    # 4th action exceeds limit
    allowed, err = safety.check_rate_limit(target)
    assert not allowed
    assert "Rate limit exceeded" in err


# 2. Policy Engine Evaluation Tests
def test_policy_engine_disruptive_actions_require_approval_by_default(response_config):
    policy = PolicyEngine(response_config)

    # Disruptive action: BLOCK_IP
    dec_block = policy.evaluate(ActionType.BLOCK_IP, "203.0.113.5", incident_risk_score=70)
    assert dec_block.allowed
    assert dec_block.requires_approval
    assert dec_block.dry_run

    # Disruptive action: LOCK_ACCOUNT
    dec_lock = policy.evaluate(ActionType.LOCK_ACCOUNT, "compromised_user", incident_risk_score=75)
    assert dec_lock.allowed
    assert dec_lock.requires_approval

    # Non-disruptive action: REVIEW_AUDIT
    dec_info = policy.evaluate(ActionType.REVIEW_AUDIT, "192.168.1.15", incident_risk_score=50)
    assert dec_info.allowed
    assert not dec_info.requires_approval


def test_policy_engine_auto_execution_threshold():
    # Config with auto-execution enabled for high risk (>= 85)
    config = ResponseConfig(
        dry_run=True,
        auto_execution_enabled=True,
        auto_execution_risk_threshold=85,
    )
    policy = PolicyEngine(config)

    # Score 80 < 85 -> requires approval
    dec_low = policy.evaluate(ActionType.BLOCK_IP, "203.0.113.5", incident_risk_score=80)
    assert dec_low.requires_approval

    # Score 90 >= 85 -> auto-approved under policy
    dec_high = policy.evaluate(ActionType.BLOCK_IP, "203.0.113.5", incident_risk_score=90)
    assert not dec_high.requires_approval
    assert "meets auto-execution threshold" in dec_high.policy_reason


# 3. Action Handlers Execution and Rollback Tests
def test_block_ip_handler_execution_and_rollback():
    handler = BlockIPHandler()

    # Dry-run execution
    res = handler.execute("act_test1", "203.0.113.44", {}, dry_run=True)
    assert res.status == ActionStatus.SIMULATED
    assert res.dry_run is True
    assert "Simulated firewall block" in res.message
    assert res.rollback_available is True
    assert "rollback_data" in res.execution_output

    # Rollback
    rb = handler.rollback("act_test1", res.execution_output["rollback_data"], dry_run=True)
    assert rb.status == ActionStatus.ROLLED_BACK
    assert "rolled back" in rb.message.lower()


def test_lock_account_handler_execution_and_rollback():
    handler = LockAccountHandler()

    # Dry-run execution
    res = handler.execute("act_test2", "compromised_analyst_test", {}, dry_run=True)
    assert res.status == ActionStatus.SIMULATED
    assert res.dry_run is True
    assert "Simulated lockout" in res.message

    # Rollback
    rb = handler.rollback("act_test2", res.execution_output["rollback_data"], dry_run=True)
    assert rb.status == ActionStatus.ROLLED_BACK
    assert "unlocked account" in rb.message.lower()


# 4. ResponseEngine End-to-End Lifecycle Tests
def test_response_engine_propose_approve_execute_rollback_lifecycle(response_engine):
    # 1. Propose disruptive action
    proposal = ResponseActionProposal(
        incident_id="inc_test_100",
        action_type=ActionType.BLOCK_IP,
        target="198.51.100.77",
        priority=ActionPriority.HIGH,
        reason="Repeated brute force attempts observed in incident inc_test_100.",
    )
    record = response_engine.propose_action(proposal, incident_risk_score=60)
    assert record.status == ActionStatus.PROPOSED
    assert record.requires_approval is True
    assert record.target == "198.51.100.77"

    # 2. Cannot execute unapproved action
    with pytest.raises(ValueError, match="Must be APPROVED first"):
        response_engine.execute_action(record.action_id)

    # 3. Approve action
    approved = response_engine.approve_action(
        record.action_id,
        analyst_name="senior_soc_analyst",
        comment="Confirmed hostile IP from threat intelligence feed."
    )
    assert approved.status == ActionStatus.APPROVED
    assert approved.approved_by == "senior_soc_analyst"

    # 4. Execute approved action
    exec_res = response_engine.execute_action(record.action_id)
    assert exec_res.status == ActionStatus.SIMULATED  # dry_run default
    assert exec_res.dry_run is True

    # Check updated persistent record
    persisted = response_engine.repository.get_action(record.action_id)
    assert persisted.status == ActionStatus.SIMULATED
    assert persisted.executed_at is not None
    assert persisted.rollback_data is not None

    # 5. Rollback action
    rb_res = response_engine.rollback_action(record.action_id, analyst_name="senior_soc_analyst")
    assert rb_res.status == ActionStatus.ROLLED_BACK

    rolled_back = response_engine.repository.get_action(record.action_id)
    assert rolled_back.status == ActionStatus.ROLLED_BACK
    assert rolled_back.rolled_back_at is not None


def test_response_engine_rejects_protected_target_immediately(response_engine):
    # Attempting to propose blocking loopback
    proposal = ResponseActionProposal(
        incident_id="inc_test_200",
        action_type=ActionType.BLOCK_IP,
        target="127.0.0.1",
        reason="Malicious loopback injection attempt.",
    )
    record = response_engine.propose_action(proposal)
    assert record.status == ActionStatus.REJECTED
    assert "protected allowlist" in record.error_message


def test_response_engine_stage_ai_recommendations(response_engine):
    recommendations = [
        RecommendationEntry(
            recommendation="Block source IP 203.0.113.88 to stop brute force",
            priority="immediate",
            reversible=True,
            action_type="block_ip",
            parameters={"ip": "203.0.113.88"}
        ),
        RecommendationEntry(
            recommendation="Lock user account temp_test_user to prevent lateral movement",
            priority="high",
            reversible=True,
            action_type="lock_account",
            parameters={"username": "temp_test_user"}
        ),
        RecommendationEntry(
            recommendation="Review audit logs on host srv-dc-01",
            priority="medium",
            reversible=False,
            action_type="review_audit",
            parameters={"host": "srv-dc-01"}
        )
    ]

    staged = response_engine.stage_ai_recommendations("inc_test_ai_01", recommendations, incident_risk_score=75)
    assert len(staged) == 3

    # block_ip should be PROPOSED (requires approval)
    assert staged[0].action_type == ActionType.BLOCK_IP
    assert staged[0].status == ActionStatus.PROPOSED
    assert staged[0].target == "203.0.113.88"

    # lock_account should be PROPOSED
    assert staged[1].action_type == ActionType.LOCK_ACCOUNT
    assert staged[1].status == ActionStatus.PROPOSED
    assert staged[1].target == "temp_test_user"

    # review_audit is informational, so it is auto-APPROVED
    assert staged[2].action_type == ActionType.REVIEW_AUDIT
    assert staged[2].status == ActionStatus.APPROVED
