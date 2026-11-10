"""Comprehensive positive and negative test cases for deterministic detection rules."""

import pytest

from collectors.common.schemas import EventType, SecurityEvent, Severity
from backend.detection.config import DetectionConfig
from backend.detection.rules import (
    DistributedPasswordSprayRule,
    FailedFollowedBySuccessRule,
    PrivilegedActivityRule,
    SingleSourceBruteForceRule,
    SuspiciousAuthenticationSequenceRule,
)


def _ev(
    eid: str,
    ts: str,
    etype: str,
    user: str = "alice",
    src_ip: str = "192.168.1.100",
    host: str = "host1",
    is_invalid: bool = False,
    command: str = None,
    win_id: int = None,
    logon_type: int = None,
) -> SecurityEvent:
    meta = {}
    if is_invalid:
        meta["is_invalid_user"] = True
    if command:
        meta["command"] = command
    if logon_type is not None:
        meta["logon_type"] = logon_type

    return SecurityEvent(
        schema_version="1.0",
        event_id=eid,
        timestamp=ts,
        observed_at=ts,
        source_host=host,
        source_type="linux_auth",
        event_type=etype,
        username=user,
        source_ip=src_ip,
        windows_event_id=win_id,
        raw_event=f"raw_{eid}",
        metadata=meta,
    )


# ============================================================================
# RULE-001: Single Source Brute Force
# ============================================================================

def test_rule_001_positive():
    """Positive: 5 failures from same IP within 300s triggers RULE-001."""
    rule = SingleSourceBruteForceRule()
    events = [
        _ev(f"e_{i}", f"2026-10-15T10:0{i}:00Z", EventType.AUTHENTICATION_FAILURE.value, src_ip="10.0.0.50")
        for i in range(5)
    ]
    alerts = rule.evaluate(events)
    assert len(alerts) == 1
    alt = alerts[0]
    assert alt.rule_id == "RULE-001"
    assert alt.entities["source_ip"] == "10.0.0.50"
    assert len(alt.related_event_ids) == 5
    assert "Observed 5 failed" in alt.explanation


def test_rule_001_negative_below_threshold():
    """Negative: 4 failures (threshold is 5) does NOT trigger RULE-001."""
    rule = SingleSourceBruteForceRule()
    events = [
        _ev(f"e_{i}", f"2026-10-15T10:0{i}:00Z", EventType.AUTHENTICATION_FAILURE.value, src_ip="10.0.0.50")
        for i in range(4)
    ]
    assert len(rule.evaluate(events)) == 0


def test_rule_001_negative_outside_time_window():
    """Negative: 5 failures spaced 10 minutes apart (outside 300s window) do NOT trigger."""
    rule = SingleSourceBruteForceRule()
    events = [
        _ev(f"e_{i}", f"2026-10-15T1{i}:00:00Z", EventType.AUTHENTICATION_FAILURE.value, src_ip="10.0.0.50")
        for i in range(5)
    ]
    assert len(rule.evaluate(events)) == 0


def test_rule_001_negative_distinct_ips():
    """Negative: 5 failures from 5 different single-attempt IPs do NOT trigger."""
    rule = SingleSourceBruteForceRule()
    events = [
        _ev(f"e_{i}", f"2026-10-15T10:0{i}:00Z", EventType.AUTHENTICATION_FAILURE.value, src_ip=f"10.0.0.{i+1}")
        for i in range(5)
    ]
    assert len(rule.evaluate(events)) == 0


# ============================================================================
# RULE-002: Failed Logins Followed by Success
# ============================================================================

def test_rule_002_positive():
    """Positive: 3 failures followed by success for alice within 600s triggers RULE-002."""
    rule = FailedFollowedBySuccessRule()
    events = [
        _ev("f1", "2026-10-15T12:00:00Z", EventType.AUTHENTICATION_FAILURE.value, user="alice", src_ip="192.168.1.20"),
        _ev("f2", "2026-10-15T12:01:00Z", EventType.AUTHENTICATION_FAILURE.value, user="alice", src_ip="192.168.1.20"),
        _ev("f3", "2026-10-15T12:02:00Z", EventType.AUTHENTICATION_FAILURE.value, user="alice", src_ip="192.168.1.20"),
        _ev("s1", "2026-10-15T12:03:00Z", EventType.AUTHENTICATION_SUCCESS.value, user="alice", src_ip="192.168.1.20"),
    ]
    alerts = rule.evaluate(events)
    assert len(alerts) == 1
    alt = alerts[0]
    assert alt.rule_id == "RULE-002"
    assert alt.severity == Severity.HIGH.value
    assert alt.entities["username"] == "alice"
    assert "s1" in alt.related_event_ids
    assert alt.supporting_evidence["prior_failure_count"] == 3


def test_rule_002_negative_insufficient_prior_failures():
    """Negative: 2 failures (threshold is 3) followed by success does NOT trigger."""
    rule = FailedFollowedBySuccessRule()
    events = [
        _ev("f1", "2026-10-15T12:00:00Z", EventType.AUTHENTICATION_FAILURE.value, user="alice"),
        _ev("f2", "2026-10-15T12:01:00Z", EventType.AUTHENTICATION_FAILURE.value, user="alice"),
        _ev("s1", "2026-10-15T12:03:00Z", EventType.AUTHENTICATION_SUCCESS.value, user="alice"),
    ]
    assert len(rule.evaluate(events)) == 0


def test_rule_002_negative_different_users():
    """Negative: Failures for alice followed by success for bob does NOT trigger."""
    rule = FailedFollowedBySuccessRule()
    events = [
        _ev("f1", "2026-10-15T12:00:00Z", EventType.AUTHENTICATION_FAILURE.value, user="alice"),
        _ev("f2", "2026-10-15T12:01:00Z", EventType.AUTHENTICATION_FAILURE.value, user="alice"),
        _ev("f3", "2026-10-15T12:02:00Z", EventType.AUTHENTICATION_FAILURE.value, user="alice"),
        _ev("s1", "2026-10-15T12:03:00Z", EventType.AUTHENTICATION_SUCCESS.value, user="bob"),
    ]
    assert len(rule.evaluate(events)) == 0


def test_rule_002_negative_outside_window():
    """Negative: 3 failures, but success happens 1 hour later (outside 600s window) does NOT trigger."""
    rule = FailedFollowedBySuccessRule()
    events = [
        _ev("f1", "2026-10-15T10:00:00Z", EventType.AUTHENTICATION_FAILURE.value, user="alice"),
        _ev("f2", "2026-10-15T10:01:00Z", EventType.AUTHENTICATION_FAILURE.value, user="alice"),
        _ev("f3", "2026-10-15T10:02:00Z", EventType.AUTHENTICATION_FAILURE.value, user="alice"),
        _ev("s1", "2026-10-15T11:30:00Z", EventType.AUTHENTICATION_SUCCESS.value, user="alice"),
    ]
    assert len(rule.evaluate(events)) == 0


# ============================================================================
# RULE-003: Distributed Password Spray
# ============================================================================

def test_rule_003_positive():
    """Positive: 3 distinct source IPs failing against same account within 600s triggers RULE-003."""
    rule = DistributedPasswordSprayRule()
    events = [
        _ev("f1", "2026-10-15T14:00:00Z", EventType.AUTHENTICATION_FAILURE.value, user="finance_user", src_ip="172.16.1.10"),
        _ev("f2", "2026-10-15T14:02:00Z", EventType.AUTHENTICATION_FAILURE.value, user="finance_user", src_ip="172.16.1.20"),
        _ev("f3", "2026-10-15T14:04:00Z", EventType.AUTHENTICATION_FAILURE.value, user="finance_user", src_ip="172.16.1.30"),
    ]
    alerts = rule.evaluate(events)
    assert len(alerts) == 1
    alt = alerts[0]
    assert alt.rule_id == "RULE-003"
    assert alt.supporting_evidence["distinct_source_count"] == 3
    assert alt.entities["username"] == "finance_user"


def test_rule_003_negative_same_ip():
    """Negative: 3 failures from the SAME IP is single-source brute force, NOT password spray."""
    rule = DistributedPasswordSprayRule()
    events = [
        _ev("f1", "2026-10-15T14:00:00Z", EventType.AUTHENTICATION_FAILURE.value, user="finance_user", src_ip="172.16.1.10"),
        _ev("f2", "2026-10-15T14:02:00Z", EventType.AUTHENTICATION_FAILURE.value, user="finance_user", src_ip="172.16.1.10"),
        _ev("f3", "2026-10-15T14:04:00Z", EventType.AUTHENTICATION_FAILURE.value, user="finance_user", src_ip="172.16.1.10"),
    ]
    assert len(rule.evaluate(events)) == 0


def test_rule_003_negative_distinct_users():
    """Negative: 3 distinct IPs targeting 3 different users (1 attempt each) does NOT trigger single-account spray."""
    rule = DistributedPasswordSprayRule()
    events = [
        _ev("f1", "2026-10-15T14:00:00Z", EventType.AUTHENTICATION_FAILURE.value, user="user_a", src_ip="172.16.1.10"),
        _ev("f2", "2026-10-15T14:02:00Z", EventType.AUTHENTICATION_FAILURE.value, user="user_b", src_ip="172.16.1.20"),
        _ev("f3", "2026-10-15T14:04:00Z", EventType.AUTHENTICATION_FAILURE.value, user="user_c", src_ip="172.16.1.30"),
    ]
    assert len(rule.evaluate(events)) == 0


# ============================================================================
# RULE-004: Unusual Privileged Activity
# ============================================================================

def test_rule_004_positive_sensitive_sudo_shadow():
    """Positive: Sudo command accessing /etc/shadow triggers RULE-004."""
    rule = PrivilegedActivityRule()
    events = [
        _ev("p1", "2026-10-15T15:00:00Z", EventType.PRIVILEGE_ESCALATION.value, user="alice", command="cat /etc/shadow")
    ]
    alerts = rule.evaluate(events)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE-004"
    assert alerts[0].severity == Severity.HIGH.value
    assert "/etc/shadow" in alerts[0].supporting_evidence["command"]


def test_rule_004_positive_remote_special_logon():
    """Positive: Windows Event 4672 with remote LogonType 10 triggers RULE-004."""
    rule = PrivilegedActivityRule()
    events = [
        _ev("p2", "2026-10-15T15:10:00Z", EventType.PRIVILEGE_ESCALATION.value, user="secadmin", win_id=4672, logon_type=10)
    ]
    alerts = rule.evaluate(events)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE-004"


def test_rule_004_negative_benign_sudo():
    """Negative: Benign sudo command (e.g. ls, git) does NOT trigger RULE-004."""
    rule = PrivilegedActivityRule()
    events = [
        _ev("p3", "2026-10-15T15:00:00Z", EventType.PRIVILEGE_ESCALATION.value, user="alice", command="/usr/bin/git status")
    ]
    assert len(rule.evaluate(events)) == 0


# ============================================================================
# RULE-005: Suspicious Authentication Sequence
# ============================================================================

def test_rule_005_positive():
    """Positive: 3 invalid usernames probed followed by targeted valid login triggers RULE-005."""
    rule = SuspiciousAuthenticationSequenceRule()
    events = [
        _ev("i1", "2026-10-15T16:00:00Z", EventType.AUTHENTICATION_FAILURE.value, user="admin123", src_ip="198.51.100.5", is_invalid=True),
        _ev("i2", "2026-10-15T16:01:00Z", EventType.AUTHENTICATION_FAILURE.value, user="testguest", src_ip="198.51.100.5", is_invalid=True),
        _ev("i3", "2026-10-15T16:02:00Z", EventType.AUTHENTICATION_FAILURE.value, user="oracle_dba", src_ip="198.51.100.5", is_invalid=True),
        _ev("t1", "2026-10-15T16:03:00Z", EventType.AUTHENTICATION_FAILURE.value, user="Administrator", src_ip="198.51.100.5", is_invalid=False),
    ]
    alerts = rule.evaluate(events)
    assert len(alerts) == 1
    alt = alerts[0]
    assert alt.rule_id == "RULE-005"
    assert alt.entities["targeted_username"] == "Administrator"
    assert alt.supporting_evidence["invalid_probe_count"] == 3


def test_rule_005_negative_insufficient_probes():
    """Negative: 2 invalid probes (threshold is 3) followed by targeted login does NOT trigger."""
    rule = SuspiciousAuthenticationSequenceRule()
    events = [
        _ev("i1", "2026-10-15T16:00:00Z", EventType.AUTHENTICATION_FAILURE.value, user="admin123", src_ip="198.51.100.5", is_invalid=True),
        _ev("i2", "2026-10-15T16:01:00Z", EventType.AUTHENTICATION_FAILURE.value, user="testguest", src_ip="198.51.100.5", is_invalid=True),
        _ev("t1", "2026-10-15T16:03:00Z", EventType.AUTHENTICATION_FAILURE.value, user="Administrator", src_ip="198.51.100.5", is_invalid=False),
    ]
    assert len(rule.evaluate(events)) == 0
