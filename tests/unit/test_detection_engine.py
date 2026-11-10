"""Unit tests for DetectionEngine orchestrator and repository evaluation."""

import pytest
from backend.detection.engine import DetectionEngine
from backend.storage.sqlite_repository import SQLiteEventRepository
from collectors.common.schemas import EventType, SecurityEvent, Severity


def _make_event(eid: str, ts: str, etype: str, user: str, ip: str, is_inv: bool = False, cmd: str = None) -> SecurityEvent:
    meta = {}
    if is_inv:
        meta["is_invalid_user"] = True
    if cmd:
        meta["command"] = cmd
    return SecurityEvent(
        schema_version="1.0",
        event_id=eid,
        timestamp=ts,
        observed_at=ts,
        source_host="host1",
        source_type="linux_auth",
        event_type=etype,
        username=user,
        source_ip=ip,
        raw_event=f"raw_{eid}",
        metadata=meta,
    )


def test_detection_engine_rules_metadata():
    engine = DetectionEngine()
    rules = engine.get_rules_metadata()
    assert len(rules) == 5
    rule_ids = {r["rule_id"] for r in rules}
    assert rule_ids == {"RULE-001", "RULE-002", "RULE-003", "RULE-004", "RULE-005"}


def test_detection_engine_evaluate_events_multi_rule():
    engine = DetectionEngine()

    # Mix events that trigger RULE-001 (5 failures from 10.0.0.1) and RULE-004 (sudo shadow)
    events = [
        _make_event(f"f_{i}", f"2026-10-15T10:0{i}:00Z", EventType.AUTHENTICATION_FAILURE.value, "bob", "10.0.0.1")
        for i in range(5)
    ]
    events.append(
        _make_event("p1", "2026-10-15T10:10:00Z", EventType.PRIVILEGE_ESCALATION.value, "bob", "10.0.0.1", cmd="/bin/cat /etc/shadow")
    )

    alerts = engine.evaluate_events(events)
    assert len(alerts) >= 2
    rule_ids = {a.rule_id for a in alerts}
    assert "RULE-001" in rule_ids
    assert "RULE-004" in rule_ids


def test_detection_engine_evaluate_from_repository(tmp_path):
    db_file = tmp_path / "test_engine_repo.sqlite"
    repo = SQLiteEventRepository(db_path=str(db_file))

    # Insert brute-force attack in repo
    events = [
        _make_event(f"bf_{i}", f"2026-10-15T12:0{i}:00Z", EventType.AUTHENTICATION_FAILURE.value, "root", "192.168.10.50")
        for i in range(5)
    ]
    repo.insert_batch(events)

    engine = DetectionEngine()
    alerts = engine.evaluate_from_repository(repo=repo, start_time="2026-10-15T12:00:00Z", end_time="2026-10-15T12:30:00Z")
    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE-001"
    assert alerts[0].entities["source_ip"] == "192.168.10.50"

    repo.close()
