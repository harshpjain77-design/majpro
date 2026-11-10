"""Unit and integration tests for SQLiteEventRepository."""

import pytest
from backend.storage.sqlite_repository import SQLiteEventRepository
from backend.storage.models import EventFilter, PaginationParams
from collectors.common.schemas import EventType, SecurityEvent, Severity


@pytest.fixture
def repo(tmp_path):
    db_file = tmp_path / "test_repo.sqlite"
    r = SQLiteEventRepository(db_path=str(db_file))
    yield r
    r.close()


def _create_test_event(
    event_id: str,
    timestamp: str,
    host: str = "kali-01",
    user: str = "alice",
    src_ip: str = "192.168.1.10",
    event_type: str = EventType.AUTHENTICATION_SUCCESS.value,
    severity: str = Severity.LOW.value,
    raw_event: str = "sample raw event text",
) -> SecurityEvent:
    return SecurityEvent(
        schema_version="1.0",
        event_id=event_id,
        timestamp=timestamp,
        observed_at=timestamp,
        source_host=host,
        source_type="linux_auth",
        event_type=event_type,
        username=user,
        source_ip=src_ip,
        severity=severity,
        raw_event=raw_event,
        collector_version="0.1.0",
        metadata={"test": True},
    )


def test_repo_insert_and_get_by_id(repo):
    ev = _create_test_event("evt_1", "2026-10-15T01:00:00Z")
    assert repo.insert_event(ev) is True
    assert repo.insert_event(ev) is False  # Duplicate

    fetched = repo.get_event_by_id("evt_1")
    assert fetched is not None
    assert fetched.event_id == "evt_1"
    assert fetched.username == "alice"
    assert fetched.metadata.get("test") is True

    # Missing event returns None
    assert repo.get_event_by_id("evt_non_existent") is None


def test_repo_get_raw_event(repo):
    raw_text = "Oct 15 01:00:00 kali sshd[123]: Accepted password for alice"
    ev = _create_test_event("evt_raw_test", "2026-10-15T01:00:00Z", raw_event=raw_text)
    repo.insert_event(ev)

    assert repo.get_raw_event("evt_raw_test") == raw_text
    assert repo.get_raw_event("evt_missing") is None


def test_repo_time_range_and_multi_field_filtering(repo):
    events = [
        _create_test_event("e1", "2026-10-15T10:00:00Z", host="host-a", user="alice", src_ip="10.0.0.1", event_type=EventType.AUTHENTICATION_SUCCESS.value, severity=Severity.LOW.value),
        _create_test_event("e2", "2026-10-15T11:00:00Z", host="host-a", user="bob", src_ip="10.0.0.2", event_type=EventType.AUTHENTICATION_FAILURE.value, severity=Severity.MEDIUM.value),
        _create_test_event("e3", "2026-10-15T12:00:00Z", host="host-b", user="root", src_ip="10.0.0.3", event_type=EventType.AUTHENTICATION_FAILURE.value, severity=Severity.HIGH.value),
        _create_test_event("e4", "2026-10-15T13:00:00Z", host="host-b", user="alice", src_ip="10.0.0.1", event_type=EventType.PRIVILEGE_ESCALATION.value, severity=Severity.HIGH.value, raw_event="sudo COMMAND=/bin/bash"),
    ]
    repo.insert_batch(events)
    assert repo.count_events() == 4

    # 1. Time range filter: 10:30 to 12:30 -> Should match e2 and e3
    res_time = repo.search_events(
        EventFilter(start_time="2026-10-15T10:30:00Z", end_time="2026-10-15T12:30:00Z"),
        PaginationParams(limit=10, offset=0),
    )
    assert res_time.total == 2
    assert {e.event_id for e in res_time.events} == {"e2", "e3"}

    # 2. Host filter: host-a (case-insensitive) -> e1 and e2
    res_host = repo.search_events(
        EventFilter(source_host="HOST-A"),
        PaginationParams(limit=10, offset=0),
    )
    assert res_host.total == 2
    assert {e.event_id for e in res_host.events} == {"e1", "e2"}

    # 3. Username filter: alice -> e1 and e4
    res_user = repo.search_events(
        EventFilter(username="alice"),
        PaginationParams(limit=10, offset=0),
    )
    assert res_user.total == 2
    assert {e.event_id for e in res_user.events} == {"e1", "e4"}

    # 4. Severity filter: high -> e3 and e4
    res_sev = repo.search_events(
        EventFilter(severity="high"),
        PaginationParams(limit=10, offset=0),
    )
    assert res_sev.total == 2
    assert {e.event_id for e in res_sev.events} == {"e3", "e4"}

    # 5. Free-text search term in raw_event: "COMMAND=/bin/bash" -> e4
    res_search = repo.search_events(
        EventFilter(search_term="/bin/bash"),
        PaginationParams(limit=10, offset=0),
    )
    assert res_search.total == 1
    assert res_search.events[0].event_id == "e4"


def test_repo_pagination(repo):
    events = [
        _create_test_event(f"e_p_{i}", f"2026-10-15T10:{i:02d}:00Z")
        for i in range(10)
    ]
    repo.insert_batch(events)

    # Page 1: limit 3, offset 0
    p1 = repo.search_events(EventFilter(), PaginationParams(limit=3, offset=0))
    assert p1.total == 10
    assert len(p1.events) == 3
    assert p1.has_more is True
    # Most recent first: 10:09, 10:08, 10:07
    assert p1.events[0].event_id == "e_p_9"

    # Page 2: limit 3, offset 3
    p2 = repo.search_events(EventFilter(), PaginationParams(limit=3, offset=3))
    assert len(p2.events) == 3
    assert p2.has_more is True
    assert p2.events[0].event_id == "e_p_6"

    # Last page: offset 9, limit 3
    p4 = repo.search_events(EventFilter(), PaginationParams(limit=3, offset=9))
    assert len(p4.events) == 1
    assert p4.has_more is False


def test_repo_summary_and_time_series(repo):
    events = [
        _create_test_event("s1", "2026-10-15T08:10:00Z", severity=Severity.LOW.value, event_type=EventType.AUTHENTICATION_SUCCESS.value),
        _create_test_event("s2", "2026-10-15T08:20:00Z", severity=Severity.MEDIUM.value, event_type=EventType.AUTHENTICATION_FAILURE.value),
        _create_test_event("s3", "2026-10-15T09:15:00Z", severity=Severity.HIGH.value, event_type=EventType.AUTHENTICATION_FAILURE.value),
    ]
    repo.insert_batch(events)

    summary = repo.get_summary_counts()
    assert summary.total_events == 3
    assert summary.by_severity[Severity.LOW.value] == 1
    assert summary.by_severity[Severity.MEDIUM.value] == 1
    assert summary.by_severity[Severity.HIGH.value] == 1
    assert summary.by_event_type[EventType.AUTHENTICATION_FAILURE.value] == 2
    assert summary.by_event_type[EventType.AUTHENTICATION_SUCCESS.value] == 1

    # Check time series buckets: 2 buckets (hour 08:00 has 2, hour 09:00 has 1)
    assert len(summary.time_series) == 2
    assert summary.time_series[0].count == 2
    assert summary.time_series[1].count == 1
