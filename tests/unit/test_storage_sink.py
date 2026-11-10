"""Unit tests for EventStorageSink SQLite persistence and deduplication."""

import pytest
from backend.api.storage_sink import EventStorageSink
from collectors.common.schemas import EventType, SecurityEvent, Severity


@pytest.fixture
def temp_sink(tmp_path):
    db_file = tmp_path / "test_soc.sqlite"
    sink = EventStorageSink(db_path=str(db_file))
    yield sink
    sink.close()


def test_storage_sink_init_and_health(temp_sink):
    assert temp_sink.check_health() is True
    assert temp_sink.count_events() == 0


def test_storage_sink_insert_and_deduplicate(temp_sink):
    event1 = SecurityEvent(
        schema_version="1.0",
        event_id="evt_unique_1",
        timestamp="2026-10-15T00:00:00Z",
        observed_at="2026-10-15T00:00:01Z",
        source_host="host1",
        source_type="linux_auth",
        event_type=EventType.AUTHENTICATION_SUCCESS.value,
        raw_event="raw 1",
    )

    # First insert: success
    inserted = temp_sink.insert_event(event1, agent_id="agent-01")
    assert inserted is True
    assert temp_sink.count_events() == 1

    # Second insert with identical event_id: duplicate ignored
    inserted_again = temp_sink.insert_event(event1, agent_id="agent-01")
    assert inserted_again is False
    assert temp_sink.count_events() == 1


def test_storage_sink_batch_insert(temp_sink):
    events = [
        SecurityEvent(
            schema_version="1.0",
            event_id=f"evt_batch_{i}",
            timestamp="2026-10-15T00:00:00Z",
            observed_at="2026-10-15T00:00:01Z",
            source_host="host1",
            source_type="linux_auth",
            event_type=EventType.AUTHENTICATION_FAILURE.value,
            raw_event=f"raw batch {i}",
        )
        for i in range(5)
    ]

    ingested, dups, ids = temp_sink.insert_batch(events, agent_id="agent-batch")
    assert ingested == 5
    assert dups == 0
    assert len(ids) == 5
    assert temp_sink.count_events() == 5

    # Re-insert batch with 2 new events and 5 old
    more_events = list(events)
    more_events.append(
        SecurityEvent(
            schema_version="1.0",
            event_id="evt_batch_new_1",
            timestamp="2026-10-15T00:00:00Z",
            observed_at="2026-10-15T00:00:01Z",
            source_host="host1",
            source_type="linux_auth",
            event_type=EventType.AUTHENTICATION_SUCCESS.value,
            raw_event="raw new 1",
        )
    )

    ingested2, dups2, ids2 = temp_sink.insert_batch(more_events, agent_id="agent-batch")
    assert ingested2 == 1
    assert dups2 == 5
    assert ids2 == ["evt_batch_new_1"]
    assert temp_sink.count_events() == 6
