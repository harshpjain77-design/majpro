"""Unit tests for AlertDeduplicator: sliding windows, fingerprint matching, and reduction metrics."""

import pytest
from backend.correlation.config import CorrelationConfig
from backend.correlation.deduplicator import AlertDeduplicator
from backend.detection.schemas import Alert


def create_sample_alert(
    rule_id: str,
    first_obs: str,
    last_obs: str,
    ip: str = "192.168.1.50",
    username: str = "alice",
    host: str = "srv1",
    severity: str = "medium",
    failure_count: int = 5,
    event_ids: list = None,
) -> Alert:
    """Helper to synthesize test Alert instances."""
    e_ids = event_ids or [f"evt_{rule_id}_{first_obs}_{i}" for i in range(failure_count)]
    return Alert.create(
        rule_id=rule_id,
        rule_name=f"Test {rule_id}",
        severity=severity,
        first_observed=first_obs,
        last_observed=last_obs,
        related_event_ids=e_ids,
        explanation=f"Test alert for {rule_id} from {ip}",
        supporting_evidence={"failure_count": failure_count, "source_ip": ip},
        entities={"source_ip": ip, "username": username, "host": host},
        confidence=0.85,
        risk_score=50.0,
    )


def test_dedup_single_alert():
    """Single alert establishes initial deduplication record."""
    deduplicator = AlertDeduplicator(config=CorrelationConfig(deduplication_window_seconds=900))
    alert = create_sample_alert("RULE-001", "2026-10-15T01:00:00Z", "2026-10-15T01:02:00Z")

    dedup = deduplicator.process_alert(alert)
    assert dedup.occurrence_count == 1
    assert dedup.first_seen == "2026-10-15T01:00:00Z"
    assert dedup.last_seen == "2026-10-15T01:02:00Z"
    assert dedup.primary_alert_id == alert.alert_id
    assert dedup.contributing_alert_ids == [alert.alert_id]
    assert len(dedup.related_event_ids) == 5

    metrics = deduplicator.get_metrics()
    assert metrics.total_alerts_received == 1
    assert metrics.deduplicated_alerts_emitted == 1
    assert metrics.raw_alert_reduction_count == 0
    assert metrics.deduplication_ratio == 0.0


def test_dedup_multiple_identical_alerts_within_window():
    """Identical alerts within sliding window are collapsed and counted."""
    deduplicator = AlertDeduplicator(config=CorrelationConfig(deduplication_window_seconds=900))

    # Alert 1 at 01:00
    a1 = create_sample_alert("RULE-001", "2026-10-15T01:00:00Z", "2026-10-15T01:02:00Z", event_ids=["e1", "e2"])
    # Alert 2 at 01:05 (5 mins later, within 15 min window)
    a2 = create_sample_alert("RULE-001", "2026-10-15T01:05:00Z", "2026-10-15T01:06:00Z", event_ids=["e3", "e4"])
    # Alert 3 at 01:10 (5 mins later, within sliding window)
    a3 = create_sample_alert(
        "RULE-001",
        "2026-10-15T01:10:00Z",
        "2026-10-15T01:11:00Z",
        severity="high",
        event_ids=["e4", "e5"],
    )

    dedup1 = deduplicator.process_alert(a1)
    dedup2 = deduplicator.process_alert(a2)
    dedup3 = deduplicator.process_alert(a3)

    assert dedup3.occurrence_count == 3
    assert dedup3.first_seen == "2026-10-15T01:00:00Z"
    assert dedup3.last_seen == "2026-10-15T01:11:00Z"
    assert dedup3.severity == "high"  # Escalated from medium to high
    assert dedup3.primary_alert_id == a1.alert_id
    assert dedup3.contributing_alert_ids == [a1.alert_id, a2.alert_id, a3.alert_id]
    # Unique event IDs: e1, e2, e3, e4, e5 (e4 not duplicated)
    assert set(dedup3.related_event_ids) == {"e1", "e2", "e3", "e4", "e5"}

    metrics = deduplicator.get_metrics()
    assert metrics.total_alerts_received == 3
    assert metrics.deduplicated_alerts_emitted == 1
    assert metrics.raw_alert_reduction_count == 2
    assert metrics.deduplication_ratio == round(2 / 3, 4)


def test_dedup_window_expiration_creates_new_aggregate():
    """Alerts outside sliding window separate into consecutive aggregates."""
    # 10 minute window (600 seconds)
    deduplicator = AlertDeduplicator(config=CorrelationConfig(deduplication_window_seconds=600))

    # Alert 1 at 01:00
    a1 = create_sample_alert("RULE-001", "2026-10-15T01:00:00Z", "2026-10-15T01:01:00Z")
    # Alert 2 at 01:25 (24 minutes later, exceeding 10 min window)
    a2 = create_sample_alert("RULE-001", "2026-10-15T01:25:00Z", "2026-10-15T01:26:00Z")

    dedup1 = deduplicator.process_alert(a1)
    dedup2 = deduplicator.process_alert(a2)

    assert dedup1.occurrence_count == 1
    assert dedup2.occurrence_count == 1
    assert dedup1.primary_alert_id != dedup2.primary_alert_id
    assert dedup1.first_seen == "2026-10-15T01:00:00Z"
    assert dedup2.first_seen == "2026-10-15T01:25:00Z"

    aggregates = deduplicator.get_all_aggregates()
    assert len(aggregates) == 2


def test_dedup_distinct_fingerprints():
    """Alerts for different rules or different IPs maintain independent deduplication windows."""
    deduplicator = AlertDeduplicator(config=CorrelationConfig(deduplication_window_seconds=900))

    # Alert from IP A
    a_ip_a = create_sample_alert("RULE-001", "2026-10-15T01:00:00Z", "2026-10-15T01:01:00Z", ip="10.0.0.1")
    # Alert from IP B
    a_ip_b = create_sample_alert("RULE-001", "2026-10-15T01:00:30Z", "2026-10-15T01:01:30Z", ip="10.0.0.2")

    dedup_a = deduplicator.process_alert(a_ip_a)
    dedup_b = deduplicator.process_alert(a_ip_b)

    assert dedup_a.fingerprint != dedup_b.fingerprint
    assert len(deduplicator.get_all_aggregates()) == 2


def test_deduplicate_batch():
    """Batch deduplication cleanly sorts and collapses out-of-order alert streams."""
    deduplicator = AlertDeduplicator(config=CorrelationConfig(deduplication_window_seconds=900))

    # 10 alerts in rapid succession for the same brute-force attack
    raw_alerts = [
        create_sample_alert(
            "RULE-001",
            f"2026-10-15T01:{i:02d}:00Z",
            f"2026-10-15T01:{i:02d}:30Z",
            ip="192.168.1.100",
        )
        for i in range(10)
    ]

    # Reverse order to verify sorting resilience
    raw_alerts.reverse()

    results = deduplicator.deduplicate_batch(raw_alerts)
    assert len(results) == 1
    assert results[0].occurrence_count == 10
    assert results[0].first_seen == "2026-10-15T01:00:00Z"
    assert results[0].last_seen == "2026-10-15T01:09:30Z"

    metrics = deduplicator.get_metrics()
    assert metrics.total_alerts_received == 10
    assert metrics.deduplication_ratio == 0.9  # 90% reduction
