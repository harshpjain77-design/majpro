"""Unit tests for FeatureExtractor: authentication velocity, entropy, and temporal metrics."""

from datetime import datetime, timezone
import pytest
from collectors.common.schemas import EventType, SecurityEvent
from backend.ml.config import MLConfig
from backend.ml.features import FeatureExtractor
from backend.ml.schemas import FEATURE_NAMES


def make_event(
    event_id: str,
    timestamp: str,
    event_type: str = EventType.AUTHENTICATION_SUCCESS.value,
    username: str = "alice",
    source_ip: str = "192.168.1.10",
    host: str = "web-srv",
) -> SecurityEvent:
    return SecurityEvent(
        schema_version="1.0",
        event_id=event_id,
        timestamp=timestamp,
        observed_at=timestamp,
        source_host=host,
        source_type="linux_auth",
        event_type=event_type,
        username=username,
        source_ip=source_ip,
        severity="low",
        raw_event=f"Auth event {event_id}",
    )


def test_feature_extractor_computes_all_10_features():
    """Verify FeatureExtractor produces complete, accurate feature vectors for an event window."""
    extractor = FeatureExtractor(
        config=MLConfig(feature_window_seconds=900, min_events_per_window=3)
    )

    events = [
        make_event("ev1", "2026-10-15T01:00:00Z", EventType.AUTHENTICATION_SUCCESS.value, username="alice"),
        make_event("ev2", "2026-10-15T01:01:00Z", EventType.AUTHENTICATION_FAILURE.value, username="alice"),
        make_event("ev3", "2026-10-15T01:02:00Z", EventType.AUTHENTICATION_FAILURE.value, username="bob"),
        make_event("ev4", "2026-10-15T01:03:00Z", EventType.AUTHENTICATION_SUCCESS.value, username="alice"),
    ]

    vectors = extractor.extract_features_from_events(events, entity_key="source_ip")
    assert len(vectors) == 1
    v = vectors[0]

    assert v.entity_type == "source_ip"
    assert v.entity_value == "192.168.1.10"
    assert set(v.features.keys()) == set(FEATURE_NAMES)

    assert v.features["event_count"] == 4.0
    assert v.features["failure_count"] == 2.0
    assert v.features["success_count"] == 2.0
    assert v.features["failure_ratio"] == 0.50
    assert v.features["unique_usernames_targeted"] == 2.0
    assert v.features["username_entropy"] > 0.0  # Mix of alice and bob
    assert v.features["unique_hosts_targeted"] == 1.0
    assert v.features["mean_inter_arrival_time"] == 60.0  # 60s gaps between each
    assert v.features["inter_arrival_variance"] == 0.0  # Exactly constant gaps

    # Verify numpy conversion
    np_vec = v.to_numpy_vector()
    assert np_vec.shape == (10,)
    assert np_vec[0] == 4.0  # event_count is first


def test_feature_extractor_entropy_calculation():
    """Verify Shannon entropy is zero for single-user traffic and positive for multi-user spraying."""
    extractor = FeatureExtractor()

    # Single user -> zero entropy
    single_user = ["alice"] * 10
    assert extractor._calculate_entropy(single_user) == 0.0

    # Two equally balanced users -> entropy = 1.0 (log2(2))
    balanced_two = ["alice", "bob"] * 5
    assert extractor._calculate_entropy(balanced_two) == 1.0

    # Many distinct users (spray) -> high entropy
    diverse_users = [f"user_{i}" for i in range(8)]
    assert extractor._calculate_entropy(diverse_users) == 3.0  # log2(8)


def test_feature_extractor_ignores_non_auth_and_sub_threshold():
    """FeatureExtractor ignores non-authentication events and windows below min_events."""
    extractor = FeatureExtractor(
        config=MLConfig(feature_window_seconds=900, min_events_per_window=5)
    )

    # 3 events when min_events is 5 -> should produce 0 vectors
    events = [
        make_event("ev1", "2026-10-15T01:00:00Z"),
        make_event("ev2", "2026-10-15T01:01:00Z"),
        make_event("ev3", "2026-10-15T01:02:00Z"),
    ]
    assert extractor.extract_features_from_events(events) == []

    # Non-auth event type (e.g., session_logoff) should be excluded
    logoff_events = [
        make_event("ev1", "2026-10-15T01:00:00Z", event_type=EventType.SESSION_LOGOFF.value),
        make_event("ev2", "2026-10-15T01:01:00Z", event_type=EventType.SESSION_LOGOFF.value),
    ]
    assert extractor.extract_features_from_events(logoff_events) == []
