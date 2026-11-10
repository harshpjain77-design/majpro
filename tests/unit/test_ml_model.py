"""Unit tests for AnomalyDetector: Isolation Forest training, inference, and explainability."""

import os
import tempfile
import numpy as np
import pytest

from backend.ml.config import MLConfig
from backend.ml.model import AnomalyDetector
from backend.ml.schemas import FEATURE_NAMES, EntityFeatureVector


def make_vector(
    ip: str,
    event_count: float = 5.0,
    failure_count: float = 0.0,
    success_count: float = 5.0,
    failure_ratio: float = 0.0,
    unique_users: float = 1.0,
    entropy: float = 0.0,
    velocity: float = 1.0,
    mean_gap: float = 60.0,
    var_gap: float = 100.0,
) -> EntityFeatureVector:
    features = {
        "event_count": event_count,
        "failure_count": failure_count,
        "success_count": success_count,
        "failure_ratio": failure_ratio,
        "unique_usernames_targeted": unique_users,
        "username_entropy": entropy,
        "unique_hosts_targeted": 1.0,
        "auth_velocity_per_min": velocity,
        "mean_inter_arrival_time": mean_gap,
        "inter_arrival_variance": var_gap,
    }
    return EntityFeatureVector(
        entity_type="source_ip",
        entity_value=ip,
        window_start="2026-10-15T01:00:00Z",
        window_end="2026-10-15T01:15:00Z",
        features=features,
        event_ids=[f"ev_{ip}_{i}" for i in range(int(event_count))],
    )


def test_anomaly_detector_requires_fit_before_predict():
    """Unfitted model raises RuntimeError on predict."""
    detector = AnomalyDetector()
    vec = make_vector("192.168.1.1")
    with pytest.raises(RuntimeError, match="must be fitted before calling predict"):
        detector.predict([vec])


def test_anomaly_detector_training_and_inference():
    """Verify Isolation Forest training, baseline calculations, and outlier detection."""
    detector = AnomalyDetector(
        config=MLConfig(contamination=0.05, n_estimators=50, random_state=42, alert_threshold=0.60)
    )

    # 1. Generate 30 benign baseline vectors (low velocity, low failure ratio, single user)
    benign_vectors = [
        make_vector(
            ip=f"192.168.1.{i}",
            event_count=float(4 + (i % 4)),
            failure_count=0.0 if (i % 5 != 0) else 1.0,
            success_count=float(4 + (i % 4)) - (1.0 if (i % 5 == 0) else 0.0),
            failure_ratio=0.0 if (i % 5 != 0) else 0.2,
            unique_users=1.0,
            entropy=0.0,
            velocity=float(0.5 + (i % 3) * 0.3),
            mean_gap=float(40.0 + (i % 10) * 5.0),
        )
        for i in range(30)
    ]

    detector.fit(benign_vectors)
    assert detector.is_fitted
    assert detector.samples_trained_count == 30
    assert "event_count" in detector.baseline_means
    assert detector.baseline_means["failure_ratio"] < 0.10

    # 2. Predict on new benign sample
    test_benign = make_vector("10.0.0.1", event_count=5.0, velocity=0.8, failure_ratio=0.0)
    benign_res = detector.predict([test_benign])[0]
    assert not benign_res.is_anomaly
    assert benign_res.anomaly_score < 0.60

    # 3. Predict on aggressive brute-force outlier
    outlier = make_vector(
        "203.0.113.99",
        event_count=50.0,
        failure_count=50.0,
        success_count=0.0,
        failure_ratio=1.0,
        unique_users=10.0,
        entropy=3.32,
        velocity=45.0,
        mean_gap=1.2,
        var_gap=0.1,
    )
    outlier_res = detector.predict([outlier])[0]
    assert outlier_res.is_anomaly
    assert outlier_res.anomaly_score >= 0.60
    assert len(outlier_res.feature_attributions) == len(FEATURE_NAMES)

    # Check top feature attributions
    top_features = [a.feature_name for a in outlier_res.feature_attributions[:4]]
    # Extreme velocity, failure_ratio, or failure_count should be top drivers
    assert any(f in top_features for f in ["auth_velocity_per_min", "failure_count", "failure_ratio", "username_entropy"])


def test_anomaly_detector_deterministic_reproducibility():
    """Verify fixed random_state produces 100% identical predictions across runs."""
    cfg = MLConfig(random_state=42, n_estimators=50)

    train_set = [make_vector(f"192.168.1.{i}", velocity=1.0 + (i * 0.1)) for i in range(20)]
    test_vec = make_vector("203.0.113.1", velocity=30.0, failure_ratio=1.0)

    d1 = AnomalyDetector(config=cfg)
    d1.fit(train_set)
    res1 = d1.predict([test_vec])[0]

    d2 = AnomalyDetector(config=cfg)
    d2.fit(train_set)
    res2 = d2.predict([test_vec])[0]

    assert res1.anomaly_score == res2.anomaly_score
    assert res1.is_anomaly == res2.is_anomaly
    assert res1.raw_decision_score == res2.raw_decision_score


def test_anomaly_detector_persistence():
    """Verify model serialization and deserialization via joblib."""
    with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as tmp:
        model_path = tmp.name

    try:
        detector = AnomalyDetector(config=MLConfig(model_save_path=model_path, n_estimators=20))
        train_set = [make_vector(f"192.168.1.{i}") for i in range(15)]
        detector.fit(train_set)

        detector.save_model(model_path)

        # Restore into new instance
        new_detector = AnomalyDetector(config=MLConfig(model_save_path=model_path))
        new_detector.load_model(model_path)

        assert new_detector.is_fitted
        assert new_detector.samples_trained_count == 15
        assert new_detector.baseline_means == detector.baseline_means

        test_sample = make_vector("192.168.1.99", velocity=25.0, failure_ratio=1.0)
        res_original = detector.predict([test_sample])[0]
        res_loaded = new_detector.predict([test_sample])[0]

        assert res_original.anomaly_score == res_loaded.anomaly_score
        assert res_original.is_anomaly == res_loaded.is_anomaly
    finally:
        if os.path.exists(model_path):
            os.remove(model_path)
