"""Unit and integration tests for ML alert generation, incident correlation, and REST API."""

import os
import tempfile
import pytest
from fastapi.testclient import TestClient

from backend.api.config import settings
from backend.api.dependencies import incident_repo, storage_sink
from backend.api.main import app
from backend.api.routes.ml import anomaly_detector
from backend.correlation.correlator import IncidentCorrelator
from backend.correlation.deduplicator import AlertDeduplicator
from backend.ml.alert_generator import MLAlertGenerator
from backend.ml.explainability import FeatureAttributor
from backend.ml.schemas import AnomalyResult, FeatureAttribution

VALID_KEY = next(iter(settings.VALID_API_KEYS))
AUTH_HEADERS = {"X-API-Key": VALID_KEY}


@pytest.fixture(autouse=True)
def isolated_storage():
    """Ensure clean temporary SQLite database for each test."""
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tmp:
        db_path = tmp.name

    original_sink_db = storage_sink.db_path
    original_inc_db = incident_repo.db_path

    storage_sink.db_path = db_path
    storage_sink._conn = None
    storage_sink._init_db()

    incident_repo.db_path = db_path
    incident_repo._conn = None
    incident_repo._init_db()

    yield

    if storage_sink._conn:
        storage_sink._conn.close()
        storage_sink._conn = None
    if incident_repo._conn:
        incident_repo._conn.close()
        incident_repo._conn = None

    storage_sink.db_path = original_sink_db
    incident_repo.db_path = original_inc_db

    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except Exception:
            pass


def test_ml_alert_generator_and_correlation_pipeline():
    """Verify MLAlertGenerator creates valid canonical Alerts that cleanly feed into correlation."""
    attributions = [
        FeatureAttribution(
            feature_name="auth_velocity_per_min",
            observed_value=25.0,
            baseline_mean=0.8,
            baseline_std=0.2,
            z_score=121.0,
            contribution_ratio=0.75,
        ),
        FeatureAttribution(
            feature_name="failure_ratio",
            observed_value=1.0,
            baseline_mean=0.04,
            baseline_std=0.02,
            z_score=48.0,
            contribution_ratio=0.25,
        ),
    ]

    result = AnomalyResult(
        entity_type="source_ip",
        entity_value="198.51.100.77",
        window_start="2026-10-15T08:00:00Z",
        window_end="2026-10-15T08:15:00Z",
        is_anomaly=True,
        anomaly_score=0.88,
        raw_decision_score=-0.19,
        feature_attributions=attributions,
        event_ids=["ev_ml_1", "ev_ml_2"],
        features={"auth_velocity_per_min": 25.0, "failure_ratio": 1.0},
    )

    attributor = FeatureAttributor(
        baseline_means={"auth_velocity_per_min": 0.8, "failure_ratio": 0.04},
        baseline_stds={"auth_velocity_per_min": 0.2, "failure_ratio": 0.02},
    )
    generator = MLAlertGenerator(attributor=attributor)
    alerts = generator.results_to_alerts([result])

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "ML-ANOMALY-001"
    assert alert.severity == "critical"  # score 0.88 >= 0.85
    assert alert.fingerprint.startswith("fp_")
    assert alert.alert_id.startswith("alt_")
    assert alert.entities["source_ip"] == "198.51.100.77"
    assert "Statistical behavioral anomaly" in alert.explanation

    # Feed ML alert into Deduplicator
    deduplicator = AlertDeduplicator()
    dedup = deduplicator.process_alert(alert)
    assert dedup.occurrence_count == 1
    assert dedup.rule_id == "ML-ANOMALY-001"

    # Feed into Correlator
    correlator = IncidentCorrelator()
    incidents = correlator.correlate_alerts([alert])
    assert len(incidents) == 1
    inc = incidents[0]
    assert "198.51.100.77" in inc.entities["source_ips"]
    assert "ML-ANOMALY-001" in inc.distinct_rules


def test_ml_api_unauthenticated_rejected():
    """Unauthenticated requests must receive HTTP 401."""
    client = TestClient(app)
    resp = client.get("/api/v1/ml/status")
    assert resp.status_code == 401


def test_ml_api_status():
    """Verify /api/v1/ml/status returns metadata and hyperparameter config."""
    client = TestClient(app)
    resp = client.get("/api/v1/ml/status", headers=AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert "is_trained" in data
    assert "contamination" in data
    assert "features_tracked" in data
    assert len(data["features_tracked"]) == 10


def test_ml_api_benchmark_endpoint():
    """Verify /api/v1/ml/benchmark executes evaluation pipeline and returns valid metrics."""
    client = TestClient(app)
    resp = client.get("/api/v1/ml/benchmark?seed=42", headers=AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_samples"] > 0
    assert data["precision"] >= 0.60
    assert data["recall"] >= 0.60
    assert data["f1_score"] >= 0.60
    assert "rule_comparison" in data
    assert data["rule_comparison"]["isolation_forest"]["slow_and_low_detected"] is True


def test_ml_api_train_and_detect_flow():
    """Test full API train and detect lifecycle on stored events."""
    client = TestClient(app)

    # 1. Ingest benign training events
    events = [
        {
            "schema_version": "1.0",
            "event_id": f"evt_train_{i}",
            "timestamp": f"2026-10-15T01:{i:02d}:00Z",
            "observed_at": f"2026-10-15T01:{i:02d}:00Z",
            "source_host": "srv1",
            "source_type": "linux_auth",
            "event_type": "authentication_success",
            "username": "alice",
            "source_ip": "192.168.1.15",
            "severity": "low",
            "raw_event": f"Accepted password for alice {i}",
        }
        for i in range(10)
    ]
    resp_ingest = client.post("/api/v1/ingest/batch", headers=AUTH_HEADERS, json={"events": events})
    assert resp_ingest.status_code == 200

    # 2. Train model via API
    resp_train = client.post("/api/v1/ml/train", headers=AUTH_HEADERS, json={"limit": 100})
    assert resp_train.status_code == 200
    train_data = resp_train.json()
    assert train_data["status"] == "success"
    assert train_data["samples_trained"] >= 1

    # 3. Detect anomalies via API
    resp_detect = client.post("/api/v1/ml/detect", headers=AUTH_HEADERS)
    assert resp_detect.status_code == 200
    detect_data = resp_detect.json()
    assert "anomalies_detected" in detect_data
    assert "alerts" in detect_data
