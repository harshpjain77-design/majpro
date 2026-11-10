"""Machine Learning anomaly detection and benchmark evaluation API endpoints."""

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.api.dependencies import incident_repo, storage_sink, verify_api_key
from backend.detection.schemas import Alert
from backend.ml.alert_generator import MLAlertGenerator
from backend.ml.config import default_ml_config
from backend.ml.evaluation import evaluate_ml_pipeline, generate_synthetic_benchmark_dataset
from backend.ml.features import FeatureExtractor
from backend.ml.model import AnomalyDetector
from backend.ml.schemas import (
    FEATURE_NAMES,
    AnomalyResult,
    EvaluationMetrics,
    ModelStatusResponse,
    TrainRequest,
    TrainResponse,
)
from backend.storage.models import EventFilter, PaginationParams

logger = logging.getLogger("MLApiRouter")

router = APIRouter(
    prefix="/api/v1/ml",
    tags=["Machine Learning Anomaly Detection"],
    dependencies=[Depends(verify_api_key)],
)

# Global model and feature extractor instances
anomaly_detector = AnomalyDetector(config=default_ml_config)
feature_extractor = FeatureExtractor(config=default_ml_config)


@router.get("/status", response_model=ModelStatusResponse)
async def get_model_status() -> ModelStatusResponse:
    """Return current Isolation Forest training status and tracked features."""
    return ModelStatusResponse(
        is_trained=anomaly_detector.is_fitted,
        contamination=anomaly_detector.config.contamination,
        n_estimators=anomaly_detector.config.n_estimators,
        random_state=anomaly_detector.config.random_state,
        feature_window_seconds=anomaly_detector.config.feature_window_seconds,
        features_tracked=FEATURE_NAMES,
        baseline_samples_count=anomaly_detector.samples_trained_count,
    )


@router.post("/train", response_model=TrainResponse)
async def train_model(payload: TrainRequest) -> TrainResponse:
    """Fit Isolation Forest on historical events stored in the repository."""
    filters = EventFilter(start_time=payload.start_time, end_time=payload.end_time)
    pagination = PaginationParams(limit=payload.limit, offset=0)

    res = storage_sink.search_events(filters=filters, pagination=pagination)
    if len(res.events) < 5:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Insufficient events in repository to train anomaly model (minimum 5 required).",
        )

    vectors = feature_extractor.extract_features_from_events(res.events, entity_key="source_ip")
    if not vectors:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No valid behavioral feature windows could be extracted from provided events.",
        )

    anomaly_detector.fit(vectors)
    saved_path = anomaly_detector.save_model()

    return TrainResponse(
        status="success",
        samples_trained=len(vectors),
        feature_dimensions=len(FEATURE_NAMES),
        baseline_means=anomaly_detector.baseline_means,
        baseline_stds=anomaly_detector.baseline_stds,
        model_path=saved_path,
    )


@router.post("/detect")
async def detect_anomalies(
    start_time: Optional[str] = Query(None, description="Start time for evaluated window"),
    end_time: Optional[str] = Query(None, description="End time for evaluated window"),
    limit: int = Query(1000, ge=1, le=5000, description="Max events to pull"),
    correlate: bool = Query(True, description="Whether to correlate ML anomaly alerts into incidents"),
):
    """Run Isolation Forest anomaly detection on stored events and synthesize alerts."""
    if not anomaly_detector.is_fitted:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Anomaly model is not trained yet. Call /api/v1/ml/train first or run benchmark.",
        )

    filters = EventFilter(start_time=start_time, end_time=end_time)
    pagination = PaginationParams(limit=limit, offset=0)
    res = storage_sink.search_events(filters=filters, pagination=pagination)

    vectors = feature_extractor.extract_features_from_events(res.events, entity_key="source_ip")
    if not vectors:
        return {"anomalies_detected": 0, "alerts": [], "results": []}

    predictions = anomaly_detector.predict(vectors)
    alert_gen = MLAlertGenerator(attributor=anomaly_detector.attributor)
    alerts = alert_gen.results_to_alerts(predictions)

    # Correlate into incidents if requested
    if correlate and alerts:
        incident_repo.correlate_and_persist(alerts=alerts, event_repo=storage_sink)

    return {
        "anomalies_detected": len(alerts),
        "alerts": alerts,
        "results": [p.model_dump() for p in predictions if p.is_anomaly],
    }


@router.get("/benchmark", response_model=EvaluationMetrics)
async def run_evaluation_benchmark(
    seed: int = Query(42, description="Random seed for reproducible evaluation dataset"),
) -> EvaluationMetrics:
    """Execute leakage-free train/test evaluation benchmark and return precision/recall/F1 metrics."""
    train_events, test_events, ground_truth = generate_synthetic_benchmark_dataset(seed=seed)
    metrics = evaluate_ml_pipeline(
        train_events=train_events,
        test_events=test_events,
        ground_truth_labels=ground_truth,
        ml_config=anomaly_detector.config,
    )
    return metrics
