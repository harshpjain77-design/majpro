"""Machine Learning Anomaly Detection module for behavioral security analytics."""

from backend.ml.alert_generator import MLAlertGenerator
from backend.ml.config import MLConfig, default_ml_config
from backend.ml.evaluation import evaluate_ml_pipeline, generate_synthetic_benchmark_dataset
from backend.ml.explainability import FeatureAttributor
from backend.ml.features import FeatureExtractor
from backend.ml.model import AnomalyDetector
from backend.ml.schemas import (
    FEATURE_NAMES,
    AnomalyResult,
    EntityFeatureVector,
    EvaluationMetrics,
    FeatureAttribution,
)

__all__ = [
    "AnomalyDetector",
    "AnomalyResult",
    "EntityFeatureVector",
    "EvaluationMetrics",
    "FEATURE_NAMES",
    "FeatureAttribution",
    "FeatureAttributor",
    "FeatureExtractor",
    "MLAlertGenerator",
    "MLConfig",
    "default_ml_config",
    "evaluate_ml_pipeline",
    "generate_synthetic_benchmark_dataset",
]
