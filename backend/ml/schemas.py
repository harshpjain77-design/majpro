"""Data schemas for feature vectors, anomaly detection results, and model evaluation."""

from typing import Any, Dict, List, Optional
import numpy as np
from pydantic import BaseModel, ConfigDict, Field

FEATURE_NAMES: List[str] = [
    "event_count",
    "failure_count",
    "success_count",
    "failure_ratio",
    "unique_usernames_targeted",
    "username_entropy",
    "unique_hosts_targeted",
    "auth_velocity_per_min",
    "mean_inter_arrival_time",
    "inter_arrival_variance",
]


class EntityFeatureVector(BaseModel):
    """Behavioral statistical feature vector extracted from an entity's event window."""

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="allow")

    entity_type: str = Field(..., description="Type of entity: 'source_ip' or 'username'")
    entity_value: str = Field(..., description="Entity identifier (e.g. IP address or username)")
    window_start: str = Field(..., description="Start of evaluated sliding window (UTC ISO-8601)")
    window_end: str = Field(..., description="End of evaluated sliding window (UTC ISO-8601)")
    features: Dict[str, float] = Field(..., description="Dictionary of named numerical features")
    event_ids: List[str] = Field(default_factory=list, description="IDs of contributing raw events")

    def to_numpy_vector(self) -> np.ndarray:
        """Convert features dictionary to a 1D numpy array in consistent feature order."""
        return np.array([self.features.get(name, 0.0) for name in FEATURE_NAMES], dtype=np.float64)


class FeatureAttribution(BaseModel):
    """Contribution metric explaining why an individual feature triggered the anomaly."""

    feature_name: str
    observed_value: float
    baseline_mean: float
    baseline_std: float
    z_score: float
    contribution_ratio: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Relative proportion of anomaly attribution accounted for by this feature",
    )


class AnomalyResult(BaseModel):
    """Result of Isolation Forest evaluation on a single entity feature vector."""

    entity_type: str
    entity_value: str
    window_start: str
    window_end: str
    is_anomaly: bool
    anomaly_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Normalized anomaly score: 0.0 (normal) to 1.0 (highly anomalous)",
    )
    raw_decision_score: float = Field(
        ...,
        description="Raw output from scikit-learn decision_function (lower is more anomalous)",
    )
    feature_attributions: List[FeatureAttribution] = Field(
        default_factory=list,
        description="Ranked list of feature contributions explaining the anomaly",
    )
    event_ids: List[str] = Field(default_factory=list)
    features: Dict[str, float] = Field(default_factory=dict)


class EvaluationMetrics(BaseModel):
    """Standardized performance metrics for leakage-free train/test evaluation."""

    total_samples: int
    benign_samples: int
    anomalous_samples: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    accuracy: float
    rule_comparison: Dict[str, Any] = Field(
        default_factory=dict,
        description="Comparative detection overlap and divergence metrics against deterministic rules",
    )


class TrainRequest(BaseModel):
    """Request payload to fit the Isolation Forest model on historical repository events."""

    start_time: Optional[str] = None
    end_time: Optional[str] = None
    limit: int = Field(default=5000, ge=10, le=20000)


class TrainResponse(BaseModel):
    """Response returned upon training completion."""

    status: str
    samples_trained: int
    feature_dimensions: int
    baseline_means: Dict[str, float]
    baseline_stds: Dict[str, float]
    model_path: str


class ModelStatusResponse(BaseModel):
    """Current state and metadata for the ML anomaly model."""

    is_trained: bool
    contamination: float
    n_estimators: int
    random_state: int
    feature_window_seconds: int
    features_tracked: List[str]
    baseline_samples_count: int
