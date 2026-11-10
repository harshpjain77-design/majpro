"""Configuration settings and hyperparameters for Machine Learning Anomaly Detection."""

from pydantic import BaseModel, Field


class MLConfig(BaseModel):
    """Hyperparameters and configuration for Isolation Forest anomaly detection."""

    # Contamination factor: estimated proportion of outliers in the data
    contamination: float = Field(
        default=0.05,
        ge=0.001,
        le=0.5,
        description="Expected proportion of outliers in training dataset",
    )

    # Number of trees in the Isolation Forest ensemble
    n_estimators: int = Field(
        default=100,
        ge=10,
        le=500,
        description="Number of base estimators in the Isolation Forest",
    )

    # Fixed random seed for complete scientific reproducibility
    random_state: int = Field(
        default=42,
        description="Random seed ensuring deterministic training and evaluation",
    )

    # Sliding window length in seconds over which features are aggregated per entity
    feature_window_seconds: int = Field(
        default=900,  # 15 minutes
        ge=60,
        le=86400,
        description="Time window in seconds to aggregate behavioral metrics per entity",
    )

    # Minimum events required in a window before extracting features for an entity
    min_events_per_window: int = Field(
        default=3,
        ge=1,
        le=100,
        description="Minimum event count required to generate a feature vector",
    )

    # Anomaly score threshold (0.0 to 1.0) above which an alert is generated
    alert_threshold: float = Field(
        default=0.60,
        ge=0.0,
        le=1.0,
        description="Normalized anomaly score threshold triggering a security alert",
    )

    # Model persistence file path
    model_save_path: str = Field(
        default="output/isolation_forest_model.joblib",
        description="Default disk path to serialize/deserialize trained model artifacts",
    )


default_ml_config = MLConfig()
