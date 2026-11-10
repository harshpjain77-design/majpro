"""Isolation Forest anomaly detection model with feature scaling and attribution."""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from backend.ml.config import MLConfig, default_ml_config
from backend.ml.explainability import FeatureAttributor
from backend.ml.schemas import FEATURE_NAMES, AnomalyResult, EntityFeatureVector

logger = logging.getLogger("AnomalyDetector")


class AnomalyDetector:
    """Isolation Forest anomaly detector for behavioral authentication analytics."""

    def __init__(self, config: Optional[MLConfig] = None):
        self.config = config or default_ml_config
        self.model = IsolationForest(
            contamination=self.config.contamination,
            n_estimators=self.config.n_estimators,
            random_state=self.config.random_state,
            n_jobs=-1,
        )
        self.scaler = StandardScaler()
        self.is_fitted: bool = False
        self.baseline_means: Dict[str, float] = {name: 0.0 for name in FEATURE_NAMES}
        self.baseline_stds: Dict[str, float] = {name: 1.0 for name in FEATURE_NAMES}
        self.attributor: Optional[FeatureAttributor] = None
        self.samples_trained_count: int = 0

    def fit(self, feature_vectors: List[EntityFeatureVector]) -> None:
        """Fit scaler and Isolation Forest on benign baseline feature vectors."""
        if not feature_vectors:
            raise ValueError("Cannot train AnomalyDetector on an empty list of feature vectors.")

        X = np.array([v.to_numpy_vector() for v in feature_vectors], dtype=np.float64)

        # Compute empirical baseline statistics for feature attribution
        means = np.mean(X, axis=0)
        stds = np.std(X, axis=0)

        self.baseline_means = {name: float(means[idx]) for idx, name in enumerate(FEATURE_NAMES)}
        self.baseline_stds = {
            name: float(stds[idx]) if stds[idx] > 0 else 1.0
            for idx, name in enumerate(FEATURE_NAMES)
        }
        self.attributor = FeatureAttributor(self.baseline_means, self.baseline_stds)

        # Scale features and fit ensemble
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)

        self.is_fitted = True
        self.samples_trained_count = len(feature_vectors)
        logger.info(
            f"Fitted IsolationForest on {self.samples_trained_count} samples across {len(FEATURE_NAMES)} features."
        )

    def predict(self, feature_vectors: List[EntityFeatureVector]) -> List[AnomalyResult]:
        """Evaluate feature vectors and return scored anomaly results with explainable attributions."""
        if not self.is_fitted:
            raise RuntimeError("AnomalyDetector must be fitted before calling predict.")

        if not feature_vectors:
            return []

        X = np.array([v.to_numpy_vector() for v in feature_vectors], dtype=np.float64)
        X_scaled = self.scaler.transform(X)

        raw_preds = self.model.predict(X_scaled)  # +1 normal, -1 anomaly
        raw_decisions = self.model.decision_function(X_scaled)  # Lower is more anomalous

        results: List[AnomalyResult] = []
        for idx, vec in enumerate(feature_vectors):
            dec = float(raw_decisions[idx])
            raw_pred = raw_preds[idx]

            # Invert and scale decision function to [0.0, 1.0] anomaly score
            # A negative decision function value indicates outlier (< 0 maps to >= 0.50; >= 0 maps to < 0.50)
            if dec < 0:
                normalized_score = float(np.clip(0.50 + (-dec / 0.10) * 0.50, 0.50, 1.0))
            else:
                normalized_score = float(np.clip(0.50 - (dec / 0.20) * 0.50, 0.0, 0.50))

            is_anomaly = bool(raw_pred == -1 or normalized_score >= self.config.alert_threshold)

            attributions = (
                self.attributor.explain(vec.features) if self.attributor else []
            )

            results.append(
                AnomalyResult(
                    entity_type=vec.entity_type,
                    entity_value=vec.entity_value,
                    window_start=vec.window_start,
                    window_end=vec.window_end,
                    is_anomaly=is_anomaly,
                    anomaly_score=round(normalized_score, 4),
                    raw_decision_score=round(dec, 4),
                    feature_attributions=attributions,
                    event_ids=list(vec.event_ids),
                    features=dict(vec.features),
                )
            )

        return results

    def save_model(self, path: Optional[str] = None) -> str:
        """Serialize model, scaler, and baseline parameters to disk using joblib."""
        target_path = Path(path or self.config.model_save_path)
        target_path.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "model": self.model,
            "scaler": self.scaler,
            "baseline_means": self.baseline_means,
            "baseline_stds": self.baseline_stds,
            "samples_trained_count": self.samples_trained_count,
            "config": self.config.model_dump(),
        }
        joblib.dump(payload, str(target_path))
        logger.info(f"Saved AnomalyDetector model artifact to {target_path}")
        return str(target_path)

    def load_model(self, path: Optional[str] = None) -> None:
        """Load model artifact from disk."""
        target_path = Path(path or self.config.model_save_path)
        if not target_path.exists():
            raise FileNotFoundError(f"Model file not found at {target_path}")

        payload = joblib.load(str(target_path))
        self.model = payload["model"]
        self.scaler = payload["scaler"]
        self.baseline_means = payload["baseline_means"]
        self.baseline_stds = payload["baseline_stds"]
        self.samples_trained_count = payload.get("samples_trained_count", 0)
        self.attributor = FeatureAttributor(self.baseline_means, self.baseline_stds)
        self.is_fitted = True
        logger.info(f"Loaded AnomalyDetector model artifact from {target_path}")
