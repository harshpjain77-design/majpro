"""Explainable feature attribution for Isolation Forest anomaly detections."""

from typing import Dict, List, Tuple
from backend.ml.schemas import FEATURE_NAMES, FeatureAttribution

EPSILON = 1e-6


class FeatureAttributor:
    """Calculates feature-level deviations and attribution proportions explaining anomaly scores."""

    def __init__(
        self,
        baseline_means: Dict[str, float],
        baseline_stds: Dict[str, float],
    ):
        self.baseline_means = baseline_means
        self.baseline_stds = baseline_stds

    def explain(
        self,
        observed_features: Dict[str, float],
    ) -> List[FeatureAttribution]:
        """Compute ranked z-score deviations and attribution weights for an observation."""
        deviations: List[Tuple[str, float, float, float, float]] = []
        positive_z_sum = 0.0

        for name in FEATURE_NAMES:
            obs = observed_features.get(name, 0.0)
            mean = self.baseline_means.get(name, 0.0)
            std = self.baseline_stds.get(name, 1.0)
            if std <= 0.0:
                std = 1.0

            z = (obs - mean) / (std + EPSILON)
            pos_z = max(0.0, z)
            positive_z_sum += pos_z
            deviations.append((name, obs, mean, std, z))

        attributions: List[FeatureAttribution] = []
        for name, obs, mean, std, z in deviations:
            pos_z = max(0.0, z)
            ratio = (pos_z / (positive_z_sum + EPSILON)) if positive_z_sum > 0 else 0.0

            attributions.append(
                FeatureAttribution(
                    feature_name=name,
                    observed_value=round(obs, 4),
                    baseline_mean=round(mean, 4),
                    baseline_std=round(std, 4),
                    z_score=round(z, 2),
                    contribution_ratio=round(ratio, 4),
                )
            )

        # Sort descending by contribution ratio
        attributions.sort(key=lambda x: x.contribution_ratio, reverse=True)
        return attributions

    def format_narrative(
        self,
        attributions: List[FeatureAttribution],
        top_k: int = 3,
    ) -> str:
        """Format top-k contributing features into an objective, evidence-based analyst explanation."""
        significant = [a for a in attributions if a.contribution_ratio > 0.05][:top_k]
        if not significant:
            significant = attributions[:top_k]

        parts = []
        for a in significant:
            pct = int(round(a.contribution_ratio * 100))
            parts.append(
                f"{a.feature_name}={a.observed_value:.2f} (baseline mean {a.baseline_mean:.2f}, "
                f"+{a.z_score:.1f}σ deviation, {pct}% contribution)"
            )

        return "Statistical behavioral anomaly driven by: " + "; ".join(parts) + "."
