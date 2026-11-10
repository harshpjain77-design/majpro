"""Converts machine learning anomaly detections into canonical SOC alerts."""

from typing import List, Optional
from backend.detection.schemas import Alert
from backend.ml.explainability import FeatureAttributor
from backend.ml.schemas import AnomalyResult


class MLAlertGenerator:
    """Translates anomalous ML predictions into standardized, correlated Security Alert records."""

    def __init__(self, attributor: Optional[FeatureAttributor] = None):
        self.attributor = attributor

    def results_to_alerts(self, anomaly_results: List[AnomalyResult]) -> List[Alert]:
        """Filter anomalous results and construct canonical Alert instances."""
        alerts: List[Alert] = []

        for res in anomaly_results:
            if not res.is_anomaly:
                continue

            # Determine severity based on calibrated anomaly score
            if res.anomaly_score >= 0.85:
                severity = "critical"
            elif res.anomaly_score >= 0.70:
                severity = "high"
            elif res.anomaly_score >= 0.50:
                severity = "medium"
            else:
                severity = "low"

            # Formulate explainable narrative
            if self.attributor:
                explanation = self.attributor.format_narrative(res.feature_attributions)
            else:
                top_features = ", ".join(
                    f"{a.feature_name}={a.observed_value}"
                    for a in res.feature_attributions[:2]
                )
                explanation = (
                    f"Statistical behavioral anomaly detected (score {res.anomaly_score:.2f}) "
                    f"characterized by: {top_features}."
                )

            # Map entities dictionary
            entities = {res.entity_type: res.entity_value}
            if res.entity_type == "source_ip":
                entities["source_ip"] = res.entity_value
            elif res.entity_type == "username":
                entities["username"] = res.entity_value

            top_attributions = [
                a.model_dump() for a in res.feature_attributions[:3]
            ]

            alert = Alert.create(
                rule_id="ML-ANOMALY-001",
                rule_name="Isolation Forest Behavioral Anomaly",
                severity=severity,
                first_observed=res.window_start,
                last_observed=res.window_end,
                related_event_ids=res.event_ids,
                explanation=explanation,
                supporting_evidence={
                    "anomaly_score": res.anomaly_score,
                    "raw_decision_score": res.raw_decision_score,
                    "features": res.features,
                    "top_attributions": top_attributions,
                },
                entities=entities,
                confidence=round(res.anomaly_score, 2),
                risk_score=round(res.anomaly_score * 100.0, 1),
                rule_version="1.0",
            )
            alerts.append(alert)

        return alerts
