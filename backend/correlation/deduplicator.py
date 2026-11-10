"""Alert deduplicator grouping identical alert signatures within sliding windows."""

import hashlib
import logging
from typing import Any, Dict, List, Optional

from backend.detection.rules.base import parse_timestamp_epoch
from backend.detection.schemas import Alert
from backend.correlation.config import CorrelationConfig, default_correlation_config
from backend.correlation.schemas import DeduplicatedAlert, DeduplicationMetrics

logger = logging.getLogger("AlertDeduplicator")

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def get_severity_rank(sev: str) -> int:
    return SEVERITY_ORDER.get(sev.lower(), 1)


class AlertDeduplicator:
    """Collapses repetitive firings of the same alert fingerprint into unified records."""

    def __init__(self, config: Optional[CorrelationConfig] = None):
        self.config = config or default_correlation_config
        self.total_alerts_received: int = 0
        self.total_incidents_created: int = 0
        self._active_windows: Dict[str, DeduplicatedAlert] = {}
        self._closed_aggregates: List[DeduplicatedAlert] = []

    def _derive_fingerprint(self, alert: Alert) -> str:
        """Derive deterministic fingerprint if alert does not already have one."""
        if alert.fingerprint:
            return alert.fingerprint
        entities = alert.entities or {}
        primary = (
            entities.get("source_ip")
            or entities.get("username")
            or entities.get("host")
            or "global"
        )
        fp_hasher = hashlib.sha256()
        fp_hasher.update(alert.rule_id.encode("utf-8"))
        fp_hasher.update(b"|")
        fp_hasher.update(str(primary).lower().encode("utf-8"))
        return f"fp_{fp_hasher.hexdigest()[:24]}"

    def process_alert(self, alert: Alert) -> DeduplicatedAlert:
        """Process a single incoming alert, merging into an active sliding window or starting a new one."""
        self.total_alerts_received += 1
        fp = self._derive_fingerprint(alert)
        t_alert_start = parse_timestamp_epoch(alert.first_observed)
        t_alert_end = parse_timestamp_epoch(alert.last_observed)

        if fp in self._active_windows:
            active = self._active_windows[fp]
            t_last_seen = parse_timestamp_epoch(active.last_seen)

            # Check if alert falls within the deduplication sliding window
            if (t_alert_start - t_last_seen) <= self.config.deduplication_window_seconds:
                # Merge into existing active window
                active.occurrence_count += 1
                if t_alert_end > t_last_seen:
                    active.last_seen = alert.last_observed

                if alert.alert_id not in active.contributing_alert_ids:
                    active.contributing_alert_ids.append(alert.alert_id)

                for eid in alert.related_event_ids:
                    if eid not in active.related_event_ids:
                        active.related_event_ids.append(eid)

                # Update severity if higher
                if get_severity_rank(alert.severity) > get_severity_rank(active.severity):
                    active.severity = alert.severity

                # Merge supporting evidence
                ev_counts = active.supporting_evidence.get("total_failures", 0)
                add_counts = alert.supporting_evidence.get("failure_count", 0)
                if add_counts:
                    active.supporting_evidence["total_failures"] = ev_counts + add_counts
                active.supporting_evidence["latest_occurrence"] = alert.last_observed

                # Escalate risk score incrementally for persistent repetition
                active.risk_score = round(min(100.0, active.risk_score + 2.0), 1)
                return active
            else:
                # Previous sliding window expired; close it and start a new one
                self._closed_aggregates.append(active)
                del self._active_windows[fp]

        # Start a new deduplication window
        hasher = hashlib.sha256()
        hasher.update(fp.encode())
        hasher.update(alert.first_observed.encode())
        dedup_id = f"dup_{hasher.hexdigest()[:20]}"

        new_aggregate = DeduplicatedAlert(
            dedup_id=dedup_id,
            fingerprint=fp,
            rule_id=alert.rule_id,
            rule_name=alert.rule_name,
            severity=alert.severity,
            occurrence_count=1,
            first_seen=alert.first_observed,
            last_seen=alert.last_observed,
            primary_alert_id=alert.alert_id,
            contributing_alert_ids=[alert.alert_id],
            related_event_ids=list(alert.related_event_ids),
            entities=dict(alert.entities),
            explanation=alert.explanation,
            supporting_evidence=dict(alert.supporting_evidence),
            risk_score=alert.risk_score,
        )
        self._active_windows[fp] = new_aggregate
        return new_aggregate

    def deduplicate_batch(self, alerts: List[Alert]) -> List[DeduplicatedAlert]:
        """Batch-process a list of alerts chronologically, returning deduplicated aggregates."""
        if not alerts:
            return []

        # Sort chronologically by first_observed timestamp
        sorted_alerts = sorted(alerts, key=lambda a: parse_timestamp_epoch(a.first_observed))
        for alert in sorted_alerts:
            self.process_alert(alert)

        return self.get_all_aggregates()

    def get_all_aggregates(self) -> List[DeduplicatedAlert]:
        """Return all deduplicated alerts across closed and currently open windows."""
        return list(self._closed_aggregates) + list(self._active_windows.values())

    def get_metrics(self) -> DeduplicationMetrics:
        """Calculate and return operational deduplication metrics."""
        emitted = len(self._closed_aggregates) + len(self._active_windows)
        received = self.total_alerts_received
        reduction = max(0, received - emitted)
        ratio = (reduction / received) if received > 0 else 0.0

        return DeduplicationMetrics(
            total_alerts_received=received,
            deduplicated_alerts_emitted=emitted,
            raw_alert_reduction_count=reduction,
            deduplication_ratio=round(ratio, 4),
            total_incidents_created=self.total_incidents_created,
        )
