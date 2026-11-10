"""RULE-001: Repeated failed authentication attempts from one source (Brute Force)."""

from collections import defaultdict
from typing import Dict, List

from collectors.common.schemas import EventType, SecurityEvent, Severity
from backend.detection.config import DetectionConfig, default_config
from backend.detection.rules.base import BaseRule, parse_timestamp_epoch
from backend.detection.schemas import Alert


class SingleSourceBruteForceRule(BaseRule):
    """Detects repeated authentication failures originating from a single source address."""

    rule_id: str = "RULE-001"
    rule_version: str = "1.0"
    name: str = "Repeated Failed Authentications from Single Source"
    description: str = "Flags multiple failed authentication attempts originating from a single IP address within a configurable window."
    default_severity: str = Severity.MEDIUM.value

    def __init__(self, config: DetectionConfig = default_config):
        self.config = config

    def evaluate(self, events: List[SecurityEvent]) -> List[Alert]:
        alerts: List[Alert] = []

        # Filter for authentication failures with an identifiable source IP
        failures = [
            e for e in events
            if e.event_type == EventType.AUTHENTICATION_FAILURE.value and e.source_ip
        ]
        if not failures:
            return []

        # Group by source IP
        by_ip: Dict[str, List[SecurityEvent]] = defaultdict(list)
        for ev in failures:
            by_ip[ev.source_ip].append(ev)

        threshold = self.config.rule_1_failed_threshold
        window = self.config.rule_1_window_seconds

        for ip, ip_events in by_ip.items():
            # Sort chronologically by timestamp
            ip_events.sort(key=lambda x: parse_timestamp_epoch(x.timestamp))

            # Sliding window evaluation
            window_events: List[SecurityEvent] = []
            for ev in ip_events:
                t_ev = parse_timestamp_epoch(ev.timestamp)
                window_events.append(ev)

                # Evict events outside the time window
                while window_events and (t_ev - parse_timestamp_epoch(window_events[0].timestamp)) > window:
                    window_events.pop(0)

                # If threshold is reached within window
                if len(window_events) >= threshold:
                    first_ev = window_events[0]
                    last_ev = window_events[-1]
                    count = len(window_events)

                    targeted_users = list({e.username for e in window_events if e.username})
                    event_ids = [e.event_id for e in window_events]
                    hosts = list({e.source_host for e in window_events if e.source_host})
                    target_host = hosts[0] if hosts else "unknown"

                    severity = Severity.HIGH.value if count >= (threshold * 2) else Severity.MEDIUM.value
                    confidence = min(0.95, 0.70 + (count * 0.03))
                    risk = min(90.0, 45.0 + (count * 4.0))

                    alert = Alert.create(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        severity=severity,
                        first_observed=first_ev.timestamp,
                        last_observed=last_ev.timestamp,
                        related_event_ids=event_ids,
                        explanation=(
                            f"Observed {count} failed authentication attempts originating from source IP "
                            f"'{ip}' within a {window}-second window targeting {len(targeted_users)} account(s)."
                        ),
                        supporting_evidence={
                            "failure_count": count,
                            "time_window_seconds": window,
                            "targeted_users": targeted_users,
                            "source_ip": ip,
                        },
                        entities={
                            "source_ip": ip,
                            "host": target_host,
                            "usernames": targeted_users,
                        },
                        confidence=round(confidence, 2),
                        risk_score=round(risk, 1),
                    )
                    alerts.append(alert)
                    # Clear window to avoid emitting duplicate alerts for overlapping subsets
                    window_events = []

        return alerts
