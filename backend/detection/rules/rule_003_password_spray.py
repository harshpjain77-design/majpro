"""RULE-003: Repeated failures against one account from multiple sources (Password Spraying)."""

from collections import defaultdict
from typing import Dict, List

from collectors.common.schemas import EventType, SecurityEvent, Severity
from backend.detection.config import DetectionConfig, default_config
from backend.detection.rules.base import BaseRule, parse_timestamp_epoch
from backend.detection.schemas import Alert


class DistributedPasswordSprayRule(BaseRule):
    """Detects failed authentications against a single target account originating from multiple distinct sources."""

    rule_id: str = "RULE-003"
    rule_version: str = "1.0"
    name: str = "Multi-Source Authentication Failures on Single Account"
    description: str = "Flags multiple failed logins against a single account originating from distinct source IPs within a configurable window (distributed password spray indicator)."
    default_severity: str = Severity.HIGH.value

    def __init__(self, config: DetectionConfig = default_config):
        self.config = config

    def evaluate(self, events: List[SecurityEvent]) -> List[Alert]:
        alerts: List[Alert] = []

        failures = [
            e for e in events
            if e.event_type == EventType.AUTHENTICATION_FAILURE.value
            and e.username
            and e.source_ip
        ]
        if not failures:
            return []

        # Group by target account username
        by_user: Dict[str, List[SecurityEvent]] = defaultdict(list)
        for ev in failures:
            by_user[ev.username.lower()].append(ev)

        threshold = self.config.rule_3_distinct_sources_threshold
        window = self.config.rule_3_window_seconds

        for username, user_events in by_user.items():
            user_events.sort(key=lambda x: parse_timestamp_epoch(x.timestamp))

            # Sliding window evaluation
            window_events: List[SecurityEvent] = []
            for ev in user_events:
                t_ev = parse_timestamp_epoch(ev.timestamp)
                window_events.append(ev)

                # Evict events outside time window
                while window_events and (t_ev - parse_timestamp_epoch(window_events[0].timestamp)) > window:
                    window_events.pop(0)

                distinct_ips = {e.source_ip for e in window_events if e.source_ip}
                if len(distinct_ips) >= threshold:
                    first_ev = window_events[0]
                    last_ev = window_events[-1]
                    event_ids = [e.event_id for e in window_events]
                    hosts = list({e.source_host for e in window_events if e.source_host})

                    alert = Alert.create(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        severity=Severity.HIGH.value,
                        first_observed=first_ev.timestamp,
                        last_observed=last_ev.timestamp,
                        related_event_ids=event_ids,
                        explanation=(
                            f"Target account '{first_ev.username}' experienced failed authentication attempts "
                            f"originating from {len(distinct_ips)} distinct source IPs within {window} seconds."
                        ),
                        supporting_evidence={
                            "distinct_source_count": len(distinct_ips),
                            "distinct_source_ips": sorted(list(distinct_ips)),
                            "total_failure_count": len(window_events),
                            "time_window_seconds": window,
                        },
                        entities={
                            "username": first_ev.username,
                            "source_ips": sorted(list(distinct_ips)),
                            "host": hosts[0] if hosts else "unknown",
                        },
                        confidence=0.85,
                        risk_score=75.0,
                    )
                    alerts.append(alert)
                    # Reset window to prevent duplicate alerts for overlapping subsets
                    window_events = []

        return alerts
