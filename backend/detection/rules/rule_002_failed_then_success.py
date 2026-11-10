"""RULE-002: Failed logins followed by a successful login (Potential Compromise)."""

from collections import defaultdict
from typing import Dict, List

from collectors.common.schemas import EventType, SecurityEvent, Severity
from backend.detection.config import DetectionConfig, default_config
from backend.detection.rules.base import BaseRule, parse_timestamp_epoch
from backend.detection.schemas import Alert


class FailedFollowedBySuccessRule(BaseRule):
    """Detects multiple failed logins followed shortly by a successful authentication."""

    rule_id: str = "RULE-002"
    rule_version: str = "1.0"
    name: str = "Failed Logins Followed by Successful Authentication"
    description: str = "Flags scenarios where an account experiences multiple consecutive failures followed by a successful logon within a temporal window."
    default_severity: str = Severity.HIGH.value

    def __init__(self, config: DetectionConfig = default_config):
        self.config = config

    def evaluate(self, events: List[SecurityEvent]) -> List[Alert]:
        alerts: List[Alert] = []

        # Filter for auth events that have a username
        auth_events = [
            e for e in events
            if e.event_type in {
                EventType.AUTHENTICATION_FAILURE.value,
                EventType.AUTHENTICATION_SUCCESS.value,
            }
            and e.username
        ]
        if not auth_events:
            return []

        # Group by target account username
        by_user: Dict[str, List[SecurityEvent]] = defaultdict(list)
        for ev in auth_events:
            by_user[ev.username.lower()].append(ev)

        fail_threshold = self.config.rule_2_fail_threshold
        window = self.config.rule_2_window_seconds

        for username, user_events in by_user.items():
            user_events.sort(key=lambda x: parse_timestamp_epoch(x.timestamp))

            # Maintain active failure streak
            failure_streak: List[SecurityEvent] = []

            for ev in user_events:
                t_ev = parse_timestamp_epoch(ev.timestamp)

                if ev.event_type == EventType.AUTHENTICATION_FAILURE.value:
                    failure_streak.append(ev)
                    # Evict failures older than the window relative to this failure
                    while failure_streak and (t_ev - parse_timestamp_epoch(failure_streak[0].timestamp)) > window:
                        failure_streak.pop(0)

                elif ev.event_type == EventType.AUTHENTICATION_SUCCESS.value:
                    # Filter active failures within window relative to this success
                    valid_prior_failures = [
                        f for f in failure_streak
                        if 0 <= (t_ev - parse_timestamp_epoch(f.timestamp)) <= window
                    ]

                    if len(valid_prior_failures) >= fail_threshold:
                        first_fail = valid_prior_failures[0]
                        related_ids = [f.event_id for f in valid_prior_failures] + [ev.event_id]
                        source_ips = list({f.source_ip for f in valid_prior_failures if f.source_ip})
                        if ev.source_ip and ev.source_ip not in source_ips:
                            source_ips.append(ev.source_ip)

                        delta_seconds = int(t_ev - parse_timestamp_epoch(first_fail.timestamp))

                        alert = Alert.create(
                            rule_id=self.rule_id,
                            rule_name=self.name,
                            severity=Severity.HIGH.value,
                            first_observed=first_fail.timestamp,
                            last_observed=ev.timestamp,
                            related_event_ids=related_ids,
                            explanation=(
                                f"Account '{ev.username}' experienced {len(valid_prior_failures)} failed "
                                f"authentication attempt(s) followed by a successful login within {delta_seconds} seconds."
                            ),
                            supporting_evidence={
                                "prior_failure_count": len(valid_prior_failures),
                                "time_delta_seconds": delta_seconds,
                                "success_event_id": ev.event_id,
                                "source_ips": source_ips,
                            },
                            entities={
                                "username": ev.username,
                                "host": ev.source_host,
                                "source_ip": ev.source_ip or (source_ips[0] if source_ips else None),
                            },
                            confidence=0.90,
                            risk_score=85.0,
                        )
                        alerts.append(alert)

                    # Reset failure streak after a success
                    failure_streak = []

        return alerts
