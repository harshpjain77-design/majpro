"""RULE-005: Suspicious sequences of related authentication events (Reconnaissance to Targeting)."""

from collections import defaultdict
from typing import Dict, List

from collectors.common.schemas import EventType, SecurityEvent, Severity
from backend.detection.config import DetectionConfig, default_config
from backend.detection.rules.base import BaseRule, parse_timestamp_epoch
from backend.detection.schemas import Alert


class SuspiciousAuthenticationSequenceRule(BaseRule):
    """Detects invalid username reconnaissance followed by targeted authentication against valid accounts."""

    rule_id: str = "RULE-005"
    rule_version: str = "1.0"
    name: str = "Suspicious Sequence: Invalid User Reconnaissance Followed by Targeted Login"
    description: str = "Flags sequences where an IP address enumerates non-existent usernames and subsequently targets a valid account."
    default_severity: str = Severity.MEDIUM.value

    def __init__(self, config: DetectionConfig = default_config):
        self.config = config

    def evaluate(self, events: List[SecurityEvent]) -> List[Alert]:
        alerts: List[Alert] = []

        auth_events = [
            e for e in events
            if e.event_type in {
                EventType.AUTHENTICATION_FAILURE.value,
                EventType.AUTHENTICATION_SUCCESS.value,
            }
            and e.source_ip
        ]
        if not auth_events:
            return []

        # Group by source IP
        by_ip: Dict[str, List[SecurityEvent]] = defaultdict(list)
        for ev in auth_events:
            by_ip[ev.source_ip].append(ev)

        recon_threshold = self.config.rule_5_invalid_recon_threshold
        window = self.config.rule_5_window_seconds

        for ip, ip_events in by_ip.items():
            ip_events.sort(key=lambda x: parse_timestamp_epoch(x.timestamp))

            invalid_attempts: List[SecurityEvent] = []

            for ev in ip_events:
                t_ev = parse_timestamp_epoch(ev.timestamp)
                is_invalid = ev.metadata.get("is_invalid_user", False)

                if is_invalid:
                    invalid_attempts.append(ev)
                    # Evict entries older than window
                    while invalid_attempts and (t_ev - parse_timestamp_epoch(invalid_attempts[0].timestamp)) > window:
                        invalid_attempts.pop(0)

                elif not is_invalid and ev.username:
                    # Valid account attempt following invalid probes
                    valid_recon = [
                        inv for inv in invalid_attempts
                        if 0 <= (t_ev - parse_timestamp_epoch(inv.timestamp)) <= window
                    ]

                    if len(valid_recon) >= recon_threshold:
                        first_recon = valid_recon[0]
                        related_ids = [inv.event_id for inv in valid_recon] + [ev.event_id]
                        probed_users = list({inv.username for inv in valid_recon if inv.username})

                        delta_sec = int(t_ev - parse_timestamp_epoch(first_recon.timestamp))

                        alert = Alert.create(
                            rule_id=self.rule_id,
                            rule_name=self.name,
                            severity=Severity.HIGH.value if ev.event_type == EventType.AUTHENTICATION_SUCCESS.value else Severity.MEDIUM.value,
                            first_observed=first_recon.timestamp,
                            last_observed=ev.timestamp,
                            related_event_ids=related_ids,
                            explanation=(
                                f"Source IP '{ip}' performed username reconnaissance probing ({len(probed_users)} invalid usernames: "
                                f"{', '.join(probed_users[:5])}) followed by authentication against valid account '{ev.username}'."
                            ),
                            supporting_evidence={
                                "invalid_probe_count": len(valid_recon),
                                "probed_users": probed_users,
                                "targeted_account": ev.username,
                                "targeted_event_type": ev.event_type,
                                "time_delta_seconds": delta_sec,
                            },
                            entities={
                                "source_ip": ip,
                                "targeted_username": ev.username,
                                "host": ev.source_host,
                            },
                            confidence=0.85,
                            risk_score=75.0,
                        )
                        alerts.append(alert)

                        # Clear invalid attempts to prevent duplicate re-triggers
                        invalid_attempts = []

        return alerts
