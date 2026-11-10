"""RULE-004: Unusual privileged-account activity."""

from typing import List

from collectors.common.schemas import EventType, SecurityEvent, Severity
from backend.detection.config import DetectionConfig, default_config
from backend.detection.rules.base import BaseRule
from backend.detection.schemas import Alert


class PrivilegedActivityRule(BaseRule):
    """Detects potentially sensitive privileged actions or critical command executions."""

    rule_id: str = "RULE-004"
    rule_version: str = "1.0"
    name: str = "Unusual Privileged Account Activity"
    description: str = "Flags executions of highly sensitive commands via sudo or privileged logon contexts with elevated administrative impact."
    default_severity: str = Severity.MEDIUM.value

    def __init__(self, config: DetectionConfig = default_config):
        self.config = config

    def evaluate(self, events: List[SecurityEvent]) -> List[Alert]:
        alerts: List[Alert] = []

        for ev in events:
            command = ev.metadata.get("command") or ""
            invoker = ev.metadata.get("invoker") or ev.username

            is_sensitive_command = False
            matching_keyword = None
            if command:
                for kw in self.config.rule_4_sensitive_commands:
                    if kw.lower() in command.lower():
                        is_sensitive_command = True
                        matching_keyword = kw
                        break

            # 1. Sudo execution of sensitive command
            if ev.event_type == EventType.PRIVILEGE_ESCALATION.value and is_sensitive_command:
                severity = Severity.HIGH.value if any(k in command for k in ["/etc/shadow", "mimikatz", "chmod +s"]) else Severity.MEDIUM.value
                alert = Alert.create(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    severity=severity,
                    first_observed=ev.timestamp,
                    last_observed=ev.timestamp,
                    related_event_ids=[ev.event_id],
                    explanation=(
                        f"Account '{invoker}' executed sensitive privileged command '{command}' "
                        f"(matched keyword '{matching_keyword}') on host '{ev.source_host}'."
                    ),
                    supporting_evidence={
                        "invoker": invoker,
                        "command": command,
                        "matched_keyword": matching_keyword,
                        "tty": ev.metadata.get("tty"),
                        "pwd": ev.metadata.get("pwd"),
                    },
                    entities={
                        "username": invoker,
                        "host": ev.source_host,
                    },
                    confidence=0.85,
                    risk_score=70.0,
                )
                alerts.append(alert)

            # 2. Windows Special Privileges Assigned (Event 4672) with non-standard logon type or remote logon
            elif ev.windows_event_id == 4672 and ev.metadata.get("logon_type") in {3, 10}:
                # Remote network or RDP logon acquiring full administrative privileges
                logon_type = ev.metadata.get("logon_type")
                alert = Alert.create(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    severity=Severity.MEDIUM.value,
                    first_observed=ev.timestamp,
                    last_observed=ev.timestamp,
                    related_event_ids=[ev.event_id],
                    explanation=(
                        f"Special administrative privileges assigned to logon for user '{ev.username}' "
                        f"via network/remote logon context (Logon Type {logon_type}) on host '{ev.source_host}'."
                    ),
                    supporting_evidence={
                        "windows_event_id": 4672,
                        "logon_type": logon_type,
                        "domain": ev.metadata.get("domain"),
                    },
                    entities={
                        "username": ev.username,
                        "host": ev.source_host,
                        "source_ip": ev.source_ip,
                    },
                    confidence=0.75,
                    risk_score=60.0,
                )
                alerts.append(alert)

        return alerts
