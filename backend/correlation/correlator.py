"""Incident correlation engine clustering related alerts across entities and time."""

from collections import defaultdict, deque
from datetime import datetime, timezone
import hashlib
import logging
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from backend.detection.rules.base import parse_timestamp_epoch
from backend.detection.schemas import Alert
from backend.correlation.config import CorrelationConfig, default_correlation_config
from backend.correlation.risk import calculate_incident_risk
from backend.correlation.schemas import DeduplicatedAlert, Incident, IncidentStatus
from backend.correlation.timeline import build_incident_timeline
from backend.storage.base import EventRepository

logger = logging.getLogger("IncidentCorrelator")


class IncidentCorrelator:
    """Correlates security alerts into unified, actionable security incidents using entity-temporal graphs."""

    def __init__(self, config: Optional[CorrelationConfig] = None):
        self.config = config or default_correlation_config

    def _normalize_entity(self, val: Any) -> Optional[str]:
        """Normalize an entity identifier, returning None if generic or blank."""
        if val is None:
            return None
        s = str(val).strip().lower()
        if not s or s in self.config.ignored_entities:
            return None
        return s

    def _extract_alert_entities(
        self, alert: Union[Alert, DeduplicatedAlert]
    ) -> Tuple[Set[str], Set[str], Set[str]]:
        """Extract valid (source_ips, usernames, hosts) sets from an alert's entity dictionary."""
        entities = getattr(alert, "entities", {}) or {}

        ips: Set[str] = set()
        users: Set[str] = set()
        hosts: Set[str] = set()

        # Extract IPs
        if "source_ip" in entities:
            norm = self._normalize_entity(entities["source_ip"])
            if norm:
                ips.add(norm)
        if "source_ips" in entities and isinstance(entities["source_ips"], (list, set, tuple)):
            for item in entities["source_ips"]:
                norm = self._normalize_entity(item)
                if norm:
                    ips.add(norm)

        # Extract Usernames
        for user_key in ["username", "targeted_user"]:
            if user_key in entities:
                norm = self._normalize_entity(entities[user_key])
                if norm:
                    users.add(norm)
        for list_key in ["usernames", "invalid_users"]:
            if list_key in entities and isinstance(entities[list_key], (list, set, tuple)):
                for item in entities[list_key]:
                    norm = self._normalize_entity(item)
                    if norm:
                        users.add(norm)

        # Extract Hosts
        if "host" in entities:
            norm = self._normalize_entity(entities["host"])
            if norm:
                hosts.add(norm)
        if "hosts" in entities and isinstance(entities["hosts"], (list, set, tuple)):
            for item in entities["hosts"]:
                norm = self._normalize_entity(item)
                if norm:
                    hosts.add(norm)

        return ips, users, hosts

    def _should_correlate(
        self,
        alert_a: Union[Alert, DeduplicatedAlert],
        entities_a: Tuple[Set[str], Set[str], Set[str]],
        alert_b: Union[Alert, DeduplicatedAlert],
        entities_b: Tuple[Set[str], Set[str], Set[str]],
    ) -> bool:
        """Determine if two alerts should be linked in the correlation graph."""
        ips_a, users_a, hosts_a = entities_a
        ips_b, users_b, hosts_b = entities_b

        # 1. Temporal Check: Must be within correlation window
        ts_a_start = parse_timestamp_epoch(getattr(alert_a, "first_observed", getattr(alert_a, "first_seen", "")))
        ts_a_end = parse_timestamp_epoch(getattr(alert_a, "last_observed", getattr(alert_a, "last_seen", "")))
        ts_b_start = parse_timestamp_epoch(getattr(alert_b, "first_observed", getattr(alert_b, "first_seen", "")))
        ts_b_end = parse_timestamp_epoch(getattr(alert_b, "last_observed", getattr(alert_b, "last_seen", "")))

        # Distance between intervals
        if ts_a_end < ts_b_start:
            time_delta = ts_b_start - ts_a_end
        elif ts_b_end < ts_a_start:
            time_delta = ts_a_start - ts_b_end
        else:
            time_delta = 0.0  # Overlapping

        if time_delta > self.config.correlation_window_seconds:
            return False

        # 2. Entity Matching
        # Shared source IP
        if ips_a and ips_b and bool(ips_a & ips_b):
            return True

        # Shared username
        if users_a and users_b and bool(users_a & users_b):
            return True

        # Optional Host-Only correlation (default False to prevent false correlations across independent attacks)
        if self.config.allow_host_only_correlation and hosts_a and hosts_b and bool(hosts_a & hosts_b):
            return True

        return False

    def _generate_incident_title(
        self,
        rules: List[str],
        entities: Dict[str, List[str]],
    ) -> str:
        """Construct a concise, human-readable title summarizing the correlated incident."""
        rule_set = set(rules)
        targets = []
        if entities.get("usernames"):
            targets.append(f"user '{entities['usernames'][0]}'")
        if entities.get("hosts"):
            targets.append(f"host '{entities['hosts'][0]}'")
        target_str = f" on {', '.join(targets)}" if targets else ""

        attacker_str = ""
        if entities.get("source_ips"):
            attacker_str = f" from {entities['source_ips'][0]}"

        if len(rule_set) > 1:
            if {"RULE-001", "RULE-002", "RULE-004"} <= rule_set:
                return f"Multi-Stage Compromise: Brute Force, Logon, and Privilege Escalation{target_str}{attacker_str}"
            elif {"RULE-001", "RULE-002"} <= rule_set:
                return f"Compromise Progression: Brute Force followed by Successful Logon{target_str}{attacker_str}"
            elif {"RULE-004"} <= rule_set:
                return f"Correlated Attack with Privileged Activity{target_str}{attacker_str}"
            else:
                return f"Correlated Multi-Alert Threat Activity ({', '.join(sorted(rule_set))}){target_str}{attacker_str}"
        elif len(rule_set) == 1:
            r = list(rule_set)[0]
            if r == "RULE-001":
                return f"Brute Force Authentication Campaign{attacker_str}{target_str}"
            elif r == "RULE-002":
                return f"Suspicious Logon Sequence (Failure followed by Success){target_str}{attacker_str}"
            elif r == "RULE-003":
                return f"Distributed Password Spraying Attack{target_str}"
            elif r == "RULE-004":
                return f"Privileged Activity Alert{target_str}"
            elif r == "RULE-005":
                return f"Suspicious Account Reconnaissance & Logon Sequence{attacker_str}{target_str}"

        return f"Correlated Security Incident{target_str}{attacker_str}"

    def correlate_alerts(
        self,
        alerts: List[Union[Alert, DeduplicatedAlert]],
        repo: Optional[EventRepository] = None,
    ) -> List[Incident]:
        """Group alerts into correlated Incidents using connected components clustering."""
        if not alerts:
            return []

        # Extract normalized entity sets for each alert
        alert_entities = [self._extract_alert_entities(a) for a in alerts]
        n = len(alerts)

        # Build adjacency graph
        adj: Dict[int, List[int]] = defaultdict(list)
        for i in range(n):
            for j in range(i + 1, n):
                if self._should_correlate(alerts[i], alert_entities[i], alerts[j], alert_entities[j]):
                    adj[i].append(j)
                    adj[j].append(i)

        # Find connected components via BFS
        visited: Set[int] = set()
        incidents: List[Incident] = []

        for start_node in range(n):
            if start_node in visited:
                continue

            component_indices: List[int] = []
            queue = deque([start_node])
            visited.add(start_node)

            while queue:
                curr = queue.popleft()
                component_indices.append(curr)
                for neighbor in adj[curr]:
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append(neighbor)

            # Build incident from this component
            component_alerts = [alerts[idx] for idx in component_indices]

            # Collect consolidated entities
            c_ips: Set[str] = set()
            c_users: Set[str] = set()
            c_hosts: Set[str] = set()
            for idx in component_indices:
                ips, users, hosts = alert_entities[idx]
                c_ips.update(ips)
                c_users.update(users)
                c_hosts.update(hosts)

            entities_dict = {
                "source_ips": sorted(list(c_ips)),
                "usernames": sorted(list(c_users)),
                "hosts": sorted(list(c_hosts)),
            }

            # Collect related alerts and events
            alert_ids: List[str] = []
            event_ids: List[str] = []
            distinct_rules: Set[str] = set()
            first_seen_ts: Optional[str] = None
            last_seen_ts: Optional[str] = None

            for a in component_alerts:
                aid = getattr(a, "primary_alert_id", getattr(a, "alert_id", ""))
                if aid and aid not in alert_ids:
                    alert_ids.append(aid)

                for contributing_id in getattr(a, "contributing_alert_ids", []):
                    if contributing_id not in alert_ids:
                        alert_ids.append(contributing_id)

                for eid in getattr(a, "related_event_ids", []):
                    if eid not in event_ids:
                        event_ids.append(eid)

                distinct_rules.add(a.rule_id)

                a_start = getattr(a, "first_observed", getattr(a, "first_seen", ""))
                a_end = getattr(a, "last_observed", getattr(a, "last_seen", ""))

                if first_seen_ts is None or (a_start and parse_timestamp_epoch(a_start) < parse_timestamp_epoch(first_seen_ts)):
                    first_seen_ts = a_start
                if last_seen_ts is None or (a_end and parse_timestamp_epoch(a_end) > parse_timestamp_epoch(last_seen_ts)):
                    last_seen_ts = a_end

            # Calculate deterministic risk score and incident severity
            risk_score, severity = calculate_incident_risk(component_alerts, entities_dict)

            # Generate deterministic Incident ID based on primary signature
            inc_hasher = hashlib.sha256()
            inc_hasher.update((first_seen_ts or "").encode())
            inc_hasher.update(b"|")
            inc_hasher.update(",".join(sorted(distinct_rules)).encode())
            inc_hasher.update(b"|")
            inc_hasher.update(",".join(entities_dict["source_ips"]).encode())
            inc_hasher.update(b"|")
            inc_hasher.update(",".join(entities_dict["usernames"]).encode())
            incident_id = f"inc_{inc_hasher.hexdigest()[:20]}"

            title = self._generate_incident_title(list(distinct_rules), entities_dict)
            timeline = build_incident_timeline(component_alerts, repo=repo)

            now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            incidents.append(
                Incident(
                    incident_id=incident_id,
                    title=title,
                    severity=severity,
                    status=IncidentStatus.NEW,
                    risk_score=risk_score,
                    first_seen=first_seen_ts or now_utc,
                    last_seen=last_seen_ts or now_utc,
                    entities=entities_dict,
                    related_alert_ids=alert_ids,
                    related_event_ids=event_ids,
                    distinct_rules=sorted(list(distinct_rules)),
                    timeline=timeline,
                    analyst_notes=[],
                    created_at=now_utc,
                    updated_at=now_utc,
                )
            )

        # Sort incidents by risk score descending (highest risk first)
        incidents.sort(key=lambda x: x.risk_score, reverse=True)
        return incidents
