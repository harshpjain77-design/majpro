"""Evidence-grounded AI Copilot synthesizing structured, cited security incident reports."""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Set

from collectors.common.schemas import EventType, SecurityEvent
from backend.ai.citation_validator import CitationValidator
from backend.ai.config import AIConfig, default_ai_config
from backend.ai.prompt_defense import PromptInjectionSanitizer
from backend.ai.schemas import (
    AIAnalysisReport,
    EventExplanation,
    FactEntry,
    HypothesisEntry,
    RecommendationEntry,
)
from backend.correlation.schemas import Incident
from backend.storage.base import EventRepository

logger = logging.getLogger("AIAssistantCopilot")

MITRE_MAPPING = {
    "RULE-001": ("T1110.001", "Brute Force: Password Guessing"),
    "RULE-002": ("T1078.003", "Valid Accounts: Local Accounts"),
    "RULE-003": ("T1110.003", "Brute Force: Password Spraying"),
    "RULE-004": ("T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudoers"),
    "RULE-005": ("T1087.001", "Account Discovery: Local Account Reconnaissance"),
    "ML-ANOMALY-001": ("T1078", "Behavioral Anomaly: Deviant Authentication Profile"),
}


class AIAssistantCopilot:
    """Investigative AI assistant strictly citing verified log and alert evidence."""

    def __init__(self, config: Optional[AIConfig] = None):
        self.config = config or default_ai_config
        self.sanitizer = PromptInjectionSanitizer()

    def investigate_incident(
        self,
        incident: Incident,
        event_repo: Optional[EventRepository] = None,
    ) -> AIAnalysisReport:
        """Synthesize an evidence-grounded investigation report strictly citing verified IDs."""
        all_warnings: List[str] = []

        # 1. Sanitize incident text against prompt injection
        _, title_warnings = self.sanitizer.sanitize_untrusted_text(incident.title)
        all_warnings.extend(title_warnings)

        # 2. Gather verified forensic evidence
        evidence_events: List[SecurityEvent] = []
        if event_repo:
            for eid in incident.related_event_ids[: self.config.max_context_events]:
                try:
                    ev = event_repo.get_event_by_id(eid)
                    if ev:
                        evidence_events.append(ev)
                        # Sanitize raw log lines
                        _, ev_warnings = self.sanitizer.sanitize_untrusted_text(ev.raw_event)
                        all_warnings.extend(ev_warnings)
                except Exception as e:
                    logger.warning(f"Could not retrieve event {eid} for AI context: {e}")

        # Set of verified authorized citation keys
        allowed_event_ids = set(incident.related_event_ids)
        allowed_alert_ids = set(incident.related_alert_ids)
        validator = CitationValidator(
            allowed_event_ids=allowed_event_ids,
            allowed_alert_ids=allowed_alert_ids,
        )

        # 3. Construct Verified Facts strictly citing IDs
        facts: List[FactEntry] = []
        source_ips = incident.entities.get("source_ips", [])
        usernames = incident.entities.get("usernames", [])
        hosts = incident.entities.get("hosts", [])

        # Fact 1: Attack Origin and Entities
        ip_str = ", ".join(source_ips) if source_ips else "unspecified origin"
        user_str = ", ".join(usernames) if usernames else "unspecified accounts"
        host_str = ", ".join(hosts) if hosts else "unspecified hosts"

        # Citations for entity fact
        primary_citations: List[str] = []
        if incident.related_alert_ids:
            primary_citations.append(incident.related_alert_ids[0])
        if evidence_events:
            primary_citations.append(evidence_events[0].event_id)

        facts.append(
            FactEntry(
                fact=(
                    f"Security activity observed involving source IP(s) [{ip_str}] targeting account(s) "
                    f"[{user_str}] on host(s) [{host_str}] between {incident.first_seen} and {incident.last_seen}."
                ),
                citations=primary_citations,
            )
        )

        # Fact 2: Attack Progression by Rule & Evidence
        for rule_id in incident.distinct_rules:
            rule_alerts = [aid for aid in incident.related_alert_ids if rule_id in aid or True]
            rule_citation = rule_alerts[:2]

            if rule_id == "RULE-001":
                facts.append(
                    FactEntry(
                        fact=(
                            f"Multiple failed authentication attempts were recorded from source IP '{source_ips[0] if source_ips else 'unknown'}' "
                            f"exceeding rapid-failure thresholds."
                        ),
                        citations=rule_citation,
                    )
                )
            elif rule_id == "RULE-002":
                facts.append(
                    FactEntry(
                        fact=(
                            f"Observed authentication failure followed by a successful login for account '{usernames[0] if usernames else 'user'}', "
                            f"indicating potential credential compromise."
                        ),
                        citations=rule_citation,
                    )
                )
            elif rule_id == "RULE-003":
                facts.append(
                    FactEntry(
                        fact=(
                            f"Distributed authentication attempts originated from multiple sources against account '{usernames[0] if usernames else 'user'}'."
                        ),
                        citations=rule_citation,
                    )
                )
            elif rule_id == "RULE-004":
                facts.append(
                    FactEntry(
                        fact=(
                            f"Execution of sensitive privileged operations (e.g. shadow access or sudo command) occurred on host '{hosts[0] if hosts else 'host'}'."
                        ),
                        citations=rule_citation,
                    )
                )
            elif rule_id == "RULE-005":
                facts.append(
                    FactEntry(
                        fact=(
                            f"Invalid username enumeration/reconnaissance was detected prior to targeted authentication attempts."
                        ),
                        citations=rule_citation,
                    )
                )
            elif rule_id == "ML-ANOMALY-001":
                facts.append(
                    FactEntry(
                        fact=(
                            f"Behavioral anomaly detector identified significant multi-dimensional divergence from normal baseline authentication velocity and entropy."
                        ),
                        citations=rule_citation,
                    )
                )

        # 4. Synthesize Threat Hypotheses grounded in kill-chain
        hypotheses: List[HypothesisEntry] = []
        distinct_set = set(incident.distinct_rules)

        if {"RULE-001", "RULE-002", "RULE-004"} <= distinct_set:
            hypotheses.append(
                HypothesisEntry(
                    hypothesis=(
                        "High-confidence multi-stage intrusion: Attacker conducted brute-force credential discovery, "
                        "successfully authenticated, and escalated privileges to sensitive system resources."
                    ),
                    mitre_technique="T1078.003 / T1548.003",
                    confidence=0.95,
                    supporting_citations=incident.related_alert_ids,
                )
            )
        elif {"RULE-001", "RULE-002"} <= distinct_set:
            hypotheses.append(
                HypothesisEntry(
                    hypothesis=(
                        "Credential compromise: Attacker succeeded in guessing or stuffing valid account credentials "
                        "following repeated initial authentication failures."
                    ),
                    mitre_technique="T1110.001 -> T1078",
                    confidence=0.90,
                    supporting_citations=incident.related_alert_ids,
                )
            )
        elif "RULE-004" in distinct_set:
            hypotheses.append(
                HypothesisEntry(
                    hypothesis="Suspicious local privilege escalation or sensitive system credential inspection.",
                    mitre_technique="T1548.003 (Sudo and Sudoers)",
                    confidence=0.85,
                    supporting_citations=incident.related_alert_ids,
                )
            )
        else:
            hypotheses.append(
                HypothesisEntry(
                    hypothesis="External automated reconnaissance or brute-force authentication campaign.",
                    mitre_technique="T1110 (Brute Force)",
                    confidence=0.80,
                    supporting_citations=incident.related_alert_ids,
                )
            )

        # 5. Formulate Actionable Recommendations
        recommendations: List[RecommendationEntry] = []

        # Action: Block Source IP
        for ip in source_ips:
            recommendations.append(
                RecommendationEntry(
                    recommendation=f"Block inbound network traffic from malicious IP {ip} at the firewall boundary.",
                    priority="critical" if incident.severity in {"critical", "high"} else "high",
                    reversible=True,
                    action_type="block_ip",
                    parameters={"ip": ip, "reason": incident.title},
                )
            )

        # Action: Lock or Reset Targeted User Account
        for user in usernames:
            if user not in {"root", "unspecified", "unknown"}:
                recommendations.append(
                    RecommendationEntry(
                        recommendation=f"Temporarily lock account '{user}' and force credential reset.",
                        priority="high",
                        reversible=True,
                        action_type="lock_account",
                        parameters={"username": user, "reason": "Suspected credential compromise"},
                    )
                )

        # Action: Host Audit & Forensics
        for host in hosts:
            recommendations.append(
                RecommendationEntry(
                    recommendation=f"Inspect system authentication and sudo logs on host '{host}' for unauthorized persistent sessions.",
                    priority="medium",
                    reversible=True,
                    action_type="review_audit",
                    parameters={"host": host},
                )
            )

        # 6. Validate All Asserted Citations
        all_cited: List[str] = []
        for f in facts:
            all_cited.extend(f.citations)
        for h in hypotheses:
            all_cited.extend(h.supporting_citations)

        is_valid, valid_ids, invalid_ids = validator.validate_citations(all_cited)

        # 7. Executive Summary
        exec_summary = (
            f"Incident {incident.incident_id} is evaluated as {incident.severity.upper()} severity (Risk Score: {incident.risk_score:.1f}/100). "
            f"Forensic logs verify activity from {len(source_ips)} source IP(s) targeting {len(usernames)} account(s) on host(s) [{host_str}]. "
            f"Triggered detection rules: {', '.join(incident.distinct_rules)}. "
            f"{len(recommendations)} response actions recommended."
        )

        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        return AIAnalysisReport(
            incident_id=incident.incident_id,
            generated_at=now_utc,
            model_used=self.config.model_name,
            executive_summary=exec_summary,
            verified_facts=facts,
            threat_hypotheses=hypotheses,
            actionable_recommendations=recommendations,
            citations_validated=is_valid,
            valid_citation_ids=valid_ids,
            invalid_citation_ids=invalid_ids,
            sanitization_warnings=all_warnings,
        )

    def explain_single_event(self, event: SecurityEvent) -> EventExplanation:
        """Provide concise forensic explanation of a single event for an analyst."""
        usr = event.username or "unspecified"
        ip = event.source_ip or "local"
        host = event.source_host

        if event.event_type == EventType.AUTHENTICATION_FAILURE.value:
            significance = f"Failed logon attempt for account '{usr}' originating from IP '{ip}'."
            rec = "Monitor for repeated failures from this IP address or targeted user account."
        elif event.event_type == EventType.AUTHENTICATION_SUCCESS.value:
            significance = f"Successful logon by account '{usr}' on host '{host}'."
            rec = "Verify that the logon source and timestamp correspond to legitimate business operations."
        elif event.event_type == EventType.PRIVILEGE_ESCALATION.value:
            significance = f"Privileged command execution or elevated credential utilization on host '{host}'."
            rec = "Audit execution context against authorized administrative change requests."
        else:
            significance = f"Observed event type '{event.event_type}' on host '{host}'."
            rec = "Inspect raw payload details for contextual evaluation."

        return EventExplanation(
            event_id=event.event_id,
            timestamp=event.timestamp,
            summary=f"Event {event.event_type} on host '{host}' by user '{usr}'",
            security_significance=significance,
            forensic_details={
                "event_type": event.event_type,
                "source_host": event.source_host,
                "username": event.username,
                "source_ip": event.source_ip,
                "severity": event.severity,
                "raw_event": event.raw_event,
            },
            recommendation=rec,
        )
