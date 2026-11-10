"""Deterministic risk prioritization formula for security incidents."""

from typing import Any, Dict, List, Tuple, Union
from backend.correlation.schemas import DeduplicatedAlert
from backend.detection.schemas import Alert

# Base weight assigned to the highest severity alert in the incident
SEVERITY_BASE_WEIGHTS = {
    "critical": 70.0,
    "high": 50.0,
    "medium": 30.0,
    "low": 15.0,
}

RECON_RULES = {"RULE-001", "RULE-003", "RULE-005"}
ESCALATION_RULES = {"RULE-002", "RULE-004"}


def calculate_incident_risk(
    alerts: List[Union[Alert, DeduplicatedAlert]],
    entities: Dict[str, List[str]],
) -> Tuple[float, str]:
    """Calculate an explainable, deterministic risk score (0.0 - 100.0) and incident severity tier.

    Risk formula:
        Risk = Clamp(BaseSeverity + RuleDiversity + KillChainProgression + VolumeFactor + TargetDiversity, 0, 100)
    """
    if not alerts:
        return 0.0, "low"

    # 1. Base Severity Weight
    severities = [a.severity.lower() for a in alerts]
    max_sev = "low"
    for s in ["critical", "high", "medium", "low"]:
        if s in severities:
            max_sev = s
            break
    base_score = SEVERITY_BASE_WEIGHTS.get(max_sev, 20.0)

    # 2. Rule Diversity Bonus (distinct rule types indicating multi-technique activity)
    rule_ids = set(a.rule_id for a in alerts)
    diversity_bonus = min(20.0, max(0.0, (len(rule_ids) - 1) * 10.0))

    # 3. Kill-Chain Attack Progression Bonus
    has_recon = bool(rule_ids & RECON_RULES)
    has_escalation = bool(rule_ids & ESCALATION_RULES)
    progression_bonus = 15.0 if (has_recon and has_escalation) else 0.0

    # 4. Volume / Repetition Factor
    total_occurrences = sum(getattr(a, "occurrence_count", 1) for a in alerts)
    volume_bonus = min(10.0, max(0.0, (total_occurrences - 1) * 2.0))

    # 5. Target / Entity Diversity Factor
    target_bonus = 0.0
    if len(entities.get("usernames", [])) > 2:
        target_bonus += 5.0
    if len(entities.get("hosts", [])) > 1:
        target_bonus += 5.0

    raw_score = base_score + diversity_bonus + progression_bonus + volume_bonus + target_bonus
    final_score = round(min(100.0, max(0.0, raw_score)), 1)

    # Map score to severity tier
    if final_score >= 80.0:
        severity_tier = "critical"
    elif final_score >= 60.0:
        severity_tier = "high"
    elif final_score >= 40.0:
        severity_tier = "medium"
    else:
        severity_tier = "low"

    return final_score, severity_tier
