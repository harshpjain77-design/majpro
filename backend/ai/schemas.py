"""Schemas for evidence-grounded AI incident reports, citations, and recommendations."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class FactEntry(BaseModel):
    """A defensible, verified security fact citing explicit log and alert IDs."""

    fact: str = Field(..., description="Objective statement of observed activity")
    citations: List[str] = Field(
        default_factory=list,
        description="List of verified event_id or alert_id values establishing this fact",
    )


class HypothesisEntry(BaseModel):
    """An analytical threat hypothesis grounded in observed behavior."""

    hypothesis: str = Field(..., description="Plausible threat narrative or attacker objective")
    mitre_technique: Optional[str] = Field(
        default=None,
        description="Associated MITRE ATT&CK technique (e.g. T1110.001)",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score based on observed evidence volume and progression",
    )
    supporting_citations: List[str] = Field(
        default_factory=list,
        description="Citations supporting this hypothesis",
    )


class RecommendationEntry(BaseModel):
    """An actionable, human-in-the-loop mitigation recommendation."""

    recommendation: str = Field(..., description="Specific response or investigation action")
    priority: str = Field(..., description="Action priority: critical, high, medium, low")
    reversible: bool = Field(default=True, description="Whether the action is fully reversible")
    action_type: str = Field(
        ...,
        description="Category: 'block_ip', 'lock_account', 'rotate_credentials', 'review_audit'",
    )
    parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Structured arguments for automated response execution (e.g. IP to block)",
    )


class AIAnalysisReport(BaseModel):
    """Comprehensive structured incident investigation report grounded strictly in log evidence."""

    model_config = ConfigDict(extra="allow")

    incident_id: str
    generated_at: str
    model_used: str
    executive_summary: str
    verified_facts: List[FactEntry]
    threat_hypotheses: List[HypothesisEntry]
    actionable_recommendations: List[RecommendationEntry]
    citations_validated: bool
    valid_citation_ids: List[str]
    invalid_citation_ids: List[str]
    sanitization_warnings: List[str] = Field(default_factory=list)


class EventExplanation(BaseModel):
    """Single-event forensic explanation for analyst inspection."""

    event_id: str
    timestamp: str
    summary: str
    security_significance: str
    forensic_details: Dict[str, Any]
    recommendation: str
