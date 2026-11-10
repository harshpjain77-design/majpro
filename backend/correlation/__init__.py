"""Alert deduplication, correlation, and incident management module."""

from backend.correlation.config import CorrelationConfig, default_correlation_config
from backend.correlation.correlator import IncidentCorrelator
from backend.correlation.deduplicator import AlertDeduplicator
from backend.correlation.repository import IncidentRepository
from backend.correlation.risk import calculate_incident_risk
from backend.correlation.schemas import (
    AnalystNote,
    DeduplicatedAlert,
    DeduplicationMetrics,
    Incident,
    IncidentFilter,
    IncidentStatus,
    TimelineEntry,
)
from backend.correlation.timeline import build_incident_timeline

__all__ = [
    "AlertDeduplicator",
    "AnalystNote",
    "CorrelationConfig",
    "DeduplicatedAlert",
    "DeduplicationMetrics",
    "Incident",
    "IncidentCorrelator",
    "IncidentFilter",
    "IncidentRepository",
    "IncidentStatus",
    "TimelineEntry",
    "build_incident_timeline",
    "calculate_incident_risk",
    "default_correlation_config",
]
