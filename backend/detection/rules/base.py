"""Base class for all deterministic threat detection rules."""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import List, Optional

from collectors.common.schemas import SecurityEvent
from backend.detection.schemas import Alert


def parse_timestamp_epoch(ts_str: Optional[str]) -> float:
    """Parse an ISO-8601 UTC timestamp string into unix epoch seconds."""
    if not ts_str:
        return 0.0
    clean = ts_str.strip()
    if clean.endswith("Z"):
        clean = clean[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(clean)
        return dt.timestamp()
    except Exception:
        return 0.0


class BaseRule(ABC):
    """Abstract base class for deterministic detection rules."""

    rule_id: str = "RULE-BASE"
    rule_version: str = "1.0"
    name: str = "Base Detection Rule"
    description: str = "Base detection rule template"
    default_severity: str = "medium"

    @abstractmethod
    def evaluate(self, events: List[SecurityEvent]) -> List[Alert]:
        """Analyze a collection of events and return generated Alert instances."""
        pass
