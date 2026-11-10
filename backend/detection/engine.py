"""DetectionEngine orchestrating deterministic rule evaluation against event streams."""

import logging
from typing import Any, Dict, List, Optional

from collectors.common.schemas import SecurityEvent
from backend.detection.config import DetectionConfig, default_config
from backend.detection.rules import (
    BaseRule,
    DistributedPasswordSprayRule,
    FailedFollowedBySuccessRule,
    PrivilegedActivityRule,
    SingleSourceBruteForceRule,
    SuspiciousAuthenticationSequenceRule,
)
from backend.detection.schemas import Alert
from backend.storage.base import EventRepository
from backend.storage.models import EventFilter, PaginationParams

logger = logging.getLogger("DetectionEngine")


class DetectionEngine:
    """Evaluates security event streams and repository windows against registered detection rules."""

    def __init__(
        self,
        config: Optional[DetectionConfig] = None,
        custom_rules: Optional[List[BaseRule]] = None,
    ):
        self.config = config or default_config
        if custom_rules is not None:
            self.rules = custom_rules
        else:
            self.rules = [
                SingleSourceBruteForceRule(config=self.config),
                FailedFollowedBySuccessRule(config=self.config),
                DistributedPasswordSprayRule(config=self.config),
                PrivilegedActivityRule(config=self.config),
                SuspiciousAuthenticationSequenceRule(config=self.config),
            ]

    def get_rules_metadata(self) -> List[Dict[str, Any]]:
        """Return list of active detection rules with metadata."""
        return [
            {
                "rule_id": r.rule_id,
                "rule_version": r.rule_version,
                "name": r.name,
                "description": r.description,
                "default_severity": r.default_severity,
            }
            for r in self.rules
        ]

    def evaluate_events(self, events: List[SecurityEvent]) -> List[Alert]:
        """Run all active rules against the provided event list and return triggered alerts."""
        if not events:
            return []

        all_alerts: List[Alert] = []
        for rule in self.rules:
            try:
                rule_alerts = rule.evaluate(events)
                if rule_alerts:
                    logger.info(
                        f"Rule {rule.rule_id} ('{rule.name}') generated {len(rule_alerts)} alert(s)."
                    )
                    all_alerts.extend(rule_alerts)
            except Exception as e:
                logger.error(f"Error evaluating rule {rule.rule_id}: {e}", exc_info=True)

        return all_alerts

    def evaluate_from_repository(
        self,
        repo: EventRepository,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 1000,
    ) -> List[Alert]:
        """Fetch matching events from storage repository and evaluate rules."""
        filters = EventFilter(start_time=start_time, end_time=end_time)
        pagination = PaginationParams(limit=limit, offset=0)
        res = repo.search_events(filters=filters, pagination=pagination)
        return self.evaluate_events(res.events)
