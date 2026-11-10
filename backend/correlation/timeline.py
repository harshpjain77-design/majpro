"""Incident timeline generator constructing chronological forensic milestones."""

import hashlib
import logging
from typing import Any, Dict, List, Optional, Union

from backend.detection.rules.base import parse_timestamp_epoch
from backend.detection.schemas import Alert
from backend.correlation.schemas import DeduplicatedAlert, TimelineEntry
from backend.storage.base import EventRepository

logger = logging.getLogger("IncidentTimeline")


def build_incident_timeline(
    alerts: List[Union[Alert, DeduplicatedAlert]],
    repo: Optional[EventRepository] = None,
    max_raw_events: int = 15,
) -> List[TimelineEntry]:
    """Assemble chronologically ordered timeline entries combining alerts and key evidence events."""
    entries: List[TimelineEntry] = []

    # 1. Add Alert Milestones
    for alert in alerts:
        ts = getattr(alert, "first_observed", getattr(alert, "first_seen", ""))
        src_id = getattr(alert, "primary_alert_id", getattr(alert, "alert_id", "alert"))
        explanation = getattr(alert, "explanation", "")
        rule_id = getattr(alert, "rule_id", "RULE")
        rule_name = getattr(alert, "rule_name", "Detection")

        hasher = hashlib.sha256()
        hasher.update(src_id.encode())
        hasher.update(ts.encode())
        entry_id = f"tml_{hasher.hexdigest()[:16]}"

        entries.append(
            TimelineEntry(
                entry_id=entry_id,
                timestamp=ts,
                entry_type="alert",
                description=f"[{rule_id}] {rule_name}: {explanation}",
                source_id=src_id,
                severity=alert.severity,
                entities=dict(getattr(alert, "entities", {})),
            )
        )

    # 2. Add Key Event Milestones from Repository if available
    if repo is not None:
        all_event_ids: List[str] = []
        for alert in alerts:
            for eid in getattr(alert, "related_event_ids", []):
                if eid not in all_event_ids:
                    all_event_ids.append(eid)

        # Pull milestone events (up to max_raw_events to keep timeline clean and legible)
        for eid in all_event_ids[:max_raw_events]:
            try:
                ev = repo.get_event_by_id(eid)
                if ev:
                    e_hasher = hashlib.sha256()
                    e_hasher.update(ev.event_id.encode())
                    e_hasher.update(ev.timestamp.encode())
                    entry_id = f"tml_{e_hasher.hexdigest()[:16]}"

                    usr = ev.username or "unspecified"
                    ip = ev.source_ip or "local"
                    desc = f"Raw event {ev.event_type} on host '{ev.source_host}' (user: '{usr}', IP: '{ip}')"

                    entries.append(
                        TimelineEntry(
                            entry_id=entry_id,
                            timestamp=ev.timestamp,
                            entry_type="event",
                            description=desc,
                            source_id=ev.event_id,
                            severity=ev.severity,
                            entities={
                                "username": ev.username,
                                "source_ip": ev.source_ip,
                                "host": ev.source_host,
                                "event_type": ev.event_type,
                            },
                        )
                    )
            except Exception as e:
                logger.warning(f"Could not retrieve event {eid} for timeline: {e}")

    # Sort all entries chronologically
    entries.sort(key=lambda x: parse_timestamp_epoch(x.timestamp))
    return entries
