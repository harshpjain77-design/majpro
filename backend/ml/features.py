"""Behavioral feature extraction from normalized security event streams."""

from collections import Counter, defaultdict
import math
from typing import Dict, List, Optional
import numpy as np

from collectors.common.schemas import EventType, SecurityEvent
from backend.detection.rules.base import parse_timestamp_epoch
from backend.ml.config import MLConfig, default_ml_config
from backend.ml.schemas import FEATURE_NAMES, EntityFeatureVector


class FeatureExtractor:
    """Extracts multivariate behavioral vectors from authentication event streams."""

    def __init__(self, config: Optional[MLConfig] = None):
        self.config = config or default_ml_config

    def _calculate_entropy(self, items: List[str]) -> float:
        """Calculate Shannon entropy of categorical distributions."""
        valid_items = [x for x in items if x and x.strip()]
        if len(valid_items) <= 1:
            return 0.0
        counts = Counter(valid_items)
        total = float(len(valid_items))
        entropy = 0.0
        for count in counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    def extract_features_from_events(
        self,
        events: List[SecurityEvent],
        entity_key: str = "source_ip",
    ) -> List[EntityFeatureVector]:
        """Group events by entity and window length, computing behavioral feature vectors."""
        if not events:
            return []

        # Filter for authentication events
        auth_events = [
            e for e in events
            if e.event_type in {
                EventType.AUTHENTICATION_SUCCESS.value,
                EventType.AUTHENTICATION_FAILURE.value,
            }
        ]
        if not auth_events:
            return []

        # Group by primary entity
        by_entity: Dict[str, List[SecurityEvent]] = defaultdict(list)
        for ev in auth_events:
            ent = getattr(ev, entity_key, None)
            if not ent and entity_key == "source_ip":
                # Fallback to username if IP missing
                ent = ev.username or "unspecified"
            elif not ent:
                ent = "unspecified"
            by_entity[str(ent)].append(ev)

        feature_vectors: List[EntityFeatureVector] = []
        window_seconds = self.config.feature_window_seconds
        min_events = self.config.min_events_per_window

        for ent_val, ent_events in by_entity.items():
            # Sort chronologically
            ent_events.sort(key=lambda x: parse_timestamp_epoch(x.timestamp))

            # Partition into sliding windows
            n = len(ent_events)
            i = 0
            while i < n:
                w_start_epoch = parse_timestamp_epoch(ent_events[i].timestamp)
                w_end_epoch = w_start_epoch + window_seconds
                w_events: List[SecurityEvent] = []

                j = i
                while j < n and parse_timestamp_epoch(ent_events[j].timestamp) <= w_end_epoch:
                    w_events.append(ent_events[j])
                    j += 1

                # Only produce feature vector if window meets minimum sample threshold
                if len(w_events) >= min_events:
                    vec = self._compute_vector_for_window(
                        entity_type=entity_key,
                        entity_value=ent_val,
                        events=w_events,
                    )
                    feature_vectors.append(vec)

                # Advance to next window boundary
                if j == i:
                    i += 1
                else:
                    i = j

        return feature_vectors

    def _compute_vector_for_window(
        self,
        entity_type: str,
        entity_value: str,
        events: List[SecurityEvent],
    ) -> EntityFeatureVector:
        """Compute the 10 numerical features for a single slice of events."""
        event_count = len(events)
        failure_count = sum(
            1 for e in events if e.event_type == EventType.AUTHENTICATION_FAILURE.value
        )
        success_count = sum(
            1 for e in events if e.event_type == EventType.AUTHENTICATION_SUCCESS.value
        )
        failure_ratio = (failure_count / event_count) if event_count > 0 else 0.0

        usernames = [e.username for e in events if e.username]
        unique_usernames = len(set(usernames))
        username_entropy = self._calculate_entropy(usernames)

        hosts = [e.source_host for e in events if e.source_host]
        unique_hosts = len(set(hosts))

        # Velocity in events per minute
        t_first = parse_timestamp_epoch(events[0].timestamp)
        t_last = parse_timestamp_epoch(events[-1].timestamp)
        duration_minutes = max(1.0, (t_last - t_first) / 60.0)
        auth_velocity = round(event_count / duration_minutes, 2)

        # Inter-arrival time statistics
        if event_count > 1:
            timestamps = [parse_timestamp_epoch(e.timestamp) for e in events]
            gaps = [timestamps[k + 1] - timestamps[k] for k in range(len(timestamps) - 1)]
            mean_gap = float(np.mean(gaps))
            variance_gap = float(np.var(gaps))
        else:
            mean_gap = 0.0
            variance_gap = 0.0

        features_dict: Dict[str, float] = {
            "event_count": float(event_count),
            "failure_count": float(failure_count),
            "success_count": float(success_count),
            "failure_ratio": round(failure_ratio, 4),
            "unique_usernames_targeted": float(unique_usernames),
            "username_entropy": round(username_entropy, 4),
            "unique_hosts_targeted": float(unique_hosts),
            "auth_velocity_per_min": auth_velocity,
            "mean_inter_arrival_time": round(mean_gap, 2),
            "inter_arrival_variance": round(variance_gap, 2),
        }

        return EntityFeatureVector(
            entity_type=entity_type,
            entity_value=entity_value,
            window_start=events[0].timestamp,
            window_end=events[-1].timestamp,
            features=features_dict,
            event_ids=[e.event_id for e in events],
        )
