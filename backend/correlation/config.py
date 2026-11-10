"""Configuration for alert deduplication, correlation windows, and incident creation."""

from typing import Set
from pydantic import BaseModel, Field


class CorrelationConfig(BaseModel):
    """Configuration parameters for alert deduplication and multi-entity correlation."""

    # Sliding window within which alerts with identical fingerprints are deduplicated (seconds)
    deduplication_window_seconds: int = Field(
        default=900,  # 15 minutes
        ge=60,
        le=86400,
        description="Sliding window in seconds for deduplicating identical alert fingerprints",
    )

    # Maximum time difference between related alerts to be clustered into the same incident (seconds)
    correlation_window_seconds: int = Field(
        default=3600,  # 1 hour
        ge=60,
        le=604800,  # 7 days max
        description="Maximum temporal window between alerts for incident correlation",
    )

    # Maximum number of alerts that can be associated with a single incident
    max_alerts_per_incident: int = Field(
        default=100,
        ge=1,
        le=1000,
        description="Cap on alerts linked to a single incident to prevent unbounded memory growth",
    )

    # Whether to correlate alerts that only share a host name without sharing IP or username
    # Kept False by default to prevent false correlations of independent attacks on shared servers
    allow_host_only_correlation: bool = Field(
        default=False,
        description="Allow correlation between alerts sharing only host name without shared user or IP",
    )

    # Set of generic, ambient, or placeholder entity values that must never act as correlation bridges
    ignored_entities: Set[str] = Field(
        default_factory=lambda: {
            "",
            "unknown",
            "none",
            "null",
            "-",
            "n/a",
            "na",
            "system",
            "anonymous",
            "anonymous logon",
            "global",
            "undefined",
        },
        description="Generic entity tokens to ignore during correlation matching",
    )


default_correlation_config = CorrelationConfig()
