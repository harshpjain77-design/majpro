"""Configuration thresholds and parameters for detection rules."""

from typing import List
from pydantic import BaseModel, Field


class DetectionConfig(BaseModel):
    """Configurable thresholds and evaluation windows for threat detection rules."""

    # Rule 1: Brute Force from Single Source
    rule_1_failed_threshold: int = Field(
        default=5,
        ge=2,
        description="Minimum failed login attempts from a single source to trigger brute force alert",
    )
    rule_1_window_seconds: int = Field(
        default=300,
        ge=30,
        description="Time window in seconds to evaluate single-source failures",
    )

    # Rule 2: Failed Logins Followed by Success (Compromise / Brute Force Success)
    rule_2_fail_threshold: int = Field(
        default=3,
        ge=1,
        description="Minimum failed attempts preceding a successful logon to trigger alert",
    )
    rule_2_window_seconds: int = Field(
        default=600,
        ge=60,
        description="Time window in seconds for failures preceding success",
    )

    # Rule 3: Password Spraying (Multiple Sources against One Account)
    rule_3_distinct_sources_threshold: int = Field(
        default=3,
        ge=2,
        description="Minimum distinct source IPs failing against the same target account",
    )
    rule_3_window_seconds: int = Field(
        default=600,
        ge=60,
        description="Time window in seconds for password spray evaluation",
    )

    # Rule 4: Unusual Privileged-Account Activity
    rule_4_sensitive_commands: List[str] = Field(
        default=[
            "/etc/shadow",
            "/bin/bash",
            "/bin/sh",
            "visudo",
            "useradd",
            "usermod",
            "chmod +s",
            "chown root",
            "passwd",
            "reg add",
            "mimikatz",
        ],
        description="Keywords indicating potentially sensitive privileged command execution",
    )

    # Rule 5: Suspicious Authentication Sequence (Invalid user recon -> targeted logon)
    rule_5_invalid_recon_threshold: int = Field(
        default=3,
        ge=2,
        description="Number of invalid username failures preceding targeted access attempts",
    )
    rule_5_window_seconds: int = Field(
        default=600,
        ge=60,
        description="Time window in seconds for invalid user sequence evaluation",
    )


default_config = DetectionConfig()
