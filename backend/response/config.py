"""Configuration settings for the Controlled Automated Response Engine."""

from typing import Set
from pydantic import BaseModel, Field


class ResponseConfig(BaseModel):
    """Configuration for automated containment actions, safety guardrails, and policies."""

    dry_run: bool = Field(
        default=True,
        description="Dry-run mode enabled by default to prevent unintended destructive actions."
    )
    auto_execution_enabled: bool = Field(
        default=False,
        description="Whether non-disruptive or high-risk actions can execute without human sign-off."
    )
    auto_execution_risk_threshold: int = Field(
        default=85,
        description="Minimum incident risk score required before an auto-executable action can run."
    )
    max_actions_per_minute_per_target: int = Field(
        default=5,
        description="Throttling rate limit to prevent denial of service or runaway response storms."
    )
    audit_log_path: str = Field(
        default="output/response_audit.jsonl",
        description="Path to append-only forensic audit log for all response operations."
    )

    # Safety allowlist: critical system IP addresses that can NEVER be blocked
    protected_ips: Set[str] = Field(
        default_factory=lambda: {
            "127.0.0.1",
            "::1",
            "localhost",
            "192.168.1.1",     # Typical lab default gateway
            "10.0.0.1",        # Typical subnet default gateway
            "8.8.8.8",         # Google Public DNS
            "1.1.1.1",         # Cloudflare DNS
            "0.0.0.0",
        },
        description="IP addresses and gateways protected from automated firewall blocking."
    )

    # Safety allowlist: critical administrative/service accounts that can NEVER be locked
    protected_users: Set[str] = Field(
        default_factory=lambda: {
            "root",
            "administrator",
            "admin",
            "system",
            "guest",
            "daemon",
            "nobody",
            "sshd",
            "www-data",
        },
        description="Critical system usernames protected from automated account lockout."
    )
