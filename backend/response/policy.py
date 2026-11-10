"""Policy engine evaluating incident risk and action disruption gating."""

from typing import Optional, Tuple
from backend.response.config import ResponseConfig
from backend.response.schemas import ActionPriority, ActionType


class PolicyDecision:
    """Outcome of evaluating a response action proposal against safety policy."""

    def __init__(
        self,
        allowed: bool,
        requires_approval: bool,
        dry_run: bool,
        policy_reason: str
    ):
        self.allowed = allowed
        self.requires_approval = requires_approval
        self.dry_run = dry_run
        self.policy_reason = policy_reason


class PolicyEngine:
    """Evaluates whether an action requires human-in-the-loop approval or can auto-execute."""

    def __init__(self, config: Optional[ResponseConfig] = None):
        self.config = config or ResponseConfig()

    def evaluate(
        self,
        action_type: ActionType,
        target: str,
        incident_risk_score: int = 50,
        priority: ActionPriority = ActionPriority.MEDIUM,
    ) -> PolicyDecision:
        """Evaluate a proposed action against configured policy rules.
        
        Disruptive actions (firewall block, account lockout, session termination)
        default to requiring explicit analyst sign-off unless auto-execution is
        specifically enabled and the incident risk score exceeds the threshold.
        """
        # Non-disruptive informational actions can run without analyst approval
        if action_type in {ActionType.REVIEW_AUDIT, ActionType.NOTIFY_ANALYST}:
            return PolicyDecision(
                allowed=True,
                requires_approval=False,
                dry_run=self.config.dry_run,
                policy_reason="Informational action does not alter network or account state; approval not required."
            )

        # Disruptive actions check
        is_disruptive = action_type in {
            ActionType.BLOCK_IP,
            ActionType.LOCK_ACCOUNT,
            ActionType.TERMINATE_SESSION
        }

        if is_disruptive:
            # Check if auto-execution is permitted under high-risk thresholds
            if (
                self.config.auto_execution_enabled and
                incident_risk_score >= self.config.auto_execution_risk_threshold
            ):
                return PolicyDecision(
                    allowed=True,
                    requires_approval=False,
                    dry_run=self.config.dry_run,
                    policy_reason=(
                        f"Incident risk score ({incident_risk_score}) meets auto-execution threshold "
                        f"({self.config.auto_execution_risk_threshold}). Auto-approved under policy."
                    )
                )

            # Standard safety default: Human-in-the-loop approval required
            return PolicyDecision(
                allowed=True,
                requires_approval=True,
                dry_run=self.config.dry_run,
                policy_reason=(
                    f"Disruptive action '{action_type.value}' requires explicit SOC analyst approval "
                    f"before execution."
                )
            )

        return PolicyDecision(
            allowed=True,
            requires_approval=True,
            dry_run=self.config.dry_run,
            policy_reason="Standard policy gate applied."
        )
