"""Controlled Automated Response Engine coordinating safety, policy, handlers, and audit."""

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional
from backend.ai.schemas import RecommendationEntry
from backend.response.config import ResponseConfig
from backend.response.handlers import (
    BaseActionHandler,
    BlockIPHandler,
    LockAccountHandler,
    NotifyAnalystHandler,
    TerminateSessionHandler,
)
from backend.response.policy import PolicyEngine
from backend.response.repository import SQLiteResponseRepository
from backend.response.safety import SafetyGuard
from backend.response.schemas import (
    ActionPriority,
    ActionStatus,
    ActionType,
    ExecutionResult,
    ResponseActionProposal,
    ResponseActionRecord,
    RollbackResult,
)


class ResponseEngine:
    """Orchestrates approval-gated containment actions with strict safety guardrails and auditability."""

    def __init__(
        self,
        config: Optional[ResponseConfig] = None,
        repository: Optional[SQLiteResponseRepository] = None,
        safety_guard: Optional[SafetyGuard] = None,
        policy_engine: Optional[PolicyEngine] = None,
    ):
        self.config = config or ResponseConfig()
        self.repository = repository or SQLiteResponseRepository(
            db_path="output/soc_events.sqlite",
            audit_log_path=self.config.audit_log_path
        )
        self.safety = safety_guard or SafetyGuard(self.config)
        self.policy = policy_engine or PolicyEngine(self.config)

        # Register modular action handlers
        self._handlers: Dict[ActionType, BaseActionHandler] = {
            ActionType.BLOCK_IP: BlockIPHandler(),
            ActionType.LOCK_ACCOUNT: LockAccountHandler(),
            ActionType.TERMINATE_SESSION: TerminateSessionHandler(),
            ActionType.NOTIFY_ANALYST: NotifyAnalystHandler(),
            ActionType.REVIEW_AUDIT: NotifyAnalystHandler(),
        }

    def _generate_action_id(self, incident_id: str, action_type: ActionType, target: str) -> str:
        raw = f"{incident_id}:{action_type.value}:{target}:{datetime.now(timezone.utc).isoformat()}"
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
        return f"act_{digest}"

    def propose_action(
        self,
        proposal: ResponseActionProposal,
        incident_risk_score: int = 50
    ) -> ResponseActionRecord:
        """Propose a containment or mitigation response action with safety and policy gating."""
        action_id = self._generate_action_id(proposal.incident_id, proposal.action_type, proposal.target)

        # 1. Safety Guardrail Validation (Allowlists & Command Injection)
        is_valid, safety_err = self.safety.validate_target(proposal.action_type, proposal.target)
        if not is_valid:
            record = ResponseActionRecord(
                action_id=action_id,
                incident_id=proposal.incident_id,
                action_type=proposal.action_type,
                target=proposal.target,
                parameters=proposal.parameters,
                priority=proposal.priority,
                reason=proposal.reason,
                status=ActionStatus.REJECTED,
                dry_run=self.config.dry_run,
                requires_approval=True,
                requested_by=proposal.requested_by,
                error_message=safety_err,
            )
            self.repository.save_action(record)
            return record

        # 2. Rate Limit / Throttling Check
        within_limits, limit_err = self.safety.check_rate_limit(proposal.target)
        if not within_limits:
            record = ResponseActionRecord(
                action_id=action_id,
                incident_id=proposal.incident_id,
                action_type=proposal.action_type,
                target=proposal.target,
                parameters=proposal.parameters,
                priority=proposal.priority,
                reason=proposal.reason,
                status=ActionStatus.REJECTED,
                dry_run=self.config.dry_run,
                requires_approval=True,
                requested_by=proposal.requested_by,
                error_message=limit_err,
            )
            self.repository.save_action(record)
            return record

        # 3. Policy Evaluation (Approval Gating & Dry-Run Mode)
        decision = self.policy.evaluate(
            action_type=proposal.action_type,
            target=proposal.target,
            incident_risk_score=incident_risk_score,
            priority=proposal.priority,
        )

        initial_status = ActionStatus.APPROVED if not decision.requires_approval else ActionStatus.PROPOSED

        record = ResponseActionRecord(
            action_id=action_id,
            incident_id=proposal.incident_id,
            action_type=proposal.action_type,
            target=proposal.target,
            parameters=proposal.parameters,
            priority=proposal.priority,
            reason=f"{proposal.reason} (Policy: {decision.policy_reason})",
            status=initial_status,
            dry_run=decision.dry_run,
            requires_approval=decision.requires_approval,
            requested_by=proposal.requested_by,
            approved_by="policy_engine" if not decision.requires_approval else None,
            approved_at=datetime.now(timezone.utc).isoformat() if not decision.requires_approval else None,
        )

        self.repository.save_action(record)
        return record

    def approve_action(
        self,
        action_id: str,
        analyst_name: str,
        comment: Optional[str] = None
    ) -> ResponseActionRecord:
        """Approve a proposed response action with analyst signature."""
        action = self.repository.get_action(action_id)
        if not action:
            raise ValueError(f"Response action '{action_id}' not found.")

        if action.status not in {ActionStatus.PROPOSED, ActionStatus.REJECTED}:
            raise ValueError(f"Cannot approve action with current status '{action.status.value}'.")

        # Re-validate target against safety allowlist prior to approving
        is_valid, safety_err = self.safety.validate_target(action.action_type, action.target)
        if not is_valid:
            action.status = ActionStatus.REJECTED
            action.error_message = f"Approval rejected by safety guard: {safety_err}"
            self.repository.save_action(action)
            raise ValueError(action.error_message)

        now = datetime.now(timezone.utc).isoformat()
        action.status = ActionStatus.APPROVED
        action.approved_by = analyst_name
        action.approved_at = now
        if comment:
            action.reason += f" | Analyst note: {comment}"

        self.repository.save_action(action)
        return action

    def execute_action(
        self,
        action_id: str,
        force_live: bool = False
    ) -> ExecutionResult:
        """Execute or simulate an approved response action."""
        action = self.repository.get_action(action_id)
        if not action:
            raise ValueError(f"Response action '{action_id}' not found.")

        if action.status != ActionStatus.APPROVED:
            raise ValueError(
                f"Action '{action_id}' cannot be executed with status '{action.status.value}'. "
                f"Must be APPROVED first."
            )

        handler = self._handlers.get(action.action_type)
        if not handler:
            action.status = ActionStatus.FAILED
            action.error_message = f"No handler registered for action type '{action.action_type.value}'."
            self.repository.save_action(action)
            raise ValueError(action.error_message)

        # Safety & rate limit check immediately before execution
        within_limits, limit_err = self.safety.check_rate_limit(action.target)
        if not within_limits:
            action.status = ActionStatus.FAILED
            action.error_message = limit_err
            self.repository.save_action(action)
            raise ValueError(limit_err)

        effective_dry_run = action.dry_run if not force_live else False

        result = handler.execute(
            action_id=action.action_id,
            target=action.target,
            parameters=action.parameters,
            dry_run=effective_dry_run,
        )

        # Update action state
        action.status = result.status
        action.executed_at = result.executed_at
        action.execution_output = result.execution_output
        action.dry_run = effective_dry_run
        if result.execution_output and "rollback_data" in result.execution_output:
            action.rollback_data = result.execution_output["rollback_data"]

        self.safety.record_action_executed(action.target)
        self.repository.save_action(action)
        return result

    def rollback_action(
        self,
        action_id: str,
        analyst_name: str
    ) -> RollbackResult:
        """Roll back a previously executed or simulated containment action."""
        action = self.repository.get_action(action_id)
        if not action:
            raise ValueError(f"Response action '{action_id}' not found.")

        if action.status not in {ActionStatus.EXECUTED, ActionStatus.SIMULATED}:
            raise ValueError(
                f"Cannot roll back action '{action_id}' with status '{action.status.value}'. "
                f"Must be EXECUTED or SIMULATED."
            )

        if not action.rollback_data:
            raise ValueError(f"Action '{action_id}' has no rollback data recorded.")

        handler = self._handlers.get(action.action_type)
        if not handler:
            raise ValueError(f"No handler registered for action type '{action.action_type.value}'.")

        res = handler.rollback(
            action_id=action.action_id,
            rollback_data=action.rollback_data,
            dry_run=action.dry_run,
        )

        now = datetime.now(timezone.utc).isoformat()
        action.status = ActionStatus.ROLLED_BACK
        action.rolled_back_at = now
        action.reason += f" | Rolled back by {analyst_name}"
        self.repository.save_action(action)
        return res

    def stage_ai_recommendations(
        self,
        incident_id: str,
        recommendations: List[RecommendationEntry],
        incident_risk_score: int = 50
    ) -> List[ResponseActionRecord]:
        """Convert structured AI Copilot recommendations into staged response action proposals."""
        staged_actions: List[ResponseActionRecord] = []

        type_map = {
            "block_ip": ActionType.BLOCK_IP,
            "lock_account": ActionType.LOCK_ACCOUNT,
            "terminate_session": ActionType.TERMINATE_SESSION,
            "review_audit": ActionType.REVIEW_AUDIT,
            "notify_analyst": ActionType.NOTIFY_ANALYST,
        }

        priority_map = {
            "immediate": ActionPriority.IMMEDIATE,
            "high": ActionPriority.HIGH,
            "medium": ActionPriority.MEDIUM,
            "low": ActionPriority.LOW,
        }

        for rec in recommendations:
            action_enum = type_map.get(rec.action_type.lower(), ActionType.REVIEW_AUDIT)
            priority_enum = priority_map.get(rec.priority.lower(), ActionPriority.MEDIUM)

            # Determine target from parameters
            params = rec.parameters or {}
            target = params.get("ip") or params.get("username") or params.get("target") or params.get("host") or "incident_entities"

            proposal = ResponseActionProposal(
                incident_id=incident_id,
                action_type=action_enum,
                target=str(target),
                parameters=params,
                priority=priority_enum,
                reason=rec.recommendation,
                requested_by="ai_copilot",
            )

            record = self.propose_action(proposal, incident_risk_score=incident_risk_score)
            staged_actions.append(record)

        return staged_actions
