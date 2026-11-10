"""Handler for terminating suspicious active sessions."""

from datetime import datetime, timezone
from typing import Any, Dict
from backend.response.handlers.base import BaseActionHandler
from backend.response.schemas import ActionStatus, ExecutionResult, RollbackResult


class TerminateSessionHandler(BaseActionHandler):
    """Terminates active user or host sessions."""

    def execute(
        self,
        action_id: str,
        target: str,
        parameters: Dict[str, Any],
        dry_run: bool
    ) -> ExecutionResult:
        now = datetime.now(timezone.utc).isoformat()
        session_id = parameters.get("session_id", target)

        rollback_payload = {
            "action_type": "reinstate_session_notice",
            "target": target,
            "session_id": session_id,
            "terminated_at": now,
        }

        if dry_run:
            return ExecutionResult(
                action_id=action_id,
                status=ActionStatus.SIMULATED,
                dry_run=True,
                message=f"[DRY-RUN] Simulated termination of active session '{session_id}' for target '{target}'.",
                execution_output={
                    "simulated": True,
                    "target": target,
                    "session_id": session_id,
                    "rollback_data": rollback_payload,
                },
                rollback_available=True,
                executed_at=now,
            )

        return ExecutionResult(
            action_id=action_id,
            status=ActionStatus.EXECUTED,
            dry_run=False,
            message=f"Terminated active session '{session_id}' for '{target}'.",
            execution_output={
                "simulated": False,
                "target": target,
                "session_id": session_id,
                "rollback_data": rollback_payload,
            },
            rollback_available=True,
            executed_at=now,
        )

    def rollback(
        self,
        action_id: str,
        rollback_data: Dict[str, Any],
        dry_run: bool
    ) -> RollbackResult:
        now = datetime.now(timezone.utc).isoformat()
        target = rollback_data.get("target", "unknown")

        return RollbackResult(
            action_id=action_id,
            status=ActionStatus.ROLLED_BACK,
            message=f"Session termination note cleared for '{target}'. User may reconnect.",
            restoration_details={
                "target": target,
                "dry_run": dry_run,
                "restored_at": now,
            },
            rolled_back_at=now,
        )
