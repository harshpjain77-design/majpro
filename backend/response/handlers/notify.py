"""Handler for informational analyst and audit notifications."""

from datetime import datetime, timezone
from typing import Any, Dict
from backend.response.handlers.base import BaseActionHandler
from backend.response.schemas import ActionStatus, ExecutionResult, RollbackResult


class NotifyAnalystHandler(BaseActionHandler):
    """Dispatches high-priority notifications to SOC channels or audit logs."""

    def execute(
        self,
        action_id: str,
        target: str,
        parameters: Dict[str, Any],
        dry_run: bool
    ) -> ExecutionResult:
        now = datetime.now(timezone.utc).isoformat()
        channel = parameters.get("channel", "soc_security_audit")
        note = parameters.get("note", f"Notification dispatched regarding target {target}.")

        return ExecutionResult(
            action_id=action_id,
            status=ActionStatus.EXECUTED,
            dry_run=dry_run,
            message=f"Dispatched notification to channel '{channel}' regarding '{target}'.",
            execution_output={
                "channel": channel,
                "target": target,
                "note": note,
                "dispatched_at": now,
            },
            rollback_available=False,
            executed_at=now,
        )

    def rollback(
        self,
        action_id: str,
        rollback_data: Dict[str, Any],
        dry_run: bool
    ) -> RollbackResult:
        now = datetime.now(timezone.utc).isoformat()
        return RollbackResult(
            action_id=action_id,
            status=ActionStatus.ROLLED_BACK,
            message="Informational notification noted as retracted.",
            restoration_details={"restored_at": now},
            rolled_back_at=now,
        )
