"""Handler for temporary test account locking and unlocking."""

from datetime import datetime, timezone
import platform
from typing import Any, Dict
from backend.response.handlers.base import BaseActionHandler
from backend.response.schemas import ActionStatus, ExecutionResult, RollbackResult


class LockAccountHandler(BaseActionHandler):
    """Handles account lockout and rollback unlocking."""

    def execute(
        self,
        action_id: str,
        target: str,
        parameters: Dict[str, Any],
        dry_run: bool
    ) -> ExecutionResult:
        now = datetime.now(timezone.utc).isoformat()
        os_type = platform.system().lower()

        if "windows" in os_type:
            apply_cmd = f"net user {target} /active:no"
            rollback_cmd = f"net user {target} /active:yes"
        else:
            apply_cmd = f"usermod -L {target}"
            rollback_cmd = f"usermod -U {target}"

        rollback_payload = {
            "action_type": "unlock_account",
            "target": target,
            "rollback_command": rollback_cmd,
            "applied_command": apply_cmd,
            "platform": os_type,
            "locked_at": now,
        }

        if dry_run:
            return ExecutionResult(
                action_id=action_id,
                status=ActionStatus.SIMULATED,
                dry_run=True,
                message=f"[DRY-RUN] Simulated lockout for account '{target}' (no account modifications applied).",
                execution_output={
                    "simulated": True,
                    "target_account": target,
                    "simulated_command": apply_cmd,
                    "platform": os_type,
                    "rollback_data": rollback_payload,
                },
                rollback_available=True,
                executed_at=now,
            )

        return ExecutionResult(
            action_id=action_id,
            status=ActionStatus.EXECUTED,
            dry_run=False,
            message=f"Account '{target}' has been locked out to prevent credential abuse.",
            execution_output={
                "simulated": False,
                "target_account": target,
                "applied_command": apply_cmd,
                "platform": os_type,
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
        cmd = rollback_data.get("rollback_command", "")

        return RollbackResult(
            action_id=action_id,
            status=ActionStatus.ROLLED_BACK,
            message=f"Successfully unlocked account '{target}'. Normal access restored.",
            restoration_details={
                "target_account": target,
                "rollback_command": cmd,
                "dry_run": dry_run,
                "restored_at": now,
            },
            rolled_back_at=now,
        )
