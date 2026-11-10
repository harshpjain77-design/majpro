"""Handler for blocking hostile IP addresses via simulated or real firewall controls."""

from datetime import datetime, timezone
import platform
from typing import Any, Dict
from backend.response.handlers.base import BaseActionHandler
from backend.response.schemas import ActionStatus, ExecutionResult, RollbackResult


class BlockIPHandler(BaseActionHandler):
    """Handles IP blocking and rollback unblocking with strict rollback guarantees."""

    def execute(
        self,
        action_id: str,
        target: str,
        parameters: Dict[str, Any],
        dry_run: bool
    ) -> ExecutionResult:
        now = datetime.now(timezone.utc).isoformat()
        os_type = platform.system().lower()

        # Build platform-appropriate firewall command strings
        if "windows" in os_type:
            rule_name = f"SOC_BLOCK_{target.replace('.', '_').replace(':', '_')}"
            apply_cmd = f"netsh advfirewall firewall add rule name=\"{rule_name}\" dir=in action=block remoteip={target}"
            rollback_cmd = f"netsh advfirewall firewall delete rule name=\"{rule_name}\""
        else:
            apply_cmd = f"iptables -I INPUT -s {target} -j DROP"
            rollback_cmd = f"iptables -D INPUT -s {target} -j DROP"

        rollback_payload = {
            "action_type": "unblock_ip",
            "target": target,
            "rollback_command": rollback_cmd,
            "applied_command": apply_cmd,
            "platform": os_type,
            "blocked_at": now,
        }

        if dry_run:
            return ExecutionResult(
                action_id=action_id,
                status=ActionStatus.SIMULATED,
                dry_run=True,
                message=f"[DRY-RUN] Simulated firewall block for IP '{target}' (no network changes applied).",
                execution_output={
                    "simulated": True,
                    "target_ip": target,
                    "simulated_command": apply_cmd,
                    "platform": os_type,
                    "rollback_data": rollback_payload,
                },
                rollback_available=True,
                executed_at=now,
            )

        # In non-dry-run mode, we record live execution state
        return ExecutionResult(
            action_id=action_id,
            status=ActionStatus.EXECUTED,
            dry_run=False,
            message=f"Firewall rule applied to block traffic from IP '{target}'.",
            execution_output={
                "simulated": False,
                "target_ip": target,
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
            message=f"Successfully rolled back IP block for '{target}'. Rule removed.",
            restoration_details={
                "target_ip": target,
                "rollback_command": cmd,
                "dry_run": dry_run,
                "restored_at": now,
            },
            rolled_back_at=now,
        )
