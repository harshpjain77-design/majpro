"""Pydantic schemas and enums for the Controlled Automated Response Engine."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ActionType(str, Enum):
    """Supported containment and mitigation response action types."""
    BLOCK_IP = "block_ip"
    LOCK_ACCOUNT = "lock_account"
    TERMINATE_SESSION = "terminate_session"
    REVIEW_AUDIT = "review_audit"
    NOTIFY_ANALYST = "notify_analyst"


class ActionStatus(str, Enum):
    """Lifecycle status states for an automated or analyst-guided response action."""
    PROPOSED = "PROPOSED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"
    SIMULATED = "SIMULATED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"


class ActionPriority(str, Enum):
    """Priority level for executing the response action."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    IMMEDIATE = "immediate"


class ResponseActionProposal(BaseModel):
    """Input payload to propose a response action."""
    incident_id: str = Field(..., description="Correlated incident ID prompting this action.")
    action_type: ActionType = Field(..., description="Type of response action proposed.")
    target: str = Field(..., description="Target entity (IP address, username, or session ID).")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Action-specific execution parameters.")
    priority: ActionPriority = Field(default=ActionPriority.MEDIUM, description="Priority urgency level.")
    reason: str = Field(..., description="Justification and evidence supporting the response.")
    requested_by: str = Field(default="ai_copilot", description="Originator of proposal (e.g. ai_copilot, analyst).")


class ApprovalRequest(BaseModel):
    """Request model for analyst approval of a proposed action."""
    analyst_name: str = Field(..., min_length=2, description="Identity of the approving SOC analyst.")
    comment: Optional[str] = Field(default=None, description="Optional analyst notes on approval decision.")


class ExecutionResult(BaseModel):
    """Result of executing or simulating a response action."""
    action_id: str
    status: ActionStatus
    dry_run: bool
    message: str
    execution_output: Optional[Dict[str, Any]] = None
    rollback_available: bool = True
    executed_at: str


class RollbackResult(BaseModel):
    """Result of rolling back a previously executed response action."""
    action_id: str
    status: ActionStatus
    message: str
    restoration_details: Dict[str, Any]
    rolled_back_at: str


class ResponseActionRecord(BaseModel):
    """Complete persistent audit record of a response action throughout its lifecycle."""
    action_id: str = Field(..., description="Unique action tracking identifier (act_<hash>).")
    incident_id: str = Field(..., description="Associated correlated incident identifier.")
    action_type: ActionType
    target: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    priority: ActionPriority
    reason: str
    status: ActionStatus = ActionStatus.PROPOSED
    dry_run: bool = True
    requires_approval: bool = True
    requested_by: str = "ai_copilot"
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    executed_at: Optional[str] = None
    execution_output: Optional[Dict[str, Any]] = None
    rollback_data: Optional[Dict[str, Any]] = None
    rolled_back_at: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    error_message: Optional[str] = None


class SafetyStatusResponse(BaseModel):
    """Operational status of safety guardrails and allowlists."""
    dry_run: bool
    auto_execution_enabled: bool
    auto_execution_risk_threshold: int
    protected_ips: List[str]
    protected_users: List[str]
    rate_limit_per_minute: int
    total_actions_recorded: int
