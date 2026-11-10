"""REST API routes for the Controlled Automated Response Engine."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.api.dependencies import get_response_engine, verify_api_key
from backend.correlation.repository import IncidentRepository
from backend.api.dependencies import incident_repo
from backend.ai.copilot import AIAssistantCopilot
from backend.response.engine import ResponseEngine
from backend.response.schemas import (
    ActionStatus,
    ApprovalRequest,
    ExecutionResult,
    ResponseActionProposal,
    ResponseActionRecord,
    RollbackResult,
    SafetyStatusResponse,
)

router = APIRouter(prefix="/api/v1/response", tags=["response"])


@router.post(
    "/propose",
    response_model=ResponseActionRecord,
    status_code=status.HTTP_201_CREATED,
    summary="Propose a containment or mitigation response action",
)
def propose_response_action(
    proposal: ResponseActionProposal,
    engine: ResponseEngine = Depends(get_response_engine),
    _: str = Depends(verify_api_key),
) -> ResponseActionRecord:
    """Submit a proposed response action for policy evaluation and safety allowlist checks."""
    try:
        # Retrieve risk score from incident if available
        incident = incident_repo.get_incident(proposal.incident_id)
        risk_score = incident.risk_score if incident else 50
        return engine.propose_action(proposal, incident_risk_score=risk_score)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/stage_incident/{incident_id}",
    response_model=List[ResponseActionRecord],
    summary="Stage automated response actions from AI copilot recommendations for an incident",
)
def stage_incident_response(
    incident_id: str,
    engine: ResponseEngine = Depends(get_response_engine),
    _: str = Depends(verify_api_key),
) -> List[ResponseActionRecord]:
    """Generate and stage structured response actions for an incident based on AI Copilot analysis."""
    incident = incident_repo.get_incident(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found."
        )

    # Use AI copilot to generate recommendations
    copilot = AIAssistantCopilot()
    report = copilot.investigate_incident(incident)

    staged = engine.stage_ai_recommendations(
        incident_id=incident.incident_id,
        recommendations=report.actionable_recommendations,
        incident_risk_score=incident.risk_score
    )
    return staged


@router.get(
    "/actions",
    summary="List response actions with status and incident filters",
)
def list_response_actions(
    incident_id: Optional[str] = Query(None, description="Filter by incident ID"),
    status: Optional[ActionStatus] = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    engine: ResponseEngine = Depends(get_response_engine),
    _: str = Depends(verify_api_key),
) -> dict:
    """Retrieve paginated response actions and audit state."""
    total, actions = engine.repository.list_actions(
        incident_id=incident_id,
        status=status,
        limit=limit,
        offset=offset
    )
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "actions": actions
    }


@router.get(
    "/actions/{action_id}",
    response_model=ResponseActionRecord,
    summary="Get response action details and audit log",
)
def get_response_action(
    action_id: str,
    engine: ResponseEngine = Depends(get_response_engine),
    _: str = Depends(verify_api_key),
) -> ResponseActionRecord:
    """Fetch details and current status for a specific response action."""
    action = engine.repository.get_action(action_id)
    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Response action '{action_id}' not found."
        )
    return action


@router.post(
    "/actions/{action_id}/approve",
    response_model=ResponseActionRecord,
    summary="Approve a proposed response action (Human-in-the-loop)",
)
def approve_action(
    action_id: str,
    approval: ApprovalRequest,
    engine: ResponseEngine = Depends(get_response_engine),
    _: str = Depends(verify_api_key),
) -> ResponseActionRecord:
    """Analyst explicit sign-off to transition action from PROPOSED to APPROVED."""
    try:
        return engine.approve_action(
            action_id=action_id,
            analyst_name=approval.analyst_name,
            comment=approval.comment
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/actions/{action_id}/execute",
    response_model=ExecutionResult,
    summary="Execute or simulate an approved response action",
)
def execute_action(
    action_id: str,
    force_live: bool = Query(False, description="Set True to override dry-run for live lab execution"),
    engine: ResponseEngine = Depends(get_response_engine),
    _: str = Depends(verify_api_key),
) -> ExecutionResult:
    """Execute an approved response action, enforcing dry-run by default."""
    try:
        return engine.execute_action(action_id=action_id, force_live=force_live)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/actions/{action_id}/rollback",
    response_model=RollbackResult,
    summary="Roll back an executed or simulated response action",
)
def rollback_action(
    action_id: str,
    approval: ApprovalRequest,
    engine: ResponseEngine = Depends(get_response_engine),
    _: str = Depends(verify_api_key),
) -> RollbackResult:
    """Revert a containment action and restore network/account state."""
    try:
        return engine.rollback_action(action_id=action_id, analyst_name=approval.analyst_name)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/safety/status",
    response_model=SafetyStatusResponse,
    summary="Get response engine safety guardrails and allowlist status",
)
def get_safety_status(
    engine: ResponseEngine = Depends(get_response_engine),
    _: str = Depends(verify_api_key),
) -> SafetyStatusResponse:
    """Return active safety configuration, protected IPs and usernames, and dry-run state."""
    total_actions, _ = engine.repository.list_actions(limit=1, offset=0)
    return SafetyStatusResponse(
        dry_run=engine.config.dry_run,
        auto_execution_enabled=engine.config.auto_execution_enabled,
        auto_execution_risk_threshold=engine.config.auto_execution_risk_threshold,
        protected_ips=sorted(list(engine.config.protected_ips)),
        protected_users=sorted(list(engine.config.protected_users)),
        rate_limit_per_minute=engine.config.max_actions_per_minute_per_target,
        total_actions_recorded=total_actions,
    )
