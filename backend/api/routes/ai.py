"""Evidence-grounded AI Copilot REST API endpoints."""

import logging
from fastapi import APIRouter, Depends, HTTPException, status

from backend.ai.copilot import AIAssistantCopilot
from backend.ai.schemas import AIAnalysisReport, AIChatRequest, AIChatResponse, EventExplanation
from backend.api.dependencies import incident_repo, storage_sink, verify_api_key

logger = logging.getLogger("AIRoutes")

router = APIRouter(
    prefix="/api/v1/ai",
    tags=["AI Investigation Assistant"],
    dependencies=[Depends(verify_api_key)],
)

copilot = AIAssistantCopilot()


@router.get("/status")
async def get_ai_status():
    """Retrieve operational status of the Explainable AI engine and active LLM provider."""
    is_gemini = copilot.gemini.is_configured()
    return {
        "provider": "gemini" if is_gemini else "local",
        "model_name": copilot.gemini.model if is_gemini else "ThreadGrid Local Synthesizer",
        "gemini_configured": is_gemini,
        "max_context_events": copilot.config.max_context_events,
        "strict_citations_enforced": copilot.config.enforce_strict_citations,
    }


@router.post("/chat", response_model=AIChatResponse)
async def chat_with_ai(payload: AIChatRequest) -> AIChatResponse:
    """Interactive conversational Q&A about an incident with grounded citation reasoning."""
    incident = incident_repo.get_incident(payload.incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{payload.incident_id}' not found.",
        )

    try:
        response = copilot.chat_about_incident(
            incident=incident,
            user_query=payload.prompt,
            event_repo=storage_sink,
            history=payload.history,
        )
        return response
    except Exception as e:
        logger.error(f"Error during AI chat session: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate AI response: {str(e)}",
        )


@router.post("/investigate/{incident_id}", response_model=AIAnalysisReport)
async def investigate_incident_with_ai(incident_id: str) -> AIAnalysisReport:
    """Generate a structured, evidence-grounded AI investigation report strictly citing verified log IDs."""
    incident = incident_repo.get_incident(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found.",
        )

    try:
        report = copilot.investigate_incident(
            incident=incident,
            event_repo=storage_sink,
        )
        return report
    except Exception as e:
        logger.error(f"Error during AI incident investigation: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate AI investigation: {str(e)}",
        )


@router.post("/explain_event/{event_id}", response_model=EventExplanation)
async def explain_event_with_ai(event_id: str) -> EventExplanation:
    """Generate an evidence-based forensic explanation of a single security event."""
    event = storage_sink.get_event_by_id(event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event with ID '{event_id}' not found.",
        )

    return copilot.explain_single_event(event)
