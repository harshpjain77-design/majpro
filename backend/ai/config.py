"""Configuration for evidence-grounded AI investigation assistant and prompt defense."""

from typing import Optional
from pydantic import BaseModel, Field


class AIConfig(BaseModel):
    """Configuration settings for AI Copilot, prompt sanitization, and citation enforcement."""

    # AI provider: "local" (deterministic evidence synthesizer, zero external cost/API) or "external"
    provider: str = Field(
        default="local",
        description="AI engine provider: 'local' (offline deterministic synthesizer) or 'external' (HTTP LLM)",
    )

    model_name: str = Field(
        default="evidence-synthesizer-v1.0",
        description="Model identifier or engine version",
    )

    # Maximum number of raw forensic events to include in the context window
    max_context_events: int = Field(
        default=30,
        ge=1,
        le=200,
        description="Maximum raw events injected into evidence context window",
    )

    # Whether to validate that every citation corresponds to a verified event/alert ID
    enforce_strict_citations: bool = Field(
        default=True,
        description="Verify that cited IDs strictly exist in the incident evidence set",
    )

    # External LLM endpoint (used only if provider is 'external')
    external_api_url: Optional[str] = Field(
        default=None,
        description="URL for external LLM inference server if configured",
    )

    external_api_key: Optional[str] = Field(
        default=None,
        description="API key for external LLM inference server if configured",
    )


default_ai_config = AIConfig()
