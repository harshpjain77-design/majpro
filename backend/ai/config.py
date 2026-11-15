"""Configuration for evidence-grounded AI investigation assistant and prompt defense."""

import os
from typing import Optional
from dotenv import load_dotenv
from pydantic import BaseModel, Field

load_dotenv()


class AIConfig(BaseModel):
    """Configuration settings for AI Copilot, prompt sanitization, and citation enforcement."""

    # AI provider: "gemini" or "local" (offline deterministic synthesizer)
    provider: str = Field(
        default_factory=lambda: os.getenv("AI_PROVIDER", "gemini").lower(),
        description="AI engine provider: 'gemini' (Google Gemini API) or 'local' (offline deterministic synthesizer)",
    )

    model_name: str = Field(
        default_factory=lambda: os.getenv("GEMINI_MODEL", "gemini-3.5-flash"),
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

    # External LLM endpoint
    external_api_url: Optional[str] = Field(
        default=None,
        description="URL for external LLM inference server if configured",
    )

    external_api_key: Optional[str] = Field(
        default_factory=lambda: os.getenv("GEMINI_API_KEY", None),
        description="API key for external LLM inference server",
    )


default_ai_config = AIConfig()
