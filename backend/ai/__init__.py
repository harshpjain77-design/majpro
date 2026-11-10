"""Evidence-grounded AI Copilot and prompt injection defense module."""

from backend.ai.citation_validator import CitationValidator
from backend.ai.config import AIConfig, default_ai_config
from backend.ai.copilot import AIAssistantCopilot
from backend.ai.prompt_defense import PromptInjectionSanitizer
from backend.ai.schemas import (
    AIAnalysisReport,
    EventExplanation,
    FactEntry,
    HypothesisEntry,
    RecommendationEntry,
)

__all__ = [
    "AIAnalysisReport",
    "AIAssistantCopilot",
    "AIConfig",
    "CitationValidator",
    "EventExplanation",
    "FactEntry",
    "HypothesisEntry",
    "PromptInjectionSanitizer",
    "RecommendationEntry",
    "default_ai_config",
]
