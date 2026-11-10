"""Abstract base handler for containment and mitigation actions."""

from abc import ABC, abstractmethod
from typing import Any, Dict
from backend.response.schemas import ActionStatus, ExecutionResult, RollbackResult


class BaseActionHandler(ABC):
    """Abstract interface defining required execution and rollback methods for response actions."""

    @abstractmethod
    def execute(
        self,
        action_id: str,
        target: str,
        parameters: Dict[str, Any],
        dry_run: bool
    ) -> ExecutionResult:
        """Execute or simulate the containment action."""
        pass

    @abstractmethod
    def rollback(
        self,
        action_id: str,
        rollback_data: Dict[str, Any],
        dry_run: bool
    ) -> RollbackResult:
        """Revert the containment action and restore prior system state."""
        pass
