"""Abstract base interface for security event repositories."""

from abc import ABC, abstractmethod
from typing import List, Optional, Tuple

from collectors.common.schemas import SecurityEvent
from backend.storage.models import (
    EventFilter,
    PaginationParams,
    PaginatedEventsResponse,
    TimeSeriesBucket,
    EventSummaryResponse,
)


class EventRepository(ABC):
    """Abstract interface defining required storage operations for security events."""

    @abstractmethod
    def insert_event(self, event: SecurityEvent, agent_id: Optional[str] = None) -> bool:
        """Insert a single event. Returns True if inserted, False if duplicate."""
        pass

    @abstractmethod
    def insert_batch(
        self,
        events: List[SecurityEvent],
        agent_id: Optional[str] = None,
    ) -> Tuple[int, int, List[str]]:
        """Insert a batch of events transactionally.

        Returns: (ingested_count, duplicate_count, list_of_ingested_event_ids)
        """
        pass

    @abstractmethod
    def get_event_by_id(self, event_id: str) -> Optional[SecurityEvent]:
        """Retrieve full SecurityEvent by unique event_id, or None if not found."""
        pass

    @abstractmethod
    def get_raw_event(self, event_id: str) -> Optional[str]:
        """Retrieve the original unparsed raw event string/XML by event_id."""
        pass

    @abstractmethod
    def search_events(
        self,
        filters: EventFilter,
        pagination: PaginationParams,
        sort_by: str = "timestamp",
        sort_dir: str = "desc",
    ) -> PaginatedEventsResponse:
        """Query events matching multi-field criteria with pagination and sorting."""
        pass

    @abstractmethod
    def count_events(self, filters: Optional[EventFilter] = None) -> int:
        """Return total count of stored events matching optional filter."""
        pass

    @abstractmethod
    def get_summary_counts(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> EventSummaryResponse:
        """Return aggregated distributions and time-series histogram."""
        pass

    @abstractmethod
    def get_time_series_buckets(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        interval: str = "hour",
    ) -> List[TimeSeriesBucket]:
        """Aggregate event counts grouped by chronological time intervals."""
        pass

    @abstractmethod
    def check_health(self) -> bool:
        """Verify storage backend connectivity and responsiveness."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Safely release storage resources and connection pools."""
        pass
