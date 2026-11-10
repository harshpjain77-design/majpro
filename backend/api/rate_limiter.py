"""In-memory sliding-window rate limiter for ingestion endpoints."""

import threading
import time
from typing import Dict, List, Tuple


class SlidingWindowRateLimiter:
    """Thread-safe sliding window rate limiter per client IP or Agent ID."""

    def __init__(self, limit: int = 120, window_seconds: int = 60):
        self.limit = limit
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._requests: Dict[str, List[float]] = {}

    def is_allowed(self, key: str) -> Tuple[bool, int, int]:
        """Check whether the request is allowed under the rate limit.

        Returns: (is_allowed, remaining_requests, retry_after_seconds)
        """
        now = time.time()
        cutoff = now - self.window_seconds

        with self._lock:
            timestamps = self._requests.get(key, [])
            # Evict timestamps older than the window
            timestamps = [t for t in timestamps if t > cutoff]

            if len(timestamps) >= self.limit:
                # Calculate time until earliest record expires
                earliest = timestamps[0]
                retry_after = max(1, int(earliest + self.window_seconds - now))
                self._requests[key] = timestamps
                return False, 0, retry_after

            timestamps.append(now)
            self._requests[key] = timestamps
            remaining = self.limit - len(timestamps)
            return True, remaining, 0

    def reset(self) -> None:
        """Reset all rate limiter tracking records (useful for testing)."""
        with self._lock:
            self._requests.clear()
