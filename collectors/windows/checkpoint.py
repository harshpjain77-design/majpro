"""Durable checkpoint management for Windows Security Event Log collector."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional


class WindowsCheckpoint:
    """Manages durable state checkpoints for Windows Event Log record numbers and bookmarks."""

    def __init__(self, checkpoint_path: str = "checkpoint_windows.json"):
        self.checkpoint_path = Path(checkpoint_path)
        self.data: Dict[str, Any] = {
            "version": "1.0",
            "channel": "Security",
            "last_record_number": 0,
            "bookmark_xml": None,
            "last_event_timestamp": None,
            "updated_at": None,
        }
        self.load()

    def load(self) -> None:
        """Load checkpoint from disk if present."""
        if self.checkpoint_path.exists():
            try:
                with open(self.checkpoint_path, "r", encoding="utf-8") as f:
                    content = json.load(f)
                    if isinstance(content, dict):
                        self.data.update(content)
            except Exception:
                # Corrupted or unreadable checkpoint; fallback to defaults safely
                pass

    def save(self) -> None:
        """Persist checkpoint atomically to disk."""
        self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self.checkpoint_path.with_suffix(".tmp")
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2)
            os.replace(temp_path, self.checkpoint_path)
        except Exception as e:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass
            raise IOError(f"Failed to write checkpoint to {self.checkpoint_path}: {e}") from e

    def get_last_record_number(self) -> int:
        return int(self.data.get("last_record_number", 0))

    def get_bookmark_xml(self) -> Optional[str]:
        return self.data.get("bookmark_xml")

    def update_record(
        self,
        record_number: int,
        bookmark_xml: Optional[str] = None,
        event_timestamp: Optional[str] = None,
    ) -> None:
        """Update last processed record number and persist state."""
        self.data["last_record_number"] = record_number
        if bookmark_xml:
            self.data["bookmark_xml"] = bookmark_xml
        if event_timestamp:
            self.data["last_event_timestamp"] = event_timestamp
        self.data["updated_at"] = datetime.now(timezone.utc).isoformat()
        self.save()

    def check_log_reset(self, current_oldest_record: int, current_newest_record: int) -> bool:
        """Detect whether the event log was cleared or record numbers reset."""
        last_rec = self.get_last_record_number()
        if last_rec == 0:
            return False

        # If last record is beyond the newest record in the log, log was cleared or reset
        if last_rec > current_newest_record:
            return True

        # If last record is older than the oldest record available, log wrapped around
        if last_rec < current_oldest_record:
            return True

        return False

    def reset_checkpoint(self, starting_record: int = 0) -> None:
        """Explicitly reset checkpoint record position."""
        self.data["last_record_number"] = starting_record
        self.data["bookmark_xml"] = None
        self.data["updated_at"] = datetime.now(timezone.utc).isoformat()
        self.save()
