"""Durable checkpoint management for Linux collectors."""

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional


class LinuxCheckpoint:
    """Manages durable state checkpoints for file tailing and journal cursor streaming."""

    def __init__(self, checkpoint_path: str):
        self.checkpoint_path = Path(checkpoint_path)
        self.data: Dict[str, Any] = {
            "version": "1.0",
            "file_path": None,
            "inode": None,
            "offset": 0,
            "file_size": 0,
            "journal_cursor": None,
            "last_line_hash": None,
            "updated_at": None,
        }
        self.load()

    def load(self) -> None:
        """Load checkpoint from disk if it exists."""
        if self.checkpoint_path.exists():
            try:
                with open(self.checkpoint_path, "r", encoding="utf-8") as f:
                    content = json.load(f)
                    if isinstance(content, dict):
                        self.data.update(content)
            except Exception:
                # If corrupted, start with fresh default state rather than crashing
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

    def get_offset(self) -> int:
        return int(self.data.get("offset", 0))

    def get_inode(self) -> Optional[int]:
        inode = self.data.get("inode")
        return int(inode) if inode is not None else None

    def get_journal_cursor(self) -> Optional[str]:
        return self.data.get("journal_cursor")

    def update_file_position(
        self,
        file_path: str,
        inode: int,
        offset: int,
        file_size: int,
        last_line_hash: Optional[str] = None,
    ) -> None:
        from datetime import datetime, timezone

        self.data.update(
            {
                "file_path": file_path,
                "inode": inode,
                "offset": offset,
                "file_size": file_size,
                "last_line_hash": last_line_hash,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        self.save()

    def update_journal_cursor(self, cursor: str) -> None:
        from datetime import datetime, timezone

        self.data.update(
            {
                "journal_cursor": cursor,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        self.save()

    def is_rotated_or_truncated(self, current_inode: int, current_size: int) -> bool:
        """Detect whether the monitored file has been rotated or truncated."""
        saved_inode = self.get_inode()
        saved_offset = self.get_offset()

        # Inode changed -> log rotation occurred
        if saved_inode is not None and current_inode != saved_inode:
            return True

        # Current file size is smaller than previously saved offset -> log truncated (copytruncate)
        if current_size < saved_offset:
            return True

        return False
