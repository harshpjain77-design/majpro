"""Persistent SQLite storage sink with WAL mode and duplicate event tracking."""

from backend.storage.sqlite_repository import SQLiteEventRepository


class EventStorageSink(SQLiteEventRepository):
    """EventStorageSink inherits from SQLiteEventRepository for backward compatibility."""

    pass


__all__ = ["EventStorageSink"]
