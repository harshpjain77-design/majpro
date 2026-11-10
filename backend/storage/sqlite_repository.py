"""SQLite implementation of EventRepository with WAL mode and indexed query planner."""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Tuple

from collectors.common.schemas import SecurityEvent
from backend.storage.base import EventRepository
from backend.storage.models import (
    EventFilter,
    PaginationParams,
    PaginatedEventsResponse,
    TimeSeriesBucket,
    EventSummaryResponse,
)

logger = logging.getLogger("SQLiteEventRepository")


class SQLiteEventRepository(EventRepository):
    """Production-grade local SQLite repository supporting indexed queries and aggregations."""

    def __init__(self, db_path: str = "output/soc_events.sqlite"):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                timeout=30.0,
            )
            self._conn.row_factory = sqlite3.Row
            # Enable Write-Ahead Logging (WAL) for concurrent read access
            self._conn.execute("PRAGMA journal_mode = WAL;")
            self._conn.execute("PRAGMA synchronous = NORMAL;")
            self._conn.execute("PRAGMA busy_timeout = 30000;")
        return self._conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._get_connection()
            with conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS events (
                        event_id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        observed_at TEXT NOT NULL,
                        source_host TEXT NOT NULL,
                        source_type TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        username TEXT,
                        source_ip TEXT,
                        destination_ip TEXT,
                        windows_event_id INTEGER,
                        severity TEXT NOT NULL,
                        raw_event TEXT NOT NULL,
                        collector_version TEXT,
                        metadata_json TEXT,
                        ingested_at TEXT NOT NULL,
                        agent_id TEXT
                    );
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_events_source_host ON events(source_host);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_events_username ON events(username);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);")

    def insert_event(self, event: SecurityEvent, agent_id: Optional[str] = None) -> bool:
        ingested, _, _ = self.insert_batch([event], agent_id=agent_id)
        return ingested > 0

    def insert_batch(
        self,
        events: List[SecurityEvent],
        agent_id: Optional[str] = None,
    ) -> Tuple[int, int, List[str]]:
        if not events:
            return 0, 0, []

        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        ingested_ids: List[str] = []
        duplicates = 0

        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            try:
                cursor.execute("BEGIN TRANSACTION;")
                for ev in events:
                    meta_str = json.dumps(ev.metadata or {})
                    cursor.execute(
                        """
                        INSERT OR IGNORE INTO events (
                            event_id, timestamp, observed_at, source_host, source_type,
                            event_type, username, source_ip, destination_ip, windows_event_id,
                            severity, raw_event, collector_version, metadata_json,
                            ingested_at, agent_id
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            ev.event_id,
                            ev.timestamp,
                            ev.observed_at,
                            ev.source_host,
                            ev.source_type,
                            ev.event_type,
                            ev.username,
                            ev.source_ip,
                            ev.destination_ip,
                            ev.windows_event_id,
                            ev.severity,
                            ev.raw_event,
                            ev.collector_version,
                            meta_str,
                            now_utc,
                            agent_id,
                        ),
                    )
                    if cursor.rowcount > 0:
                        ingested_ids.append(ev.event_id)
                    else:
                        duplicates += 1
                conn.commit()
            except Exception as e:
                conn.rollback()
                logger.error(f"Transaction failed during batch insertion: {e}")
                raise

        return len(ingested_ids), duplicates, ingested_ids

    def _row_to_event(self, row: sqlite3.Row) -> SecurityEvent:
        metadata: Dict[str, Any] = {}
        if row["metadata_json"]:
            try:
                metadata = json.loads(row["metadata_json"])
            except Exception:
                pass

        ingested_at = None
        try:
            if "ingested_at" in row.keys():
                ingested_at = row["ingested_at"]
        except Exception:
            pass

        return SecurityEvent(
            schema_version="1.0",
            event_id=row["event_id"],
            timestamp=row["timestamp"],
            observed_at=row["observed_at"],
            source_host=row["source_host"],
            source_type=row["source_type"],
            event_type=row["event_type"],
            username=row["username"],
            source_ip=row["source_ip"],
            destination_ip=row["destination_ip"],
            windows_event_id=row["windows_event_id"],
            severity=row["severity"],
            raw_event=row["raw_event"],
            collector_version=row["collector_version"] or "0.1.0",
            metadata=metadata,
            ingested_at=ingested_at,
        )

    def get_event_by_id(self, event_id: str) -> Optional[SecurityEvent]:
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM events WHERE event_id = ? LIMIT 1;", (event_id,))
            row = cursor.fetchone()
            if row:
                return self._row_to_event(row)
            return None

    def get_raw_event(self, event_id: str) -> Optional[str]:
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT raw_event FROM events WHERE event_id = ? LIMIT 1;", (event_id,))
            row = cursor.fetchone()
            if row:
                return str(row["raw_event"])
            return None

    def _build_where_clause(self, filters: Optional[EventFilter]) -> Tuple[str, List[Any]]:
        if not filters:
            return "", []

        conditions: List[str] = []
        params: List[Any] = []

        if filters.start_time:
            conditions.append("timestamp >= ?")
            params.append(filters.start_time)

        if filters.end_time:
            conditions.append("timestamp <= ?")
            params.append(filters.end_time)

        if filters.source_host:
            h = filters.source_host.strip()
            conditions.append("""(
                LOWER(source_host) = LOWER(?)
                OR LOWER(COALESCE(agent_id, '')) = LOWER(?)
                OR LOWER(source_host) LIKE LOWER(?)
                OR LOWER(COALESCE(agent_id, '')) LIKE LOWER(?)
            )""")
            params.extend([h, h, f"%{h}%", f"%{h}%"])

        if filters.username:
            u = filters.username.strip()
            conditions.append("(LOWER(username) = LOWER(?) OR LOWER(username) LIKE LOWER(?))")
            params.extend([u, f"%{u}%"])

        if filters.source_ip:
            ip_val = filters.source_ip.strip()
            conditions.append("(source_ip = ? OR source_ip LIKE ?)")
            params.extend([ip_val, f"%{ip_val}%"])

        if filters.event_type:
            et = filters.event_type.strip()
            conditions.append("(LOWER(event_type) = LOWER(?) OR LOWER(event_type) LIKE LOWER(?))")
            params.extend([et, f"%{et}%"])

        if filters.severity:
            sev = filters.severity.strip().lower()
            if sev != "all":
                conditions.append("LOWER(severity) = ?")
                params.append(sev)

        if filters.search_term:
            term = f"%{filters.search_term.strip()}%"
            conditions.append("""(
                raw_event LIKE ?
                OR source_host LIKE ?
                OR username LIKE ?
                OR source_ip LIKE ?
                OR destination_ip LIKE ?
                OR event_type LIKE ?
                OR severity LIKE ?
                OR CAST(windows_event_id AS TEXT) LIKE ?
                OR COALESCE(agent_id, '') LIKE ?
            )""")
            params.extend([term] * 9)

        if conditions:
            return "WHERE " + " AND ".join(conditions), params
        return "", []

    def count_events(self, filters: Optional[EventFilter] = None) -> int:
        where_sql, params = self._build_where_clause(filters)
        sql = f"SELECT COUNT(*) as cnt FROM events {where_sql};"

        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(sql, params)
            row = cursor.fetchone()
            return int(row["cnt"]) if row else 0

    def search_events(
        self,
        filters: EventFilter,
        pagination: PaginationParams,
        sort_by: str = "ingested_at",
        sort_dir: str = "desc",
    ) -> PaginatedEventsResponse:
        total = self.count_events(filters)

        allowed_sort_fields = {
            "timestamp": "timestamp",
            "ingested_at": "ingested_at",
            "ingested": "ingested_at",
            "received_at": "ingested_at",
            "observed_at": "observed_at",
            "source_ip": "source_ip",
            "ip": "source_ip",
            "source_host": "source_host",
            "host": "source_host",
            "severity": "severity",
            "event_type": "event_type",
            "windows_event_id": "windows_event_id",
            "username": "username",
        }
        col = allowed_sort_fields.get((sort_by or "").lower(), "ingested_at")
        direction = "ASC" if (sort_dir or "").lower() == "asc" else "DESC"

        where_sql, params = self._build_where_clause(filters)
        query_sql = f"""
            SELECT * FROM events
            {where_sql}
            ORDER BY {col} {direction}, rowid {direction}
            LIMIT ? OFFSET ?;
        """
        query_params = list(params) + [pagination.limit, pagination.offset]

        events: List[SecurityEvent] = []
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(query_sql, query_params)
            for row in cursor.fetchall():
                events.append(self._row_to_event(row))

        has_more = (pagination.offset + len(events)) < total

        return PaginatedEventsResponse(
            total=total,
            limit=pagination.limit,
            offset=pagination.offset,
            has_more=has_more,
            events=events,
        )

    def get_time_series_buckets(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        interval: str = "hour",
    ) -> List[TimeSeriesBucket]:
        # Choose strftime format based on interval
        if interval == "minute":
            strftime_fmt = "%Y-%m-%dT%H:%M:00Z"
        elif interval == "day":
            strftime_fmt = "%Y-%m-%dT00:00:00Z"
        else:
            strftime_fmt = "%Y-%m-%dT%H:00:00Z"  # Default: hour

        filters = EventFilter(start_time=start_time, end_time=end_time)
        where_sql, params = self._build_where_clause(filters)

        sql = f"""
            SELECT strftime('{strftime_fmt}', timestamp) AS bucket, COUNT(*) AS count
            FROM events
            {where_sql}
            GROUP BY bucket
            ORDER BY bucket ASC;
        """

        buckets: List[TimeSeriesBucket] = []
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(sql, params)
            for row in cursor.fetchall():
                b_str = row["bucket"]
                if b_str:
                    buckets.append(TimeSeriesBucket(bucket=b_str, count=int(row["count"])))

        return buckets

    def get_summary_counts(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> EventSummaryResponse:
        filters = EventFilter(start_time=start_time, end_time=end_time)
        total = self.count_events(filters)
        where_sql, params = self._build_where_clause(filters)

        by_severity: Dict[str, int] = {}
        by_event_type: Dict[str, int] = {}
        by_source_host: Dict[str, int] = {}

        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            # Group by severity
            cursor.execute(f"SELECT severity, COUNT(*) as cnt FROM events {where_sql} GROUP BY severity;", params)
            for r in cursor.fetchall():
                by_severity[r["severity"]] = int(r["cnt"])

            # Group by event_type
            cursor.execute(f"SELECT event_type, COUNT(*) as cnt FROM events {where_sql} GROUP BY event_type;", params)
            for r in cursor.fetchall():
                by_event_type[r["event_type"]] = int(r["cnt"])

            # Group by source_host
            cursor.execute(f"SELECT source_host, COUNT(*) as cnt FROM events {where_sql} GROUP BY source_host;", params)
            for r in cursor.fetchall():
                by_source_host[r["source_host"]] = int(r["cnt"])

        # Also get hourly time-series buckets
        time_series = self.get_time_series_buckets(start_time, end_time, interval="hour")

        return EventSummaryResponse(
            total_events=total,
            by_severity=by_severity,
            by_event_type=by_event_type,
            by_source_host=by_source_host,
            time_series=time_series,
        )

    def check_health(self) -> bool:
        try:
            with self._lock:
                conn = self._get_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT 1;")
                row = cursor.fetchone()
                return bool(row and row[0] == 1)
        except Exception:
            return False

    def close(self) -> None:
        with self._lock:
            if self._conn:
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None
