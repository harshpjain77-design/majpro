"""Persistent SQLite repository for incident management, timeline tracking, and notes."""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Tuple, Union

from backend.correlation.config import CorrelationConfig, default_correlation_config
from backend.correlation.correlator import IncidentCorrelator
from backend.correlation.deduplicator import AlertDeduplicator
from backend.correlation.schemas import (
    AnalystNote,
    DeduplicatedAlert,
    DeduplicationMetrics,
    Incident,
    IncidentStatus,
    TimelineEntry,
)
from backend.detection.schemas import Alert
from backend.storage.base import EventRepository

logger = logging.getLogger("IncidentRepository")


class IncidentRepository:
    """Manages persistent SQLite storage of correlated incidents, timeline entries, and analyst notes."""

    def __init__(
        self,
        db_path: str = "output/soc_events.sqlite",
        config: Optional[CorrelationConfig] = None,
    ):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.config = config or default_correlation_config
        self.deduplicator = AlertDeduplicator(config=self.config)
        self.correlator = IncidentCorrelator(config=self.config)
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
            self._conn.execute("PRAGMA journal_mode = WAL;")
            self._conn.execute("PRAGMA synchronous = NORMAL;")
            self._conn.execute("PRAGMA busy_timeout = 30000;")
        return self._conn

    def close(self) -> None:
        """Close SQLite database connection if open."""
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def _init_db(self) -> None:
        with self._lock:
            conn = self._get_connection()
            with conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS incidents (
                        incident_id TEXT PRIMARY KEY,
                        title TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        status TEXT NOT NULL,
                        risk_score REAL NOT NULL,
                        first_seen TEXT NOT NULL,
                        last_seen TEXT NOT NULL,
                        entities_json TEXT NOT NULL,
                        distinct_rules_json TEXT NOT NULL,
                        related_alert_ids_json TEXT NOT NULL,
                        related_event_ids_json TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS incident_timeline (
                        entry_id TEXT PRIMARY KEY,
                        incident_id TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        entry_type TEXT NOT NULL,
                        description TEXT NOT NULL,
                        source_id TEXT,
                        severity TEXT NOT NULL,
                        entities_json TEXT NOT NULL
                    );
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS incident_notes (
                        note_id TEXT PRIMARY KEY,
                        incident_id TEXT NOT NULL,
                        author TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        content TEXT NOT NULL
                    );
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_risk_score ON incidents(risk_score);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_first_seen ON incidents(first_seen);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_timeline_incident_id ON incident_timeline(incident_id);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_notes_incident_id ON incident_notes(incident_id);")

    def save_incident(self, incident: Incident) -> None:
        """Persist or update an incident, including timeline entries and notes."""
        with self._lock:
            conn = self._get_connection()
            with conn:
                conn.execute(
                    """
                    INSERT INTO incidents (
                        incident_id, title, severity, status, risk_score, first_seen, last_seen,
                        entities_json, distinct_rules_json, related_alert_ids_json, related_event_ids_json,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(incident_id) DO UPDATE SET
                        title=excluded.title,
                        severity=excluded.severity,
                        status=excluded.status,
                        risk_score=excluded.risk_score,
                        first_seen=excluded.first_seen,
                        last_seen=excluded.last_seen,
                        entities_json=excluded.entities_json,
                        distinct_rules_json=excluded.distinct_rules_json,
                        related_alert_ids_json=excluded.related_alert_ids_json,
                        related_event_ids_json=excluded.related_event_ids_json,
                        updated_at=excluded.updated_at;
                    """,
                    (
                        incident.incident_id,
                        incident.title,
                        incident.severity,
                        incident.status.value,
                        incident.risk_score,
                        incident.first_seen,
                        incident.last_seen,
                        json.dumps(incident.entities),
                        json.dumps(incident.distinct_rules),
                        json.dumps(incident.related_alert_ids),
                        json.dumps(incident.related_event_ids),
                        incident.created_at,
                        incident.updated_at,
                    ),
                )

                # Persist timeline entries
                for entry in incident.timeline:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO incident_timeline (
                            entry_id, incident_id, timestamp, entry_type, description,
                            source_id, severity, entities_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            entry.entry_id,
                            incident.incident_id,
                            entry.timestamp,
                            entry.entry_type,
                            entry.description,
                            entry.source_id,
                            entry.severity,
                            json.dumps(entry.entities),
                        ),
                    )

                # Persist notes
                for note in incident.analyst_notes:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO incident_notes (
                            note_id, incident_id, author, created_at, content
                        ) VALUES (?, ?, ?, ?, ?);
                        """,
                        (
                            note.note_id,
                            incident.incident_id,
                            note.author,
                            note.created_at,
                            note.content,
                        ),
                    )

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Retrieve complete incident by ID including all timeline entries and notes."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT incident_id, title, severity, status, risk_score, first_seen, last_seen,
                       entities_json, distinct_rules_json, related_alert_ids_json, related_event_ids_json,
                       created_at, updated_at
                FROM incidents
                WHERE incident_id = ?;
                """,
                (incident_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None

            # Fetch timeline
            cursor.execute(
                """
                SELECT entry_id, timestamp, entry_type, description, source_id, severity, entities_json
                FROM incident_timeline
                WHERE incident_id = ?
                ORDER BY timestamp ASC;
                """,
                (incident_id,),
            )
            timeline_rows = cursor.fetchall()
            timeline = [
                TimelineEntry(
                    entry_id=tr["entry_id"],
                    timestamp=tr["timestamp"],
                    entry_type=tr["entry_type"],
                    description=tr["description"],
                    source_id=tr["source_id"],
                    severity=tr["severity"],
                    entities=json.loads(tr["entities_json"]) if tr["entities_json"] else {},
                )
                for tr in timeline_rows
            ]

            # Fetch notes
            cursor.execute(
                """
                SELECT note_id, author, created_at, content
                FROM incident_notes
                WHERE incident_id = ?
                ORDER BY created_at ASC;
                """,
                (incident_id,),
            )
            note_rows = cursor.fetchall()
            notes = [
                AnalystNote(
                    note_id=nr["note_id"],
                    author=nr["author"],
                    created_at=nr["created_at"],
                    content=nr["content"],
                )
                for nr in note_rows
            ]

            return Incident(
                incident_id=row["incident_id"],
                title=row["title"],
                severity=row["severity"],
                status=IncidentStatus(row["status"]),
                risk_score=row["risk_score"],
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
                entities=json.loads(row["entities_json"]),
                distinct_rules=json.loads(row["distinct_rules_json"]),
                related_alert_ids=json.loads(row["related_alert_ids_json"]),
                related_event_ids=json.loads(row["related_event_ids_json"]),
                timeline=timeline,
                analyst_notes=notes,
                created_at=row["created_at"],
                updated_at=row["updated_at"],
            )

    def list_incidents(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Incident], int]:
        """List incidents matching filters, ordered by risk score descending."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            conditions: List[str] = []
            params: List[Any] = []

            if status:
                conditions.append("status = ?")
                params.append(status.upper())
            if severity:
                conditions.append("severity = ?")
                params.append(severity.lower())
            if start_time:
                conditions.append("last_seen >= ?")
                params.append(start_time)
            if end_time:
                conditions.append("first_seen <= ?")
                params.append(end_time)

            where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

            # Count total
            count_query = f"SELECT COUNT(*) FROM incidents {where_clause};"
            cursor.execute(count_query, params)
            total = cursor.fetchone()[0]

            # Fetch page
            fetch_query = f"""
                SELECT incident_id, title, severity, status, risk_score, first_seen, last_seen,
                       entities_json, distinct_rules_json, related_alert_ids_json, related_event_ids_json,
                       created_at, updated_at
                FROM incidents
                {where_clause}
                ORDER BY risk_score DESC, last_seen DESC
                LIMIT ? OFFSET ?;
            """
            cursor.execute(fetch_query, params + [limit, offset])
            rows = cursor.fetchall()

            incidents: List[Incident] = []
            for row in rows:
                incidents.append(
                    Incident(
                        incident_id=row["incident_id"],
                        title=row["title"],
                        severity=row["severity"],
                        status=IncidentStatus(row["status"]),
                        risk_score=row["risk_score"],
                        first_seen=row["first_seen"],
                        last_seen=row["last_seen"],
                        entities=json.loads(row["entities_json"]),
                        distinct_rules=json.loads(row["distinct_rules_json"]),
                        related_alert_ids=json.loads(row["related_alert_ids_json"]),
                        related_event_ids=json.loads(row["related_event_ids_json"]),
                        timeline=[],  # Omit sub-timeline in listing for performance
                        analyst_notes=[],
                        created_at=row["created_at"],
                        updated_at=row["updated_at"],
                    )
                )

            return incidents, total

    def update_status(
        self,
        incident_id: str,
        new_status: IncidentStatus,
        analyst: str = "analyst",
    ) -> Incident:
        """Validate and apply a lifecycle status transition on an incident."""
        incident = self.get_incident(incident_id)
        if not incident:
            raise KeyError(f"Incident with ID '{incident_id}' not found.")

        incident.transition_to(new_status, analyst=analyst)
        self.save_incident(incident)
        return incident

    def add_note(
        self,
        incident_id: str,
        author: str,
        content: str,
    ) -> AnalystNote:
        """Attach an analyst note to an incident."""
        incident = self.get_incident(incident_id)
        if not incident:
            raise KeyError(f"Incident with ID '{incident_id}' not found.")

        note = incident.add_note(author=author, content=content)
        self.save_incident(incident)
        return note

    def correlate_and_persist(
        self,
        alerts: List[Alert],
        event_repo: Optional[EventRepository] = None,
    ) -> List[Incident]:
        """Deduplicate raw alerts, cluster into correlated incidents, and persist them."""
        if not alerts:
            return []

        # 1. Deduplicate alerts
        deduplicated = self.deduplicator.deduplicate_batch(alerts)

        # 2. Correlate into incidents
        incidents = self.correlator.correlate_alerts(deduplicated, repo=event_repo)

        # 3. Persist incidents
        for inc in incidents:
            self.save_incident(inc)

        self.deduplicator.total_incidents_created += len(incidents)
        return incidents

    def get_deduplication_metrics(self) -> DeduplicationMetrics:
        """Return operational alert reduction metrics."""
        return self.deduplicator.get_metrics()
