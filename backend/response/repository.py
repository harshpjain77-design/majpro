"""Persistent repository and forensic audit logger for response actions."""

import json
import os
import sqlite3
import threading
from typing import List, Optional, Tuple
from backend.response.schemas import (
    ActionPriority,
    ActionStatus,
    ActionType,
    ResponseActionRecord,
)


class SQLiteResponseRepository:
    """Stores response action records in SQLite and maintains an append-only audit log."""

    def __init__(self, db_path: str = "output/soc_events.sqlite", audit_log_path: str = "output/response_audit.jsonl"):
        self.db_path = db_path
        self.audit_log_path = audit_log_path
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None

        # Ensure directory exists if file-backed
        if db_path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        if audit_log_path:
            os.makedirs(os.path.dirname(os.path.abspath(audit_log_path)), exist_ok=True)

        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                timeout=30.0,
            )
            self._conn.row_factory = sqlite3.Row
            if self.db_path != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL;")
                self._conn.execute("PRAGMA synchronous=NORMAL;")
        return self._conn

    def _init_db(self) -> None:
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS response_actions (
                        action_id TEXT PRIMARY KEY,
                        incident_id TEXT NOT NULL,
                        action_type TEXT NOT NULL,
                        target TEXT NOT NULL,
                        parameters_json TEXT NOT NULL,
                        priority TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        status TEXT NOT NULL,
                        dry_run INTEGER NOT NULL,
                        requires_approval INTEGER NOT NULL,
                        requested_by TEXT NOT NULL,
                        approved_by TEXT,
                        approved_at TEXT,
                        executed_at TEXT,
                        execution_output_json TEXT,
                        rollback_data_json TEXT,
                        rolled_back_at TEXT,
                        created_at TEXT NOT NULL,
                        error_message TEXT
                    );
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_resp_incident ON response_actions(incident_id);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_resp_status ON response_actions(status);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_resp_target ON response_actions(target);")
                conn.commit()

    def save_action(self, action: ResponseActionRecord) -> None:
        """Insert or replace a response action record and append to forensic audit trail."""
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO response_actions (
                        action_id, incident_id, action_type, target, parameters_json,
                        priority, reason, status, dry_run, requires_approval, requested_by,
                        approved_by, approved_at, executed_at, execution_output_json,
                        rollback_data_json, rolled_back_at, created_at, error_message
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    action.action_id,
                    action.incident_id,
                    action.action_type.value,
                    action.target,
                    json.dumps(action.parameters),
                    action.priority.value,
                    action.reason,
                    action.status.value,
                    1 if action.dry_run else 0,
                    1 if action.requires_approval else 0,
                    action.requested_by,
                    action.approved_by,
                    action.approved_at,
                    action.executed_at,
                    json.dumps(action.execution_output) if action.execution_output else None,
                    json.dumps(action.rollback_data) if action.rollback_data else None,
                    action.rolled_back_at,
                    action.created_at,
                    action.error_message,
                ))
                conn.commit()

            # Append to immutable audit log file
            self._append_audit_log(action)

    def _append_audit_log(self, action: ResponseActionRecord) -> None:
        if not self.audit_log_path:
            return
        try:
            audit_entry = {
                "action_id": action.action_id,
                "incident_id": action.incident_id,
                "action_type": action.action_type.value,
                "target": action.target,
                "status": action.status.value,
                "dry_run": action.dry_run,
                "requires_approval": action.requires_approval,
                "approved_by": action.approved_by,
                "executed_at": action.executed_at,
                "rolled_back_at": action.rolled_back_at,
                "reason": action.reason,
            }
            with open(self.audit_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(audit_entry) + "\n")
        except Exception:
            # Audit log writing should never crash the main operation
            pass

    def get_action(self, action_id: str) -> Optional[ResponseActionRecord]:
        """Retrieve a response action record by ID."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "SELECT * FROM response_actions WHERE action_id = ?",
                    (action_id,)
                )
                row = cursor.fetchone()
                if not row:
                    return None
                return self._row_to_record(row)

    def list_actions(
        self,
        incident_id: Optional[str] = None,
        status: Optional[ActionStatus] = None,
        limit: int = 50,
        offset: int = 0
    ) -> Tuple[int, List[ResponseActionRecord]]:
        """List response actions with optional incident and status filters."""
        query = "SELECT * FROM response_actions WHERE 1=1"
        count_query = "SELECT COUNT(*) FROM response_actions WHERE 1=1"
        params: List[object] = []

        if incident_id:
            query += " AND incident_id = ?"
            count_query += " AND incident_id = ?"
            params.append(incident_id)

        if status:
            query += " AND status = ?"
            count_query += " AND status = ?"
            params.append(status.value)

        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        exec_params = list(params) + [limit, offset]

        with self._lock:
            with self._get_connection() as conn:
                count_cursor = conn.execute(count_query, params)
                total = count_cursor.fetchone()[0]

                cursor = conn.execute(query, exec_params)
                records = [self._row_to_record(r) for r in cursor.fetchall()]
                return total, records

    def _row_to_record(self, row: sqlite3.Row) -> ResponseActionRecord:
        return ResponseActionRecord(
            action_id=row["action_id"],
            incident_id=row["incident_id"],
            action_type=ActionType(row["action_type"]),
            target=row["target"],
            parameters=json.loads(row["parameters_json"]) if row["parameters_json"] else {},
            priority=ActionPriority(row["priority"]),
            reason=row["reason"],
            status=ActionStatus(row["status"]),
            dry_run=bool(row["dry_run"]),
            requires_approval=bool(row["requires_approval"]),
            requested_by=row["requested_by"],
            approved_by=row["approved_by"],
            approved_at=row["approved_at"],
            executed_at=row["executed_at"],
            execution_output=json.loads(row["execution_output_json"]) if row["execution_output_json"] else None,
            rollback_data=json.loads(row["rollback_data_json"]) if row["rollback_data_json"] else None,
            rolled_back_at=row["rolled_back_at"],
            created_at=row["created_at"],
            error_message=row["error_message"],
        )
