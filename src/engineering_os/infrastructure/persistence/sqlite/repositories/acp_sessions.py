"""SQLite persistence for acp sessions."""

from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional, Sequence

from engineering_os.domain.models import dumps_json, loads_json, utc_now
from engineering_os.infrastructure.persistence.sqlite.connection import SqliteDatabase
from engineering_os.infrastructure.persistence.sqlite.errors import ConcurrencyError


class SqliteAcpSessionRepository:
    def __init__(self, db: SqliteDatabase) -> None:
        self.db = db

    def insert_acp_session(self, data: Dict[str, Any]) -> Dict[str, Any]:
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO acp_sessions(
                  session_id, execution_id, project_id, task_id, agent_id,
                  acp_backend, transport_type, protocol_version, status,
                  correlation_id, last_event_sequence, cancellation_state,
                  failure_reason, evidence_refs_json, runtime_provenance_json,
                  created_at, started_at, completed_at, last_activity_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["session_id"],
                    data["execution_id"],
                    data["project_id"],
                    data["task_id"],
                    data["agent_id"],
                    data["acp_backend"],
                    data["transport_type"],
                    int(data["protocol_version"]),
                    data["status"],
                    data["correlation_id"],
                    int(data.get("last_event_sequence") or 0),
                    data.get("cancellation_state"),
                    data.get("failure_reason"),
                    dumps_json(data.get("evidence_refs") or []),
                    dumps_json(data.get("runtime_provenance") or {}),
                    data["created_at"],
                    data.get("started_at"),
                    data.get("completed_at"),
                    data["last_activity_at"],
                ),
            )
        return self.get_acp_session(data["session_id"])  # type: ignore[return-value]


    def update_acp_session(self, data: Dict[str, Any]) -> Dict[str, Any]:
        with self.db.transaction() as conn:
            conn.execute(
                """
                UPDATE acp_sessions SET
                  status=?, protocol_version=?, last_event_sequence=?,
                  cancellation_state=?, failure_reason=?, evidence_refs_json=?,
                  runtime_provenance_json=?, started_at=?, completed_at=?,
                  last_activity_at=?
                WHERE session_id=?
                """,
                (
                    data["status"],
                    int(data["protocol_version"]),
                    int(data.get("last_event_sequence") or 0),
                    data.get("cancellation_state"),
                    data.get("failure_reason"),
                    dumps_json(data.get("evidence_refs") or []),
                    dumps_json(data.get("runtime_provenance") or {}),
                    data.get("started_at"),
                    data.get("completed_at"),
                    data.get("last_activity_at") or utc_now(),
                    data["session_id"],
                ),
            )
        return self.get_acp_session(data["session_id"])  # type: ignore[return-value]


    def get_acp_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        row = self.db.fetchone(
            "SELECT * FROM acp_sessions WHERE session_id=?", (session_id,)
        )
        return self._row_acp_session(row) if row else None


    def get_acp_session_by_execution(self, execution_id: str) -> Optional[Dict[str, Any]]:
        row = self.db.fetchone(
            "SELECT * FROM acp_sessions WHERE execution_id=?", (execution_id,)
        )
        return self._row_acp_session(row) if row else None


    def list_acp_sessions(
        self, *, project_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        if project_id:
            rows = self.db.fetchall(
                "SELECT * FROM acp_sessions WHERE project_id=? ORDER BY created_at ASC",
                (project_id,),
            )
        else:
            rows = self.db.fetchall("SELECT * FROM acp_sessions ORDER BY created_at ASC")
        return [self._row_acp_session(r) for r in rows]


    def append_acp_event(self, data: Dict[str, Any]) -> Dict[str, Any]:
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO acp_session_events(
                  event_id, session_id, execution_id, sequence, event_type,
                  dedupe_key, payload_json, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["event_id"],
                    data["session_id"],
                    data["execution_id"],
                    int(data["sequence"]),
                    data["event_type"],
                    data["dedupe_key"],
                    dumps_json(data.get("payload") or {}),
                    data["timestamp"],
                ),
            )
        return {
            "event_id": data["event_id"],
            "session_id": data["session_id"],
            "execution_id": data["execution_id"],
            "sequence": data["sequence"],
            "event_type": data["event_type"],
            "dedupe_key": data["dedupe_key"],
            "payload": data.get("payload") or {},
            "timestamp": data["timestamp"],
        }


    def acp_event_exists(self, session_id: str, dedupe_key: str) -> bool:
        row = self.db.fetchone(
            "SELECT 1 AS ok FROM acp_session_events WHERE session_id=? AND dedupe_key=?",
            (session_id, dedupe_key),
        )
        return row is not None


    def list_acp_events(self, session_id: str) -> List[Dict[str, Any]]:
        rows = self.db.fetchall(
            """
            SELECT * FROM acp_session_events
            WHERE session_id=? ORDER BY sequence ASC
            """,
            (session_id,),
        )
        return [
            {
                "event_id": r["event_id"],
                "session_id": r["session_id"],
                "execution_id": r["execution_id"],
                "sequence": r["sequence"],
                "event_type": r["event_type"],
                "dedupe_key": r["dedupe_key"],
                "payload": dict(loads_json(r["payload_json"]) or {}),
                "timestamp": r["timestamp"],
            }
            for r in rows
        ]


    def _row_acp_session(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "session_id": row["session_id"],
            "execution_id": row["execution_id"],
            "project_id": row["project_id"],
            "task_id": row["task_id"],
            "agent_id": row["agent_id"],
            "acp_backend": row["acp_backend"],
            "transport_type": row["transport_type"],
            "protocol_version": row["protocol_version"],
            "status": row["status"],
            "correlation_id": row["correlation_id"],
            "last_event_sequence": row["last_event_sequence"],
            "cancellation_state": row["cancellation_state"],
            "failure_reason": row["failure_reason"],
            "evidence_refs": list(loads_json(row["evidence_refs_json"]) or []),
            "runtime_provenance": dict(loads_json(row["runtime_provenance_json"]) or {}),
            "created_at": row["created_at"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "last_activity_at": row["last_activity_at"],
        }

