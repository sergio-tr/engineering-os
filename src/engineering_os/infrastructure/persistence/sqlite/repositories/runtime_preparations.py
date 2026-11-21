"""SQLite persistence for runtime preparations."""

from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional, Sequence

from engineering_os.domain.models import dumps_json, loads_json, utc_now
from engineering_os.infrastructure.persistence.sqlite.connection import SqliteDatabase
from engineering_os.infrastructure.persistence.sqlite.errors import ConcurrencyError


class SqliteRuntimePreparationRepository:
    def __init__(self, db: SqliteDatabase) -> None:
        self.db = db

    def insert_runtime_preparation(self, data: Dict[str, Any]) -> Dict[str, Any]:
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO runtime_preparations(
                  preparation_id, execution_id, project_id, task_id, spec_id,
                  spec_json, acpx_session_id, cursor_session_id, readiness_json,
                  authorization_state, image_digest, status, mode,
                  blocked_reasons_json, launch_plan_json, evidence_refs_json,
                  cleanup_status, failure_reason, correlation_id, provenance_json,
                  created_at, started_at, completed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["preparation_id"],
                    data["execution_id"],
                    data["project_id"],
                    data["task_id"],
                    data["spec_id"],
                    dumps_json(data.get("spec_json") or {}),
                    data.get("acpx_session_id"),
                    data.get("cursor_session_id"),
                    dumps_json(data.get("readiness_json") or {}),
                    data["authorization_state"],
                    data["image_digest"],
                    data["status"],
                    data["mode"],
                    dumps_json(data.get("blocked_reasons") or []),
                    dumps_json(data.get("launch_plan_json") or {}),
                    dumps_json(data.get("evidence_refs") or []),
                    data.get("cleanup_status"),
                    data.get("failure_reason"),
                    data["correlation_id"],
                    dumps_json(data.get("provenance") or {}),
                    data["created_at"],
                    data.get("started_at"),
                    data.get("completed_at"),
                ),
            )
        return self.get_runtime_preparation(data["preparation_id"])  # type: ignore[return-value]


    def update_runtime_preparation(self, data: Dict[str, Any]) -> Dict[str, Any]:
        with self.db.transaction() as conn:
            conn.execute(
                """
                UPDATE runtime_preparations SET
                  acpx_session_id=?, cursor_session_id=?, readiness_json=?,
                  authorization_state=?, status=?, mode=?, blocked_reasons_json=?,
                  launch_plan_json=?, evidence_refs_json=?, cleanup_status=?,
                  failure_reason=?, provenance_json=?, started_at=?, completed_at=?
                WHERE preparation_id=?
                """,
                (
                    data.get("acpx_session_id"),
                    data.get("cursor_session_id"),
                    dumps_json(data.get("readiness_json") or {}),
                    data["authorization_state"],
                    data["status"],
                    data["mode"],
                    dumps_json(data.get("blocked_reasons") or []),
                    dumps_json(data.get("launch_plan_json") or {}),
                    dumps_json(data.get("evidence_refs") or []),
                    data.get("cleanup_status"),
                    data.get("failure_reason"),
                    dumps_json(data.get("provenance") or {}),
                    data.get("started_at"),
                    data.get("completed_at"),
                    data["preparation_id"],
                ),
            )
        return self.get_runtime_preparation(data["preparation_id"])  # type: ignore[return-value]


    def get_runtime_preparation(self, preparation_id: str) -> Optional[Dict[str, Any]]:
        row = self.db.fetchone(
            "SELECT * FROM runtime_preparations WHERE preparation_id=?",
            (preparation_id,),
        )
        return self._row_runtime_preparation(row) if row else None


    def get_runtime_preparation_by_execution(
        self, execution_id: str
    ) -> Optional[Dict[str, Any]]:
        row = self.db.fetchone(
            "SELECT * FROM runtime_preparations WHERE execution_id=?",
            (execution_id,),
        )
        return self._row_runtime_preparation(row) if row else None


    def list_runtime_preparations(
        self, *, project_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        if project_id:
            rows = self.db.fetchall(
                """
                SELECT * FROM runtime_preparations
                WHERE project_id=? ORDER BY created_at ASC
                """,
                (project_id,),
            )
        else:
            rows = self.db.fetchall(
                "SELECT * FROM runtime_preparations ORDER BY created_at ASC"
            )
        return [self._row_runtime_preparation(r) for r in rows]


    def _row_runtime_preparation(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "preparation_id": row["preparation_id"],
            "execution_id": row["execution_id"],
            "project_id": row["project_id"],
            "task_id": row["task_id"],
            "spec_id": row["spec_id"],
            "spec_json": dict(loads_json(row["spec_json"]) or {}),
            "acpx_session_id": row["acpx_session_id"],
            "cursor_session_id": row["cursor_session_id"],
            "readiness_json": dict(loads_json(row["readiness_json"]) or {}),
            "authorization_state": row["authorization_state"],
            "image_digest": row["image_digest"],
            "status": row["status"],
            "mode": row["mode"],
            "blocked_reasons": list(loads_json(row["blocked_reasons_json"]) or []),
            "launch_plan_json": dict(loads_json(row["launch_plan_json"]) or {}),
            "evidence_refs": list(loads_json(row["evidence_refs_json"]) or []),
            "cleanup_status": row["cleanup_status"],
            "failure_reason": row["failure_reason"],
            "correlation_id": row["correlation_id"],
            "provenance": dict(loads_json(row["provenance_json"]) or {}),
            "created_at": row["created_at"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
        }

