"""SQLite persistence for cursor preparations."""

from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional, Sequence

from engineering_os.domain.models import dumps_json, loads_json, utc_now
from engineering_os.infrastructure.persistence.sqlite.connection import SqliteDatabase
from engineering_os.infrastructure.persistence.sqlite.errors import ConcurrencyError


class SqliteCursorPreparationRepository:
    def __init__(self, db: SqliteDatabase) -> None:
        self.db = db

    def insert_cursor_preparation(self, data: Dict[str, Any]) -> Dict[str, Any]:
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO cursor_preparations(
                  preparation_id, execution_id, project_id, task_id, cursor_version,
                  image_digest, agent_id, acp_session_id, sandbox_identity,
                  authorization_ref, network_policy_id, credential_provider_ref,
                  resource_ceilings_json, workspace_json, acpx_config_json,
                  blockers_json, status, mode, provenance, evidence_refs_json,
                  cleanup_status, failure_reason, correlation_id,
                  created_at, started_at, completed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["preparation_id"],
                    data["execution_id"],
                    data["project_id"],
                    data["task_id"],
                    data.get("cursor_version"),
                    data.get("image_digest"),
                    data["agent_id"],
                    data.get("acp_session_id"),
                    data.get("sandbox_identity"),
                    data.get("authorization_ref"),
                    data.get("network_policy_id"),
                    data.get("credential_provider_ref"),
                    dumps_json(data.get("resource_ceilings_json") or {}),
                    dumps_json(data.get("workspace_json") or {}),
                    dumps_json(data.get("acpx_config_json") or {}),
                    dumps_json(data.get("blockers_json") or []),
                    data["status"],
                    data["mode"],
                    data["provenance"],
                    dumps_json(data.get("evidence_refs") or []),
                    data.get("cleanup_status"),
                    data.get("failure_reason"),
                    data["correlation_id"],
                    data["created_at"],
                    data.get("started_at"),
                    data.get("completed_at"),
                ),
            )
        return self.get_cursor_preparation(data["preparation_id"])  # type: ignore[return-value]


    def update_cursor_preparation(self, data: Dict[str, Any]) -> Dict[str, Any]:
        with self.db.transaction() as conn:
            conn.execute(
                """
                UPDATE cursor_preparations SET
                  acp_session_id=?, blockers_json=?, status=?, mode=?, provenance=?,
                  evidence_refs_json=?, cleanup_status=?, failure_reason=?,
                  started_at=?, completed_at=?
                WHERE preparation_id=?
                """,
                (
                    data.get("acp_session_id"),
                    dumps_json(data.get("blockers_json") or []),
                    data["status"],
                    data["mode"],
                    data["provenance"],
                    dumps_json(data.get("evidence_refs") or []),
                    data.get("cleanup_status"),
                    data.get("failure_reason"),
                    data.get("started_at"),
                    data.get("completed_at"),
                    data["preparation_id"],
                ),
            )
        return self.get_cursor_preparation(data["preparation_id"])  # type: ignore[return-value]


    def get_cursor_preparation(self, preparation_id: str) -> Optional[Dict[str, Any]]:
        row = self.db.fetchone(
            "SELECT * FROM cursor_preparations WHERE preparation_id=?",
            (preparation_id,),
        )
        return self._row_cursor_preparation(row) if row else None


    def get_cursor_preparation_by_execution(
        self, execution_id: str
    ) -> Optional[Dict[str, Any]]:
        row = self.db.fetchone(
            "SELECT * FROM cursor_preparations WHERE execution_id=?",
            (execution_id,),
        )
        return self._row_cursor_preparation(row) if row else None


    def list_cursor_preparations(
        self, *, project_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        if project_id:
            rows = self.db.fetchall(
                """
                SELECT * FROM cursor_preparations
                WHERE project_id=? ORDER BY created_at ASC
                """,
                (project_id,),
            )
        else:
            rows = self.db.fetchall(
                "SELECT * FROM cursor_preparations ORDER BY created_at ASC"
            )
        return [self._row_cursor_preparation(r) for r in rows]


    def _row_cursor_preparation(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "preparation_id": row["preparation_id"],
            "execution_id": row["execution_id"],
            "project_id": row["project_id"],
            "task_id": row["task_id"],
            "cursor_version": row["cursor_version"],
            "image_digest": row["image_digest"],
            "agent_id": row["agent_id"],
            "acp_session_id": row["acp_session_id"],
            "sandbox_identity": row["sandbox_identity"],
            "authorization_ref": row["authorization_ref"],
            "network_policy_id": row["network_policy_id"],
            "credential_provider_ref": row["credential_provider_ref"],
            "resource_ceilings_json": dict(loads_json(row["resource_ceilings_json"]) or {}),
            "workspace_json": dict(loads_json(row["workspace_json"]) or {}),
            "acpx_config_json": dict(loads_json(row["acpx_config_json"]) or {}),
            "blockers_json": list(loads_json(row["blockers_json"]) or []),
            "status": row["status"],
            "mode": row["mode"],
            "provenance": row["provenance"],
            "evidence_refs": list(loads_json(row["evidence_refs_json"]) or []),
            "cleanup_status": row["cleanup_status"],
            "failure_reason": row["failure_reason"],
            "correlation_id": row["correlation_id"],
            "created_at": row["created_at"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
        }

