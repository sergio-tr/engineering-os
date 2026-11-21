"""SQLite persistence for oci fixture runs."""

from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional, Sequence

from engineering_os.domain.models import dumps_json, loads_json, utc_now
from engineering_os.infrastructure.persistence.sqlite.connection import SqliteDatabase
from engineering_os.infrastructure.persistence.sqlite.errors import ConcurrencyError


class SqliteOciFixtureRunRepository:
    def __init__(self, db: SqliteDatabase) -> None:
        self.db = db

    def insert_oci_fixture_run(self, data: Dict[str, Any]) -> Dict[str, Any]:
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO oci_fixture_runs(
                  run_id, execution_id, project_id, task_id, acp_session_id,
                  container_id, code_revision, image_ref, image_digest,
                  applied_limits_json, runtime_controls_json, exit_code,
                  timeout_or_cancel, exchange_summary_json, host_observations_json,
                  cleanup_status, evidence_refs_json, evidence_hashes_json,
                  provenance, status, failure_reason, correlation_id,
                  created_at, started_at, completed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["run_id"],
                    data["execution_id"],
                    data["project_id"],
                    data["task_id"],
                    data.get("acp_session_id"),
                    data.get("container_id"),
                    data["code_revision"],
                    data["image_ref"],
                    data.get("image_digest"),
                    dumps_json(data.get("applied_limits") or {}),
                    dumps_json(data.get("runtime_controls") or {}),
                    data.get("exit_code"),
                    data.get("timeout_or_cancel"),
                    dumps_json(data.get("exchange_summary") or {}),
                    dumps_json(data.get("host_observations") or {}),
                    data.get("cleanup_status"),
                    dumps_json(data.get("evidence_refs") or []),
                    dumps_json(data.get("evidence_hashes") or {}),
                    data["provenance"],
                    data["status"],
                    data.get("failure_reason"),
                    data["correlation_id"],
                    data["created_at"],
                    data.get("started_at"),
                    data.get("completed_at"),
                ),
            )
        return self.get_oci_fixture_run(data["run_id"])  # type: ignore[return-value]


    def update_oci_fixture_run(self, data: Dict[str, Any]) -> Dict[str, Any]:
        with self.db.transaction() as conn:
            conn.execute(
                """
                UPDATE oci_fixture_runs SET
                  acp_session_id=?, container_id=?, exit_code=?, timeout_or_cancel=?,
                  exchange_summary_json=?, host_observations_json=?, cleanup_status=?,
                  evidence_refs_json=?, evidence_hashes_json=?, status=?,
                  failure_reason=?, started_at=?, completed_at=?
                WHERE run_id=?
                """,
                (
                    data.get("acp_session_id"),
                    data.get("container_id"),
                    data.get("exit_code"),
                    data.get("timeout_or_cancel"),
                    dumps_json(data.get("exchange_summary") or {}),
                    dumps_json(data.get("host_observations") or {}),
                    data.get("cleanup_status"),
                    dumps_json(data.get("evidence_refs") or []),
                    dumps_json(data.get("evidence_hashes") or {}),
                    data["status"],
                    data.get("failure_reason"),
                    data.get("started_at"),
                    data.get("completed_at"),
                    data["run_id"],
                ),
            )
        return self.get_oci_fixture_run(data["run_id"])  # type: ignore[return-value]


    def get_oci_fixture_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        row = self.db.fetchone(
            "SELECT * FROM oci_fixture_runs WHERE run_id=?", (run_id,)
        )
        return self._row_oci_fixture_run(row) if row else None


    def get_oci_fixture_run_by_execution(
        self, execution_id: str
    ) -> Optional[Dict[str, Any]]:
        row = self.db.fetchone(
            """
            SELECT * FROM oci_fixture_runs WHERE execution_id=?
            ORDER BY created_at DESC LIMIT 1
            """,
            (execution_id,),
        )
        return self._row_oci_fixture_run(row) if row else None


    def list_oci_fixture_runs(
        self, *, project_id: Optional[str] = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        if project_id:
            rows = self.db.fetchall(
                """
                SELECT * FROM oci_fixture_runs
                WHERE project_id=? ORDER BY created_at DESC LIMIT ?
                """,
                (project_id, int(limit)),
            )
        else:
            rows = self.db.fetchall(
                "SELECT * FROM oci_fixture_runs ORDER BY created_at DESC LIMIT ?",
                (int(limit),),
            )
        return [self._row_oci_fixture_run(r) for r in rows]


    def _row_oci_fixture_run(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "run_id": row["run_id"],
            "execution_id": row["execution_id"],
            "project_id": row["project_id"],
            "task_id": row["task_id"],
            "acp_session_id": row["acp_session_id"],
            "container_id": row["container_id"],
            "code_revision": row["code_revision"],
            "image_ref": row["image_ref"],
            "image_digest": row["image_digest"],
            "applied_limits": dict(loads_json(row["applied_limits_json"]) or {}),
            "runtime_controls": dict(loads_json(row["runtime_controls_json"]) or {}),
            "exit_code": row["exit_code"],
            "timeout_or_cancel": row["timeout_or_cancel"],
            "exchange_summary": dict(loads_json(row["exchange_summary_json"]) or {}),
            "host_observations": dict(loads_json(row["host_observations_json"]) or {}),
            "cleanup_status": row["cleanup_status"],
            "evidence_refs": list(loads_json(row["evidence_refs_json"]) or []),
            "evidence_hashes": dict(loads_json(row["evidence_hashes_json"]) or {}),
            "provenance": row["provenance"],
            "status": row["status"],
            "failure_reason": row["failure_reason"],
            "correlation_id": row["correlation_id"],
            "created_at": row["created_at"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
        }

