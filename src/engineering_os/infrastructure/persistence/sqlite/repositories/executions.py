"""SQLite persistence for executions."""

from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional, Sequence

from engineering_os.domain.models import dumps_json, loads_json, utc_now
from engineering_os.infrastructure.persistence.sqlite.connection import SqliteDatabase
from engineering_os.infrastructure.persistence.sqlite.errors import ConcurrencyError
from engineering_os.domain.models import Execution


class SqliteExecutionRepository:
    def __init__(self, db: SqliteDatabase) -> None:
        self.db = db

    def insert_execution(self, execution: Execution) -> Execution:
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO executions(
                  execution_id, task_id, project_id, execution_contract_ref,
                  runner_type, attempt_number, status, failure_reason,
                  evidence_refs_json, idempotency_key, started_at, ended_at,
                  created_at, updated_at, version, integration_state, synthetic
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    execution.execution_id,
                    execution.task_id,
                    execution.project_id,
                    execution.execution_contract_ref,
                    execution.runner_type,
                    execution.attempt_number,
                    execution.status,
                    execution.failure_reason,
                    dumps_json(execution.evidence_refs),
                    execution.idempotency_key,
                    execution.started_at,
                    execution.ended_at,
                    execution.created_at,
                    execution.updated_at,
                    execution.version,
                    execution.integration_state,
                    1 if execution.synthetic else 0,
                ),
            )
        return execution


    def update_execution(self, execution: Execution, *, expected_version: int) -> Execution:
        execution.updated_at = utc_now()
        with self.db.transaction() as conn:
            cur = conn.execute(
                """
                UPDATE executions SET
                  status=?, failure_reason=?, evidence_refs_json=?,
                  started_at=?, ended_at=?, updated_at=?, version=version+1,
                  integration_state=?, runner_type=?
                WHERE execution_id=? AND version=?
                """,
                (
                    execution.status,
                    execution.failure_reason,
                    dumps_json(execution.evidence_refs),
                    execution.started_at,
                    execution.ended_at,
                    execution.updated_at,
                    execution.integration_state,
                    execution.runner_type,
                    execution.execution_id,
                    expected_version,
                ),
            )
            if cur.rowcount != 1:
                raise ConcurrencyError(
                    f"execution version conflict: {execution.execution_id}"
                )
        refreshed = self.get_execution(execution.execution_id)
        assert refreshed is not None
        return refreshed


    def get_execution(self, execution_id: str) -> Optional[Execution]:
        row = self.db.fetchone("SELECT * FROM executions WHERE execution_id = ?", (execution_id,))
        return self._row_execution(row) if row else None


    def get_execution_by_idempotency(self, key: str) -> Optional[Execution]:
        row = self.db.fetchone("SELECT * FROM executions WHERE idempotency_key = ?", (key,))
        return self._row_execution(row) if row else None


    def list_executions(
        self, *, project_id: Optional[str] = None, task_id: Optional[str] = None
    ) -> List[Execution]:
        clauses: List[str] = []
        params: List[Any] = []
        if project_id:
            clauses.append("project_id = ?")
            params.append(project_id)
        if task_id:
            clauses.append("task_id = ?")
            params.append(task_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self.db.fetchall(
            f"SELECT * FROM executions {where} ORDER BY created_at ASC", params
        )
        return [self._row_execution(r) for r in rows]


    def next_attempt_number(self, task_id: str) -> int:
        row = self.db.fetchone(
            "SELECT COALESCE(MAX(attempt_number), 0) AS m FROM executions WHERE task_id=?",
            (task_id,),
        )
        return int(row["m"]) + 1


    def _row_execution(self, row: sqlite3.Row) -> Execution:
        return Execution(
            execution_id=row["execution_id"],
            task_id=row["task_id"],
            project_id=row["project_id"],
            execution_contract_ref=row["execution_contract_ref"],
            runner_type=row["runner_type"],
            attempt_number=row["attempt_number"],
            status=row["status"],
            failure_reason=row["failure_reason"],
            evidence_refs=list(loads_json(row["evidence_refs_json"]) or []),
            idempotency_key=row["idempotency_key"],
            started_at=row["started_at"],
            ended_at=row["ended_at"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            version=row["version"],
            integration_state=row["integration_state"],
            synthetic=bool(row["synthetic"]),
        )

