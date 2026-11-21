"""SQLite persistence for tasks."""

from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional, Sequence

from engineering_os.domain.models import dumps_json, loads_json, utc_now
from engineering_os.infrastructure.persistence.sqlite.connection import SqliteDatabase
from engineering_os.infrastructure.persistence.sqlite.errors import ConcurrencyError
from engineering_os.domain.models import Task


class SqliteTaskRepository:
    def __init__(self, db: SqliteDatabase) -> None:
        self.db = db

    def insert_task(self, task: Task) -> Task:
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO tasks(
                  task_id, goal_id, project_id, description, depends_on_json,
                  assigned_agent_ref, execution_eligible, lifecycle_state,
                  blocked_reason, created_at, updated_at, version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task.task_id,
                    task.goal_id,
                    task.project_id,
                    task.description,
                    dumps_json(task.depends_on),
                    task.assigned_agent_ref,
                    1 if task.execution_eligible else 0,
                    task.lifecycle_state,
                    task.blocked_reason,
                    task.created_at,
                    task.updated_at,
                    task.version,
                ),
            )
        return task


    def update_task(self, task: Task, *, expected_version: int) -> Task:
        task.updated_at = utc_now()
        with self.db.transaction() as conn:
            cur = conn.execute(
                """
                UPDATE tasks SET
                  description=?, depends_on_json=?, assigned_agent_ref=?,
                  execution_eligible=?, lifecycle_state=?, blocked_reason=?,
                  updated_at=?, version=version+1
                WHERE task_id=? AND version=?
                """,
                (
                    task.description,
                    dumps_json(task.depends_on),
                    task.assigned_agent_ref,
                    1 if task.execution_eligible else 0,
                    task.lifecycle_state,
                    task.blocked_reason,
                    task.updated_at,
                    task.task_id,
                    expected_version,
                ),
            )
            if cur.rowcount != 1:
                raise ConcurrencyError(f"task version conflict: {task.task_id}")
        refreshed = self.get_task(task.task_id)
        assert refreshed is not None
        return refreshed


    def get_task(self, task_id: str) -> Optional[Task]:
        row = self.db.fetchone("SELECT * FROM tasks WHERE task_id = ?", (task_id,))
        return self._row_task(row) if row else None


    def list_tasks(
        self,
        *,
        project_id: Optional[str] = None,
        goal_id: Optional[str] = None,
        state: Optional[str] = None,
    ) -> List[Task]:
        clauses: List[str] = []
        params: List[Any] = []
        if project_id:
            clauses.append("project_id = ?")
            params.append(project_id)
        if goal_id:
            clauses.append("goal_id = ?")
            params.append(goal_id)
        if state:
            clauses.append("lifecycle_state = ?")
            params.append(state)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self.db.fetchall(
            f"SELECT * FROM tasks {where} ORDER BY created_at ASC", params
        )
        return [self._row_task(r) for r in rows]


    def _row_task(self, row: sqlite3.Row) -> Task:
        return Task(
            task_id=row["task_id"],
            goal_id=row["goal_id"],
            project_id=row["project_id"],
            description=row["description"],
            depends_on=list(loads_json(row["depends_on_json"]) or []),
            assigned_agent_ref=row["assigned_agent_ref"],
            execution_eligible=bool(row["execution_eligible"]),
            lifecycle_state=row["lifecycle_state"],
            blocked_reason=row["blocked_reason"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            version=row["version"],
        )

