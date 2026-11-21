"""SQLite persistence for goals."""

from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional, Sequence

from engineering_os.domain.models import dumps_json, loads_json, utc_now
from engineering_os.infrastructure.persistence.sqlite.connection import SqliteDatabase
from engineering_os.infrastructure.persistence.sqlite.errors import ConcurrencyError
from engineering_os.domain.models import Goal


class SqliteGoalRepository:
    def __init__(self, db: SqliteDatabase) -> None:
        self.db = db

    def insert_goal(self, goal: Goal) -> Goal:
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO goals(
                  goal_id, project_id, title, description, priority,
                  approval_state, lifecycle_state, created_at, updated_at, version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    goal.goal_id,
                    goal.project_id,
                    goal.title,
                    goal.description,
                    goal.priority,
                    goal.approval_state,
                    goal.lifecycle_state,
                    goal.created_at,
                    goal.updated_at,
                    goal.version,
                ),
            )
        return goal


    def update_goal(self, goal: Goal, *, expected_version: int) -> Goal:
        goal.updated_at = utc_now()
        with self.db.transaction() as conn:
            cur = conn.execute(
                """
                UPDATE goals SET
                  title=?, description=?, priority=?, approval_state=?,
                  lifecycle_state=?, updated_at=?, version=version+1
                WHERE goal_id=? AND version=?
                """,
                (
                    goal.title,
                    goal.description,
                    goal.priority,
                    goal.approval_state,
                    goal.lifecycle_state,
                    goal.updated_at,
                    goal.goal_id,
                    expected_version,
                ),
            )
            if cur.rowcount != 1:
                raise ConcurrencyError(f"goal version conflict: {goal.goal_id}")
        refreshed = self.get_goal(goal.goal_id)
        assert refreshed is not None
        return refreshed


    def get_goal(self, goal_id: str) -> Optional[Goal]:
        row = self.db.fetchone("SELECT * FROM goals WHERE goal_id = ?", (goal_id,))
        return self._row_goal(row) if row else None


    def list_goals(self, project_id: Optional[str] = None) -> List[Goal]:
        if project_id:
            rows = self.db.fetchall(
                "SELECT * FROM goals WHERE project_id=? ORDER BY priority ASC, created_at ASC",
                (project_id,),
            )
        else:
            rows = self.db.fetchall("SELECT * FROM goals ORDER BY created_at ASC")
        return [self._row_goal(r) for r in rows]


    def _row_goal(self, row: sqlite3.Row) -> Goal:
        return Goal(
            goal_id=row["goal_id"],
            project_id=row["project_id"],
            title=row["title"],
            description=row["description"],
            priority=row["priority"],
            approval_state=row["approval_state"],
            lifecycle_state=row["lifecycle_state"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            version=row["version"],
        )

