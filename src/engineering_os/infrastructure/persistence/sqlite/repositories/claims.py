"""SQLite persistence for claims."""

from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional, Sequence

from engineering_os.domain.models import dumps_json, loads_json, utc_now
from engineering_os.infrastructure.persistence.sqlite.connection import SqliteDatabase
from engineering_os.infrastructure.persistence.sqlite.errors import ConcurrencyError


class SqliteClaimRepository:
    def __init__(self, db: SqliteDatabase) -> None:
        self.db = db

    def get_claim(self, project_id: str) -> Optional[Dict[str, Any]]:
        row = self.db.fetchone(
            "SELECT * FROM orchestration_claims WHERE project_id=?", (project_id,)
        )
        return dict(row) if row else None


    def set_claim(
        self,
        project_id: str,
        *,
        execution_id: Optional[str],
        task_id: Optional[str],
        claim_token: Optional[str],
    ) -> None:
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO orchestration_claims(project_id, execution_id, task_id, claimed_at, claim_token)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(project_id) DO UPDATE SET
                  execution_id=excluded.execution_id,
                  task_id=excluded.task_id,
                  claimed_at=excluded.claimed_at,
                  claim_token=excluded.claim_token
                """,
                (project_id, execution_id, task_id, utc_now(), claim_token),
            )


    def clear_claim(self, project_id: str) -> None:
        with self.db.transaction() as conn:
            conn.execute(
                "DELETE FROM orchestration_claims WHERE project_id=?", (project_id,)
            )

