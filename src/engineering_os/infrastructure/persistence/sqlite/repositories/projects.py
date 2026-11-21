"""SQLite persistence for projects."""

from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional, Sequence

from engineering_os.domain.models import dumps_json, loads_json, utc_now
from engineering_os.infrastructure.persistence.sqlite.connection import SqliteDatabase
from engineering_os.infrastructure.persistence.sqlite.errors import ConcurrencyError
from engineering_os.domain.models import Project


class SqliteProjectRepository:
    def __init__(self, db: SqliteDatabase) -> None:
        self.db = db

    def upsert_project(self, project: Project) -> Project:
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO projects(
                  project_id, name, repository_identity, status,
                  isolation_requirements, created_at, updated_at, version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(project_id) DO UPDATE SET
                  name=excluded.name,
                  repository_identity=excluded.repository_identity,
                  status=excluded.status,
                  isolation_requirements=excluded.isolation_requirements,
                  updated_at=excluded.updated_at,
                  version=projects.version + 1
                """,
                (
                    project.project_id,
                    project.name,
                    project.repository_identity,
                    project.status,
                    project.isolation_requirements,
                    project.created_at,
                    project.updated_at,
                    project.version,
                ),
            )
        return self.get_project(project.project_id)  # type: ignore[return-value]


    def get_project(self, project_id: str) -> Optional[Project]:
        row = self.db.fetchone("SELECT * FROM projects WHERE project_id = ?", (project_id,))
        return self._row_project(row) if row else None


    def list_projects(self) -> List[Project]:
        rows = self.db.fetchall("SELECT * FROM projects ORDER BY created_at ASC")
        return [self._row_project(r) for r in rows]


    def _row_project(self, row: sqlite3.Row) -> Project:
        return Project(
            project_id=row["project_id"],
            name=row["name"],
            repository_identity=row["repository_identity"],
            status=row["status"],
            isolation_requirements=row["isolation_requirements"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            version=row["version"],
        )

