"""Unit of work wiring focused repositories to one database."""

from __future__ import annotations

from pathlib import Path

from engineering_os.infrastructure.persistence.sqlite.connection import SqliteDatabase
from engineering_os.infrastructure.persistence.sqlite.repositories import (
    SqliteAcpSessionRepository,
    SqliteApprovalRepository,
    SqliteClaimRepository,
    SqliteCursorPreparationRepository,
    SqliteEventRepository,
    SqliteExecutionRepository,
    SqliteGoalRepository,
    SqliteIntegrationRepository,
    SqliteOciFixtureRunRepository,
    SqliteProjectRepository,
    SqliteRuntimePreparationRepository,
    SqliteTaskRepository,
)


class SqliteUnitOfWork:
    def __init__(self, db_path: str | Path) -> None:
        self.db = SqliteDatabase(db_path)
        self.projects = SqliteProjectRepository(self.db)
        self.goals = SqliteGoalRepository(self.db)
        self.tasks = SqliteTaskRepository(self.db)
        self.executions = SqliteExecutionRepository(self.db)
        self.approvals = SqliteApprovalRepository(self.db)
        self.events = SqliteEventRepository(self.db)
        self.claims = SqliteClaimRepository(self.db)
        self.integrations = SqliteIntegrationRepository(self.db)
        self.acp_sessions = SqliteAcpSessionRepository(self.db)
        self.runtime_preparations = SqliteRuntimePreparationRepository(self.db)
        self.cursor_preparations = SqliteCursorPreparationRepository(self.db)
        self.oci_fixture_runs = SqliteOciFixtureRunRepository(self.db)

    @property
    def db_path(self) -> str:
        return self.db.db_path

    def close(self) -> None:
        self.db.close()

    def initialize_schema(self) -> None:
        self.db.initialize_schema()