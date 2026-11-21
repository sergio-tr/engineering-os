"""SQLite persistence for approvals."""

from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional, Sequence

from engineering_os.domain.models import dumps_json, loads_json, utc_now
from engineering_os.infrastructure.persistence.sqlite.connection import SqliteDatabase
from engineering_os.infrastructure.persistence.sqlite.errors import ConcurrencyError
from engineering_os.domain.models import Approval


class SqliteApprovalRepository:
    def __init__(self, db: SqliteDatabase) -> None:
        self.db = db

    def insert_approval(self, approval: Approval) -> Approval:
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO approvals(
                  approval_id, requested_action, scope, approver_reference,
                  decision, expires_at, audit_metadata_json, goal_id, project_id,
                  created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    approval.approval_id,
                    approval.requested_action,
                    approval.scope,
                    approval.approver_reference,
                    approval.decision,
                    approval.expires_at,
                    dumps_json(approval.audit_metadata),
                    approval.goal_id,
                    approval.project_id,
                    approval.created_at,
                    approval.updated_at,
                ),
            )
        return approval


    def update_approval(self, approval: Approval) -> Approval:
        approval.updated_at = utc_now()
        with self.db.transaction() as conn:
            conn.execute(
                """
                UPDATE approvals SET
                  requested_action=?,
                  scope=?,
                  approver_reference=?,
                  decision=?,
                  expires_at=?,
                  audit_metadata_json=?,
                  updated_at=?
                WHERE approval_id=?
                """,
                (
                    approval.requested_action,
                    approval.scope,
                    approval.approver_reference,
                    approval.decision,
                    approval.expires_at,
                    dumps_json(approval.audit_metadata),
                    approval.updated_at,
                    approval.approval_id,
                ),
            )
        return approval


    def get_approval(self, approval_id: str) -> Optional[Approval]:
        row = self.db.fetchone("SELECT * FROM approvals WHERE approval_id = ?", (approval_id,))
        return self._row_approval(row) if row else None


    def list_approvals(self, *, pending_only: bool = False) -> List[Approval]:
        if pending_only:
            rows = self.db.fetchall(
                "SELECT * FROM approvals WHERE decision='PENDING' ORDER BY created_at ASC"
            )
        else:
            rows = self.db.fetchall("SELECT * FROM approvals ORDER BY created_at ASC")
        return [self._row_approval(r) for r in rows]


    def _row_approval(self, row: sqlite3.Row) -> Approval:
        return Approval(
            approval_id=row["approval_id"],
            requested_action=row["requested_action"],
            scope=row["scope"],
            approver_reference=row["approver_reference"],
            decision=row["decision"],
            expires_at=row["expires_at"],
            audit_metadata=dict(loads_json(row["audit_metadata_json"]) or {}),
            goal_id=row["goal_id"],
            project_id=row["project_id"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

