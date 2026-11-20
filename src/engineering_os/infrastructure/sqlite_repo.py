"""SQLite persistence for the Engineering OS control plane."""

from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence

from engineering_os.domain.models import (
    Approval,
    Execution,
    Goal,
    OperationalEvent,
    Project,
    Task,
    dumps_json,
    loads_json,
    utc_now,
)


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS projects (
  project_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  repository_identity TEXT NOT NULL,
  status TEXT NOT NULL,
  isolation_requirements TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS goals (
  goal_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(project_id),
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  priority INTEGER NOT NULL,
  approval_state TEXT NOT NULL,
  lifecycle_state TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS tasks (
  task_id TEXT PRIMARY KEY,
  goal_id TEXT NOT NULL REFERENCES goals(goal_id),
  project_id TEXT NOT NULL REFERENCES projects(project_id),
  description TEXT NOT NULL,
  depends_on_json TEXT NOT NULL,
  assigned_agent_ref TEXT NOT NULL,
  execution_eligible INTEGER NOT NULL,
  lifecycle_state TEXT NOT NULL,
  blocked_reason TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS executions (
  execution_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL REFERENCES tasks(task_id),
  project_id TEXT NOT NULL REFERENCES projects(project_id),
  execution_contract_ref TEXT NOT NULL,
  runner_type TEXT NOT NULL,
  attempt_number INTEGER NOT NULL,
  status TEXT NOT NULL,
  failure_reason TEXT,
  evidence_refs_json TEXT NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE,
  started_at TEXT,
  ended_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  integration_state TEXT,
  synthetic INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS approvals (
  approval_id TEXT PRIMARY KEY,
  requested_action TEXT NOT NULL,
  scope TEXT NOT NULL,
  approver_reference TEXT NOT NULL,
  decision TEXT NOT NULL,
  expires_at TEXT,
  audit_metadata_json TEXT NOT NULL,
  goal_id TEXT,
  project_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS operational_events (
  event_id TEXT PRIMARY KEY,
  aggregate_type TEXT NOT NULL,
  aggregate_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  correlation_id TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS orchestration_claims (
  project_id TEXT PRIMARY KEY,
  execution_id TEXT,
  task_id TEXT,
  claimed_at TEXT,
  claim_token TEXT
);

CREATE INDEX IF NOT EXISTS idx_tasks_project ON tasks(project_id, lifecycle_state);
CREATE INDEX IF NOT EXISTS idx_exec_task ON executions(task_id, attempt_number);
CREATE INDEX IF NOT EXISTS idx_events_agg ON operational_events(aggregate_type, aggregate_id);

CREATE TABLE IF NOT EXISTS github_connections (
  project_id TEXT PRIMARY KEY REFERENCES projects(project_id),
  owner TEXT NOT NULL,
  repo TEXT NOT NULL,
  repository_identity TEXT NOT NULL,
  api_base TEXT NOT NULL,
  default_branch TEXT,
  head_sha TEXT,
  last_sync_at TEXT,
  last_error_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS execution_pr_links (
  execution_id TEXT PRIMARY KEY REFERENCES executions(execution_id),
  project_id TEXT NOT NULL REFERENCES projects(project_id),
  repository_identity TEXT NOT NULL,
  pr_number INTEGER NOT NULL,
  expected_base_ref TEXT,
  expected_head_sha TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(project_id, repository_identity, pr_number)
);

CREATE TABLE IF NOT EXISTS github_observations (
  observation_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(project_id),
  execution_id TEXT,
  repository_identity TEXT NOT NULL,
  pr_number INTEGER,
  evidence_class TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  stale INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_gh_obs_project ON github_observations(project_id, observed_at);
CREATE INDEX IF NOT EXISTS idx_pr_links_project ON execution_pr_links(project_id);

CREATE TABLE IF NOT EXISTS external_identity_mappings (
  mapping_id TEXT PRIMARY KEY,
  system_name TEXT NOT NULL,
  company_id TEXT,
  local_kind TEXT NOT NULL,
  local_id TEXT NOT NULL,
  external_id TEXT NOT NULL,
  external_revision TEXT,
  correlation_id TEXT,
  last_sync_at TEXT,
  evidence_class TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(system_name, local_kind, local_id),
  UNIQUE(system_name, company_id, local_kind, external_id)
);

CREATE TABLE IF NOT EXISTS integration_observations (
  observation_id TEXT PRIMARY KEY,
  system_name TEXT NOT NULL,
  project_id TEXT,
  company_id TEXT,
  evidence_class TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  stale INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_ext_map_local ON external_identity_mappings(system_name, local_kind, local_id);
CREATE INDEX IF NOT EXISTS idx_int_obs_system ON integration_observations(system_name, observed_at);

CREATE TABLE IF NOT EXISTS acp_sessions (
  session_id TEXT PRIMARY KEY,
  execution_id TEXT NOT NULL UNIQUE,
  project_id TEXT NOT NULL,
  task_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  acp_backend TEXT NOT NULL,
  transport_type TEXT NOT NULL,
  protocol_version INTEGER NOT NULL,
  status TEXT NOT NULL,
  correlation_id TEXT NOT NULL,
  last_event_sequence INTEGER NOT NULL DEFAULT 0,
  cancellation_state TEXT,
  failure_reason TEXT,
  evidence_refs_json TEXT NOT NULL,
  runtime_provenance_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  started_at TEXT,
  completed_at TEXT,
  last_activity_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS acp_session_events (
  event_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES acp_sessions(session_id),
  execution_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  event_type TEXT NOT NULL,
  dedupe_key TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  UNIQUE(session_id, dedupe_key)
);

CREATE INDEX IF NOT EXISTS idx_acp_sess_project ON acp_sessions(project_id, status);
CREATE INDEX IF NOT EXISTS idx_acp_evt_session ON acp_session_events(session_id, sequence);
"""


class ConcurrencyError(RuntimeError):
    pass


class Repository:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            self.db_path,
            isolation_level=None,
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self.initialize_schema()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def initialize_schema(self) -> None:
        with self._lock:
            self._conn.executescript(SCHEMA)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def _fetchone(self, sql: str, params: Sequence[Any] = ()) -> Optional[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchone()

    def _fetchall(self, sql: str, params: Sequence[Any] = ()) -> List[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(sql, params).fetchall())

    # --- projects ---
    def upsert_project(self, project: Project) -> Project:
        with self.transaction() as conn:
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
        row = self._fetchone("SELECT * FROM projects WHERE project_id = ?", (project_id,))
        return self._row_project(row) if row else None

    def list_projects(self) -> List[Project]:
        rows = self._fetchall("SELECT * FROM projects ORDER BY created_at ASC")
        return [self._row_project(r) for r in rows]

    # --- goals ---
    def insert_goal(self, goal: Goal) -> Goal:
        with self.transaction() as conn:
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
        with self.transaction() as conn:
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
        row = self._fetchone("SELECT * FROM goals WHERE goal_id = ?", (goal_id,))
        return self._row_goal(row) if row else None

    def list_goals(self, project_id: Optional[str] = None) -> List[Goal]:
        if project_id:
            rows = self._fetchall(
                "SELECT * FROM goals WHERE project_id=? ORDER BY priority ASC, created_at ASC",
                (project_id,),
            )
        else:
            rows = self._fetchall("SELECT * FROM goals ORDER BY created_at ASC")
        return [self._row_goal(r) for r in rows]

    # --- tasks ---
    def insert_task(self, task: Task) -> Task:
        with self.transaction() as conn:
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
        with self.transaction() as conn:
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
        row = self._fetchone("SELECT * FROM tasks WHERE task_id = ?", (task_id,))
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
        rows = self._fetchall(
            f"SELECT * FROM tasks {where} ORDER BY created_at ASC", params
        )
        return [self._row_task(r) for r in rows]

    # --- executions ---
    def insert_execution(self, execution: Execution) -> Execution:
        with self.transaction() as conn:
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
        with self.transaction() as conn:
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
        row = self._fetchone("SELECT * FROM executions WHERE execution_id = ?", (execution_id,))
        return self._row_execution(row) if row else None

    def get_execution_by_idempotency(self, key: str) -> Optional[Execution]:
        row = self._fetchone("SELECT * FROM executions WHERE idempotency_key = ?", (key,))
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
        rows = self._fetchall(
            f"SELECT * FROM executions {where} ORDER BY created_at ASC", params
        )
        return [self._row_execution(r) for r in rows]

    def next_attempt_number(self, task_id: str) -> int:
        row = self._fetchone(
            "SELECT COALESCE(MAX(attempt_number), 0) AS m FROM executions WHERE task_id=?",
            (task_id,),
        )
        return int(row["m"]) + 1

    # --- approvals ---
    def insert_approval(self, approval: Approval) -> Approval:
        with self.transaction() as conn:
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
        with self.transaction() as conn:
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
        row = self._fetchone("SELECT * FROM approvals WHERE approval_id = ?", (approval_id,))
        return self._row_approval(row) if row else None

    def list_approvals(self, *, pending_only: bool = False) -> List[Approval]:
        if pending_only:
            rows = self._fetchall(
                "SELECT * FROM approvals WHERE decision='PENDING' ORDER BY created_at ASC"
            )
        else:
            rows = self._fetchall("SELECT * FROM approvals ORDER BY created_at ASC")
        return [self._row_approval(r) for r in rows]

    # --- events ---
    def append_event(self, event: OperationalEvent) -> OperationalEvent:
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO operational_events(
                  event_id, aggregate_type, aggregate_id, event_type,
                  correlation_id, payload_json, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.aggregate_type,
                    event.aggregate_id,
                    event.event_type,
                    event.correlation_id,
                    dumps_json(event.payload),
                    event.timestamp,
                ),
            )
        return event

    def list_events(
        self,
        *,
        limit: int = 100,
        aggregate_type: Optional[str] = None,
        aggregate_id: Optional[str] = None,
    ) -> List[OperationalEvent]:
        clauses: List[str] = []
        params: List[Any] = []
        if aggregate_type:
            clauses.append("aggregate_type = ?")
            params.append(aggregate_type)
        if aggregate_id:
            clauses.append("aggregate_id = ?")
            params.append(aggregate_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        rows = self._fetchall(
            f"""
            SELECT * FROM operational_events {where}
            ORDER BY timestamp ASC, event_id ASC LIMIT ?
            """,
            params,
        )
        return [self._row_event(r) for r in rows]

    # --- orchestration claims ---
    def get_claim(self, project_id: str) -> Optional[Dict[str, Any]]:
        row = self._fetchone(
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
        with self.transaction() as conn:
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
        with self.transaction() as conn:
            conn.execute(
                "DELETE FROM orchestration_claims WHERE project_id=?", (project_id,)
            )

    # --- GitHub integration persistence (EOS-04) ---
    def upsert_github_connection(self, data: Dict[str, Any]) -> Dict[str, Any]:
        now = utc_now()
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO github_connections(
                  project_id, owner, repo, repository_identity, api_base,
                  default_branch, head_sha, last_sync_at, last_error_json,
                  created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(project_id) DO UPDATE SET
                  owner=excluded.owner,
                  repo=excluded.repo,
                  repository_identity=excluded.repository_identity,
                  api_base=excluded.api_base,
                  default_branch=excluded.default_branch,
                  head_sha=excluded.head_sha,
                  last_sync_at=excluded.last_sync_at,
                  last_error_json=excluded.last_error_json,
                  updated_at=excluded.updated_at
                """,
                (
                    data["project_id"],
                    data["owner"],
                    data["repo"],
                    data["repository_identity"],
                    data.get("api_base") or "https://api.github.com",
                    data.get("default_branch"),
                    data.get("head_sha"),
                    data.get("last_sync_at"),
                    dumps_json(data.get("last_error")),
                    data.get("created_at") or now,
                    now,
                ),
            )
        return self.get_github_connection(data["project_id"])  # type: ignore[return-value]

    def get_github_connection(self, project_id: str) -> Optional[Dict[str, Any]]:
        row = self._fetchone(
            "SELECT * FROM github_connections WHERE project_id=?", (project_id,)
        )
        return self._row_github_connection(row) if row else None

    def list_github_connections(self) -> List[Dict[str, Any]]:
        rows = self._fetchall(
            "SELECT * FROM github_connections ORDER BY updated_at DESC"
        )
        return [self._row_github_connection(r) for r in rows]

    def upsert_execution_pr_link(self, data: Dict[str, Any]) -> Dict[str, Any]:
        now = utc_now()
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO execution_pr_links(
                  execution_id, project_id, repository_identity, pr_number,
                  expected_base_ref, expected_head_sha, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(execution_id) DO UPDATE SET
                  repository_identity=excluded.repository_identity,
                  pr_number=excluded.pr_number,
                  expected_base_ref=excluded.expected_base_ref,
                  expected_head_sha=excluded.expected_head_sha,
                  updated_at=excluded.updated_at
                """,
                (
                    data["execution_id"],
                    data["project_id"],
                    data["repository_identity"],
                    int(data["pr_number"]),
                    data.get("expected_base_ref"),
                    data.get("expected_head_sha"),
                    data.get("created_at") or now,
                    now,
                ),
            )
        return self.get_execution_pr_link(data["execution_id"])  # type: ignore[return-value]

    def get_execution_pr_link(self, execution_id: str) -> Optional[Dict[str, Any]]:
        row = self._fetchone(
            "SELECT * FROM execution_pr_links WHERE execution_id=?", (execution_id,)
        )
        return dict(row) if row else None

    def list_execution_pr_links(
        self, *, project_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        if project_id:
            rows = self._fetchall(
                "SELECT * FROM execution_pr_links WHERE project_id=? ORDER BY updated_at DESC",
                (project_id,),
            )
        else:
            rows = self._fetchall(
                "SELECT * FROM execution_pr_links ORDER BY updated_at DESC"
            )
        return [dict(r) for r in rows]

    def insert_github_observation(self, data: Dict[str, Any]) -> Dict[str, Any]:
        with self.transaction() as conn:
            # Mark previous observations for same target as stale.
            if data.get("execution_id"):
                conn.execute(
                    """
                    UPDATE github_observations SET stale=1
                    WHERE project_id=? AND execution_id=? AND stale=0
                    """,
                    (data["project_id"], data["execution_id"]),
                )
            elif data.get("pr_number") is not None:
                conn.execute(
                    """
                    UPDATE github_observations SET stale=1
                    WHERE project_id=? AND pr_number=? AND execution_id IS NULL AND stale=0
                    """,
                    (data["project_id"], data["pr_number"]),
                )
            else:
                conn.execute(
                    """
                    UPDATE github_observations SET stale=1
                    WHERE project_id=? AND pr_number IS NULL AND execution_id IS NULL AND stale=0
                    """,
                    (data["project_id"],),
                )
            conn.execute(
                """
                INSERT INTO github_observations(
                  observation_id, project_id, execution_id, repository_identity,
                  pr_number, evidence_class, payload_json, observed_at, stale
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    data["observation_id"],
                    data["project_id"],
                    data.get("execution_id"),
                    data["repository_identity"],
                    data.get("pr_number"),
                    data["evidence_class"],
                    dumps_json(data.get("payload") or {}),
                    data.get("observed_at") or utc_now(),
                ),
            )
        return self.get_github_observation(data["observation_id"])  # type: ignore[return-value]

    def get_github_observation(self, observation_id: str) -> Optional[Dict[str, Any]]:
        row = self._fetchone(
            "SELECT * FROM github_observations WHERE observation_id=?",
            (observation_id,),
        )
        return self._row_github_observation(row) if row else None

    def latest_github_observation(
        self,
        *,
        project_id: str,
        execution_id: Optional[str] = None,
        pr_number: Optional[int] = None,
        include_stale: bool = False,
    ) -> Optional[Dict[str, Any]]:
        clauses = ["project_id = ?"]
        params: List[Any] = [project_id]
        if execution_id:
            clauses.append("execution_id = ?")
            params.append(execution_id)
        if pr_number is not None:
            clauses.append("pr_number = ?")
            params.append(pr_number)
        if not include_stale:
            clauses.append("stale = 0")
        where = " AND ".join(clauses)
        row = self._fetchone(
            f"""
            SELECT * FROM github_observations
            WHERE {where}
            ORDER BY observed_at DESC, observation_id DESC
            LIMIT 1
            """,
            params,
        )
        return self._row_github_observation(row) if row else None

    def list_github_observations(
        self, *, project_id: str, limit: int = 50
    ) -> List[Dict[str, Any]]:
        rows = self._fetchall(
            """
            SELECT * FROM github_observations
            WHERE project_id=?
            ORDER BY observed_at DESC
            LIMIT ?
            """,
            (project_id, limit),
        )
        return [self._row_github_observation(r) for r in rows]

    def upsert_external_mapping(self, data: Dict[str, Any]) -> Dict[str, Any]:
        now = utc_now()
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO external_identity_mappings(
                  mapping_id, system_name, company_id, local_kind, local_id,
                  external_id, external_revision, correlation_id, last_sync_at,
                  evidence_class, payload_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(system_name, local_kind, local_id) DO UPDATE SET
                  company_id=excluded.company_id,
                  external_id=excluded.external_id,
                  external_revision=excluded.external_revision,
                  correlation_id=excluded.correlation_id,
                  last_sync_at=excluded.last_sync_at,
                  evidence_class=excluded.evidence_class,
                  payload_json=excluded.payload_json,
                  updated_at=excluded.updated_at
                """,
                (
                    data.get("mapping_id") or data["local_id"],
                    data["system_name"],
                    data.get("company_id"),
                    data["local_kind"],
                    data["local_id"],
                    data["external_id"],
                    data.get("external_revision"),
                    data.get("correlation_id"),
                    data.get("last_sync_at") or now,
                    data["evidence_class"],
                    dumps_json(data.get("payload") or {}),
                    data.get("created_at") or now,
                    now,
                ),
            )
        return self.get_external_mapping(
            data["system_name"], data["local_kind"], data["local_id"]
        )  # type: ignore[return-value]

    def get_external_mapping(
        self, system_name: str, local_kind: str, local_id: str
    ) -> Optional[Dict[str, Any]]:
        row = self._fetchone(
            """
            SELECT * FROM external_identity_mappings
            WHERE system_name=? AND local_kind=? AND local_id=?
            """,
            (system_name, local_kind, local_id),
        )
        return self._row_external_mapping(row) if row else None

    def list_external_mappings(
        self,
        *,
        system_name: Optional[str] = None,
        company_id: Optional[str] = None,
        local_kind: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        clauses: List[str] = []
        params: List[Any] = []
        if system_name:
            clauses.append("system_name = ?")
            params.append(system_name)
        if company_id:
            clauses.append("company_id = ?")
            params.append(company_id)
        if local_kind:
            clauses.append("local_kind = ?")
            params.append(local_kind)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._fetchall(
            f"SELECT * FROM external_identity_mappings {where} ORDER BY updated_at DESC",
            params,
        )
        return [self._row_external_mapping(r) for r in rows]

    def insert_integration_observation(self, data: Dict[str, Any]) -> Dict[str, Any]:
        with self.transaction() as conn:
            conn.execute(
                """
                UPDATE integration_observations SET stale=1
                WHERE system_name=? AND IFNULL(project_id,'')=IFNULL(?, '')
                  AND IFNULL(company_id,'')=IFNULL(?, '') AND stale=0
                """,
                (
                    data["system_name"],
                    data.get("project_id"),
                    data.get("company_id"),
                ),
            )
            conn.execute(
                """
                INSERT INTO integration_observations(
                  observation_id, system_name, project_id, company_id,
                  evidence_class, payload_json, observed_at, stale
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    data["observation_id"],
                    data["system_name"],
                    data.get("project_id"),
                    data.get("company_id"),
                    data["evidence_class"],
                    dumps_json(data.get("payload") or {}),
                    data.get("observed_at") or utc_now(),
                ),
            )
        return self.get_integration_observation(data["observation_id"])  # type: ignore[return-value]

    def get_integration_observation(
        self, observation_id: str
    ) -> Optional[Dict[str, Any]]:
        row = self._fetchone(
            "SELECT * FROM integration_observations WHERE observation_id=?",
            (observation_id,),
        )
        return self._row_integration_observation(row) if row else None

    def latest_integration_observation(
        self,
        *,
        system_name: str,
        project_id: Optional[str] = None,
        company_id: Optional[str] = None,
        include_stale: bool = False,
    ) -> Optional[Dict[str, Any]]:
        clauses = ["system_name = ?"]
        params: List[Any] = [system_name]
        if project_id is not None:
            clauses.append("project_id = ?")
            params.append(project_id)
        if company_id is not None:
            clauses.append("company_id = ?")
            params.append(company_id)
        if not include_stale:
            clauses.append("stale = 0")
        row = self._fetchone(
            f"""
            SELECT * FROM integration_observations
            WHERE {' AND '.join(clauses)}
            ORDER BY observed_at DESC LIMIT 1
            """,
            params,
        )
        return self._row_integration_observation(row) if row else None

    def _row_external_mapping(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "mapping_id": row["mapping_id"],
            "system_name": row["system_name"],
            "company_id": row["company_id"],
            "local_kind": row["local_kind"],
            "local_id": row["local_id"],
            "external_id": row["external_id"],
            "external_revision": row["external_revision"],
            "correlation_id": row["correlation_id"],
            "last_sync_at": row["last_sync_at"],
            "evidence_class": row["evidence_class"],
            "payload": dict(loads_json(row["payload_json"]) or {}),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def _row_integration_observation(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "observation_id": row["observation_id"],
            "system_name": row["system_name"],
            "project_id": row["project_id"],
            "company_id": row["company_id"],
            "evidence_class": row["evidence_class"],
            "payload": dict(loads_json(row["payload_json"]) or {}),
            "observed_at": row["observed_at"],
            "stale": bool(row["stale"]),
        }

    def insert_acp_session(self, data: Dict[str, Any]) -> Dict[str, Any]:
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO acp_sessions(
                  session_id, execution_id, project_id, task_id, agent_id,
                  acp_backend, transport_type, protocol_version, status,
                  correlation_id, last_event_sequence, cancellation_state,
                  failure_reason, evidence_refs_json, runtime_provenance_json,
                  created_at, started_at, completed_at, last_activity_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["session_id"],
                    data["execution_id"],
                    data["project_id"],
                    data["task_id"],
                    data["agent_id"],
                    data["acp_backend"],
                    data["transport_type"],
                    int(data["protocol_version"]),
                    data["status"],
                    data["correlation_id"],
                    int(data.get("last_event_sequence") or 0),
                    data.get("cancellation_state"),
                    data.get("failure_reason"),
                    dumps_json(data.get("evidence_refs") or []),
                    dumps_json(data.get("runtime_provenance") or {}),
                    data["created_at"],
                    data.get("started_at"),
                    data.get("completed_at"),
                    data["last_activity_at"],
                ),
            )
        return self.get_acp_session(data["session_id"])  # type: ignore[return-value]

    def update_acp_session(self, data: Dict[str, Any]) -> Dict[str, Any]:
        with self.transaction() as conn:
            conn.execute(
                """
                UPDATE acp_sessions SET
                  status=?, protocol_version=?, last_event_sequence=?,
                  cancellation_state=?, failure_reason=?, evidence_refs_json=?,
                  runtime_provenance_json=?, started_at=?, completed_at=?,
                  last_activity_at=?
                WHERE session_id=?
                """,
                (
                    data["status"],
                    int(data["protocol_version"]),
                    int(data.get("last_event_sequence") or 0),
                    data.get("cancellation_state"),
                    data.get("failure_reason"),
                    dumps_json(data.get("evidence_refs") or []),
                    dumps_json(data.get("runtime_provenance") or {}),
                    data.get("started_at"),
                    data.get("completed_at"),
                    data.get("last_activity_at") or utc_now(),
                    data["session_id"],
                ),
            )
        return self.get_acp_session(data["session_id"])  # type: ignore[return-value]

    def get_acp_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        row = self._fetchone(
            "SELECT * FROM acp_sessions WHERE session_id=?", (session_id,)
        )
        return self._row_acp_session(row) if row else None

    def get_acp_session_by_execution(self, execution_id: str) -> Optional[Dict[str, Any]]:
        row = self._fetchone(
            "SELECT * FROM acp_sessions WHERE execution_id=?", (execution_id,)
        )
        return self._row_acp_session(row) if row else None

    def list_acp_sessions(
        self, *, project_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        if project_id:
            rows = self._fetchall(
                "SELECT * FROM acp_sessions WHERE project_id=? ORDER BY created_at ASC",
                (project_id,),
            )
        else:
            rows = self._fetchall("SELECT * FROM acp_sessions ORDER BY created_at ASC")
        return [self._row_acp_session(r) for r in rows]

    def append_acp_event(self, data: Dict[str, Any]) -> Dict[str, Any]:
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO acp_session_events(
                  event_id, session_id, execution_id, sequence, event_type,
                  dedupe_key, payload_json, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["event_id"],
                    data["session_id"],
                    data["execution_id"],
                    int(data["sequence"]),
                    data["event_type"],
                    data["dedupe_key"],
                    dumps_json(data.get("payload") or {}),
                    data["timestamp"],
                ),
            )
        return {
            "event_id": data["event_id"],
            "session_id": data["session_id"],
            "execution_id": data["execution_id"],
            "sequence": data["sequence"],
            "event_type": data["event_type"],
            "dedupe_key": data["dedupe_key"],
            "payload": data.get("payload") or {},
            "timestamp": data["timestamp"],
        }

    def acp_event_exists(self, session_id: str, dedupe_key: str) -> bool:
        row = self._fetchone(
            "SELECT 1 AS ok FROM acp_session_events WHERE session_id=? AND dedupe_key=?",
            (session_id, dedupe_key),
        )
        return row is not None

    def list_acp_events(self, session_id: str) -> List[Dict[str, Any]]:
        rows = self._fetchall(
            """
            SELECT * FROM acp_session_events
            WHERE session_id=? ORDER BY sequence ASC
            """,
            (session_id,),
        )
        return [
            {
                "event_id": r["event_id"],
                "session_id": r["session_id"],
                "execution_id": r["execution_id"],
                "sequence": r["sequence"],
                "event_type": r["event_type"],
                "dedupe_key": r["dedupe_key"],
                "payload": dict(loads_json(r["payload_json"]) or {}),
                "timestamp": r["timestamp"],
            }
            for r in rows
        ]

    def _row_acp_session(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "session_id": row["session_id"],
            "execution_id": row["execution_id"],
            "project_id": row["project_id"],
            "task_id": row["task_id"],
            "agent_id": row["agent_id"],
            "acp_backend": row["acp_backend"],
            "transport_type": row["transport_type"],
            "protocol_version": row["protocol_version"],
            "status": row["status"],
            "correlation_id": row["correlation_id"],
            "last_event_sequence": row["last_event_sequence"],
            "cancellation_state": row["cancellation_state"],
            "failure_reason": row["failure_reason"],
            "evidence_refs": list(loads_json(row["evidence_refs_json"]) or []),
            "runtime_provenance": dict(loads_json(row["runtime_provenance_json"]) or {}),
            "created_at": row["created_at"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "last_activity_at": row["last_activity_at"],
        }

    def _row_github_connection(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "project_id": row["project_id"],
            "owner": row["owner"],
            "repo": row["repo"],
            "repository_identity": row["repository_identity"],
            "api_base": row["api_base"],
            "default_branch": row["default_branch"],
            "head_sha": row["head_sha"],
            "last_sync_at": row["last_sync_at"],
            "last_error": loads_json(row["last_error_json"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def _row_github_observation(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "observation_id": row["observation_id"],
            "project_id": row["project_id"],
            "execution_id": row["execution_id"],
            "repository_identity": row["repository_identity"],
            "pr_number": row["pr_number"],
            "evidence_class": row["evidence_class"],
            "payload": dict(loads_json(row["payload_json"]) or {}),
            "observed_at": row["observed_at"],
            "stale": bool(row["stale"]),
        }

    # --- row mappers ---
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

    def _row_event(self, row: sqlite3.Row) -> OperationalEvent:
        return OperationalEvent(
            event_id=row["event_id"],
            aggregate_type=row["aggregate_type"],
            aggregate_id=row["aggregate_id"],
            event_type=row["event_type"],
            correlation_id=row["correlation_id"],
            payload=dict(loads_json(row["payload_json"]) or {}),
            timestamp=row["timestamp"],
        )


def default_db_path() -> Path:
    override = os.environ.get("EOS_DB_PATH")
    if override:
        return Path(override)
    base = Path(os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share"))
    return base / "engineering-os" / "control-plane.sqlite3"
