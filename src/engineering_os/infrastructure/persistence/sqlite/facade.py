"""Public Repository facade delegating to the SQLite unit of work."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from engineering_os.domain.models import (
    Approval,
    Execution,
    Goal,
    OperationalEvent,
    Project,
    Task,
)
from engineering_os.infrastructure.persistence.sqlite.unit_of_work import SqliteUnitOfWork


class Repository:
    def __init__(self, db_path: str | Path) -> None:
        self._uow = SqliteUnitOfWork(db_path)
        self.db_path = self._uow.db_path

    def close(self) -> None:
        self._uow.close()

    def initialize_schema(self) -> None:
        self._uow.initialize_schema()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._uow.db.transaction() as conn:
            yield conn

    def upsert_project(self, project: Project) -> Project:
        return self._uow.projects.upsert_project(project)

    def get_project(self, project_id: str) -> Optional[Project]:
        return self._uow.projects.get_project(project_id)

    def list_projects(self) -> List[Project]:
        return self._uow.projects.list_projects()

    def insert_goal(self, goal: Goal) -> Goal:
        return self._uow.goals.insert_goal(goal)

    def update_goal(self, goal: Goal, *, expected_version: int) -> Goal:
        return self._uow.goals.update_goal(goal, expected_version=expected_version)

    def get_goal(self, goal_id: str) -> Optional[Goal]:
        return self._uow.goals.get_goal(goal_id)

    def list_goals(self, project_id: Optional[str]=None) -> List[Goal]:
        return self._uow.goals.list_goals(project_id)

    def insert_task(self, task: Task) -> Task:
        return self._uow.tasks.insert_task(task)

    def update_task(self, task: Task, *, expected_version: int) -> Task:
        return self._uow.tasks.update_task(task, expected_version=expected_version)

    def get_task(self, task_id: str) -> Optional[Task]:
        return self._uow.tasks.get_task(task_id)

    def list_tasks(self, *, project_id: Optional[str]=None, goal_id: Optional[str]=None, state: Optional[str]=None) -> List[Task]:
        return self._uow.tasks.list_tasks(project_id=project_id, goal_id=goal_id, state=state)

    def insert_execution(self, execution: Execution) -> Execution:
        return self._uow.executions.insert_execution(execution)

    def update_execution(self, execution: Execution, *, expected_version: int) -> Execution:
        return self._uow.executions.update_execution(execution, expected_version=expected_version)

    def get_execution(self, execution_id: str) -> Optional[Execution]:
        return self._uow.executions.get_execution(execution_id)

    def get_execution_by_idempotency(self, key: str) -> Optional[Execution]:
        return self._uow.executions.get_execution_by_idempotency(key)

    def list_executions(self, *, project_id: Optional[str]=None, task_id: Optional[str]=None) -> List[Execution]:
        return self._uow.executions.list_executions(project_id=project_id, task_id=task_id)

    def next_attempt_number(self, task_id: str) -> int:
        return self._uow.executions.next_attempt_number(task_id)

    def insert_approval(self, approval: Approval) -> Approval:
        return self._uow.approvals.insert_approval(approval)

    def update_approval(self, approval: Approval) -> Approval:
        return self._uow.approvals.update_approval(approval)

    def get_approval(self, approval_id: str) -> Optional[Approval]:
        return self._uow.approvals.get_approval(approval_id)

    def list_approvals(self, *, pending_only: bool=False) -> List[Approval]:
        return self._uow.approvals.list_approvals(pending_only=pending_only)

    def append_event(self, event: OperationalEvent) -> OperationalEvent:
        return self._uow.events.append_event(event)

    def list_events(self, *, limit: int=100, aggregate_type: Optional[str]=None, aggregate_id: Optional[str]=None) -> List[OperationalEvent]:
        return self._uow.events.list_events(limit=limit, aggregate_type=aggregate_type, aggregate_id=aggregate_id)

    def get_claim(self, project_id: str) -> Optional[Dict[str, Any]]:
        return self._uow.claims.get_claim(project_id)

    def set_claim(self, project_id: str, *, execution_id: Optional[str], task_id: Optional[str], claim_token: Optional[str]) -> None:
        return self._uow.claims.set_claim(project_id, execution_id=execution_id, task_id=task_id, claim_token=claim_token)

    def clear_claim(self, project_id: str) -> None:
        return self._uow.claims.clear_claim(project_id)

    def upsert_github_connection(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return self._uow.integrations.upsert_github_connection(data)

    def get_github_connection(self, project_id: str) -> Optional[Dict[str, Any]]:
        return self._uow.integrations.get_github_connection(project_id)

    def list_github_connections(self) -> List[Dict[str, Any]]:
        return self._uow.integrations.list_github_connections()

    def upsert_execution_pr_link(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return self._uow.integrations.upsert_execution_pr_link(data)

    def get_execution_pr_link(self, execution_id: str) -> Optional[Dict[str, Any]]:
        return self._uow.integrations.get_execution_pr_link(execution_id)

    def list_execution_pr_links(self, *, project_id: Optional[str]=None) -> List[Dict[str, Any]]:
        return self._uow.integrations.list_execution_pr_links(project_id=project_id)

    def insert_github_observation(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return self._uow.integrations.insert_github_observation(data)

    def get_github_observation(self, observation_id: str) -> Optional[Dict[str, Any]]:
        return self._uow.integrations.get_github_observation(observation_id)

    def latest_github_observation(self, *, project_id: str, execution_id: Optional[str]=None, pr_number: Optional[int]=None, include_stale: bool=False) -> Optional[Dict[str, Any]]:
        return self._uow.integrations.latest_github_observation(project_id=project_id, execution_id=execution_id, pr_number=pr_number, include_stale=include_stale)

    def list_github_observations(self, *, project_id: str, limit: int=50) -> List[Dict[str, Any]]:
        return self._uow.integrations.list_github_observations(project_id=project_id, limit=limit)

    def upsert_external_mapping(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return self._uow.integrations.upsert_external_mapping(data)

    def get_external_mapping(self, system_name: str, local_kind: str, local_id: str) -> Optional[Dict[str, Any]]:
        return self._uow.integrations.get_external_mapping(system_name, local_kind, local_id)

    def list_external_mappings(self, *, system_name: Optional[str]=None, company_id: Optional[str]=None, local_kind: Optional[str]=None) -> List[Dict[str, Any]]:
        return self._uow.integrations.list_external_mappings(system_name=system_name, company_id=company_id, local_kind=local_kind)

    def insert_integration_observation(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return self._uow.integrations.insert_integration_observation(data)

    def get_integration_observation(self, observation_id: str) -> Optional[Dict[str, Any]]:
        return self._uow.integrations.get_integration_observation(observation_id)

    def latest_integration_observation(self, *, system_name: str, project_id: Optional[str]=None, company_id: Optional[str]=None, include_stale: bool=False) -> Optional[Dict[str, Any]]:
        return self._uow.integrations.latest_integration_observation(system_name=system_name, project_id=project_id, company_id=company_id, include_stale=include_stale)

    def insert_acp_session(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return self._uow.acp_sessions.insert_acp_session(data)

    def update_acp_session(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return self._uow.acp_sessions.update_acp_session(data)

    def get_acp_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        return self._uow.acp_sessions.get_acp_session(session_id)

    def get_acp_session_by_execution(self, execution_id: str) -> Optional[Dict[str, Any]]:
        return self._uow.acp_sessions.get_acp_session_by_execution(execution_id)

    def list_acp_sessions(self, *, project_id: Optional[str]=None) -> List[Dict[str, Any]]:
        return self._uow.acp_sessions.list_acp_sessions(project_id=project_id)

    def append_acp_event(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return self._uow.acp_sessions.append_acp_event(data)

    def acp_event_exists(self, session_id: str, dedupe_key: str) -> bool:
        return self._uow.acp_sessions.acp_event_exists(session_id, dedupe_key)

    def list_acp_events(self, session_id: str) -> List[Dict[str, Any]]:
        return self._uow.acp_sessions.list_acp_events(session_id)

    def insert_runtime_preparation(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return self._uow.runtime_preparations.insert_runtime_preparation(data)

    def update_runtime_preparation(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return self._uow.runtime_preparations.update_runtime_preparation(data)

    def get_runtime_preparation(self, preparation_id: str) -> Optional[Dict[str, Any]]:
        return self._uow.runtime_preparations.get_runtime_preparation(preparation_id)

    def get_runtime_preparation_by_execution(self, execution_id: str) -> Optional[Dict[str, Any]]:
        return self._uow.runtime_preparations.get_runtime_preparation_by_execution(execution_id)

    def list_runtime_preparations(self, *, project_id: Optional[str]=None) -> List[Dict[str, Any]]:
        return self._uow.runtime_preparations.list_runtime_preparations(project_id=project_id)

    def insert_cursor_preparation(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return self._uow.cursor_preparations.insert_cursor_preparation(data)

    def update_cursor_preparation(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return self._uow.cursor_preparations.update_cursor_preparation(data)

    def get_cursor_preparation(self, preparation_id: str) -> Optional[Dict[str, Any]]:
        return self._uow.cursor_preparations.get_cursor_preparation(preparation_id)

    def get_cursor_preparation_by_execution(self, execution_id: str) -> Optional[Dict[str, Any]]:
        return self._uow.cursor_preparations.get_cursor_preparation_by_execution(execution_id)

    def list_cursor_preparations(self, *, project_id: Optional[str]=None) -> List[Dict[str, Any]]:
        return self._uow.cursor_preparations.list_cursor_preparations(project_id=project_id)

    def insert_oci_fixture_run(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return self._uow.oci_fixture_runs.insert_oci_fixture_run(data)

    def update_oci_fixture_run(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return self._uow.oci_fixture_runs.update_oci_fixture_run(data)

    def get_oci_fixture_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        return self._uow.oci_fixture_runs.get_oci_fixture_run(run_id)

    def get_oci_fixture_run_by_execution(self, execution_id: str) -> Optional[Dict[str, Any]]:
        return self._uow.oci_fixture_runs.get_oci_fixture_run_by_execution(execution_id)

    def list_oci_fixture_runs(self, *, project_id: Optional[str]=None, limit: int=50) -> List[Dict[str, Any]]:
        return self._uow.oci_fixture_runs.list_oci_fixture_runs(project_id=project_id, limit=limit)
