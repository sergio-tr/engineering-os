"""Application services for Engineering OS control plane."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import json

from engineering_os.domain.models import (
    Approval,
    Execution,
    Goal,
    OperationalEvent,
    Project,
    Task,
    new_id,
    utc_now,
)
from engineering_os.domain.states import (
    EXECUTION_TRANSITIONS,
    GOAL_TRANSITIONS,
    TASK_TRANSITIONS,
    IllegalTransitionError,
    assert_transition,
)
from engineering_os.infrastructure.adapters import (
    DisabledLiveExecutionAdapter,
    DispatchRequest,
    ExecutionAdapter,
    LocalEvidenceAdapter,
    LocalOwnerDecisionProvider,
    SimulatedRepositoryIntegrationAdapter,
    SyntheticExecutionAdapter,
)
from engineering_os.infrastructure.sqlite_repo import Repository, default_db_path

# Stable IDs for the persistent synthetic demonstration (idempotent seed).
DEMO_PROJECT_ID = "proj-eos-mvp-demo"
DEMO_GOAL_ID = "goal-eos-mvp-demo"
DEMO_TASK1_ID = "task-eos-mvp-demo-1"
DEMO_TASK2_ID = "task-eos-mvp-demo-2"
DEMO_REPOSITORY_IDENTITY = "local/synthetic-demo"


class PolicyError(ValueError):
    pass


class ControlPlane:
    def __init__(
        self,
        repo: Repository,
        *,
        execution_adapter: Optional[ExecutionAdapter] = None,
        live_adapter: Optional[ExecutionAdapter] = None,
        evidence: Optional[LocalEvidenceAdapter] = None,
        repo_integration: Optional[SimulatedRepositoryIntegrationAdapter] = None,
        approval_provider: Optional[LocalOwnerDecisionProvider] = None,
        sandbox_gate: str = "NOT_TESTED",
        max_attempts: int = 3,
    ) -> None:
        self.repo = repo
        self.synthetic = execution_adapter or SyntheticExecutionAdapter()
        self.live = live_adapter or DisabledLiveExecutionAdapter()
        self.evidence = evidence or LocalEvidenceAdapter()
        self.repo_integration = repo_integration or SimulatedRepositoryIntegrationAdapter()
        self.approval_provider = approval_provider or LocalOwnerDecisionProvider()
        self.sandbox_gate = sandbox_gate
        self.max_attempts = max_attempts

    # --- factories ---
    @classmethod
    def open(cls, db_path: Optional[str | Path] = None) -> "ControlPlane":
        path = Path(db_path) if db_path else default_db_path()
        return cls(Repository(path))

    def close(self) -> None:
        self.repo.close()

    # --- events ---
    def _emit(
        self,
        *,
        aggregate_type: str,
        aggregate_id: str,
        event_type: str,
        payload: Dict[str, Any],
        correlation_id: Optional[str] = None,
    ) -> OperationalEvent:
        event = OperationalEvent(
            event_id=new_id("evt"),
            aggregate_type=aggregate_type,
            aggregate_id=aggregate_id,
            event_type=event_type,
            correlation_id=correlation_id or new_id("corr"),
            payload=payload,
        )
        return self.repo.append_event(event)

    # --- projects ---
    def create_project(
        self, name: str, repository_identity: str, *, project_id: Optional[str] = None
    ) -> Project:
        project = Project(
            project_id=project_id or new_id("proj"),
            name=name,
            repository_identity=repository_identity,
        )
        self.repo.upsert_project(project)
        self._emit(
            aggregate_type="project",
            aggregate_id=project.project_id,
            event_type="project.created",
            payload=project.to_dict(),
        )
        return project

    def list_projects(self) -> List[Project]:
        return self.repo.list_projects()

    def get_project(self, project_id: str) -> Project:
        project = self.repo.get_project(project_id)
        if not project:
            raise KeyError(f"unknown project: {project_id}")
        return project

    # --- goals ---
    def create_goal(
        self,
        project_id: str,
        title: str,
        description: str = "",
        *,
        priority: int = 100,
    ) -> Goal:
        self.get_project(project_id)
        goal = Goal(
            goal_id=new_id("goal"),
            project_id=project_id,
            title=title,
            description=description,
            priority=priority,
            approval_state="PENDING",
            lifecycle_state="DRAFT",
        )
        self.repo.insert_goal(goal)
        self._emit(
            aggregate_type="goal",
            aggregate_id=goal.goal_id,
            event_type="goal.created",
            payload=goal.to_dict(),
        )
        return goal

    def submit_goal_for_approval(self, goal_id: str) -> Goal:
        goal = self._require_goal(goal_id)
        assert_transition("goal", goal.lifecycle_state, "PENDING_APPROVAL", GOAL_TRANSITIONS)
        version = goal.version
        goal.lifecycle_state = "PENDING_APPROVAL"
        goal = self.repo.update_goal(goal, expected_version=version)
        approval = Approval(
            approval_id=new_id("appr"),
            requested_action="approve_goal",
            scope=f"goal:{goal.goal_id}",
            approver_reference="owner-synthetic",
            decision="PENDING",
            expires_at=(datetime.now(timezone.utc) + timedelta(days=7))
            .replace(microsecond=0)
            .isoformat(),
            audit_metadata={"synthetic": True},
            goal_id=goal.goal_id,
            project_id=goal.project_id,
        )
        self.repo.insert_approval(approval)
        self._emit(
            aggregate_type="goal",
            aggregate_id=goal.goal_id,
            event_type="goal.pending_approval",
            payload={"approval_id": approval.approval_id},
        )
        return goal

    def approve_goal(
        self,
        goal_id: str,
        *,
        approver: str = "owner-synthetic",
        approval_id: Optional[str] = None,
    ) -> Tuple[Goal, Approval]:
        goal = self._require_goal(goal_id)
        if goal.lifecycle_state == "DRAFT":
            goal = self.submit_goal_for_approval(goal_id)
        assert_transition("goal", goal.lifecycle_state, "APPROVED", GOAL_TRANSITIONS)
        approval = self._resolve_pending_approval(goal, approval_id)
        self._ensure_approval_usable(approval, expected_scope=f"goal:{goal.goal_id}")
        decision = self.approval_provider.decide(
            action="approve_goal",
            scope=f"goal:{goal.goal_id}",
            approver=approver,
            approve=True,
        )
        approval.decision = "APPROVED"
        approval.approver_reference = approver
        approval.audit_metadata = {**approval.audit_metadata, **decision}
        self.repo.update_approval(approval)
        version = goal.version
        goal.approval_state = "APPROVED"
        goal.lifecycle_state = "APPROVED"
        goal = self.repo.update_goal(goal, expected_version=version)
        # Activate goal
        version = goal.version
        assert_transition("goal", goal.lifecycle_state, "ACTIVE", GOAL_TRANSITIONS)
        goal.lifecycle_state = "ACTIVE"
        goal = self.repo.update_goal(goal, expected_version=version)
        self._emit(
            aggregate_type="goal",
            aggregate_id=goal.goal_id,
            event_type="goal.approved_synthetic",
            payload={"approval_id": approval.approval_id, "decision": decision},
        )
        self.recalculate_task_eligibility(project_id=goal.project_id)
        return goal, approval

    def _resolve_pending_approval(
        self, goal: Goal, approval_id: Optional[str]
    ) -> Approval:
        if approval_id:
            approval = self.repo.get_approval(approval_id)
            if not approval:
                raise KeyError(f"unknown approval: {approval_id}")
            return approval
        pending = [
            a
            for a in self.repo.list_approvals(pending_only=True)
            if a.goal_id == goal.goal_id
        ]
        if not pending:
            raise PolicyError("no pending approval for goal")
        return pending[-1]

    def _ensure_approval_usable(self, approval: Approval, *, expected_scope: str) -> None:
        if approval.decision != "PENDING":
            raise PolicyError(f"approval not pending: {approval.decision}")
        if approval.scope != expected_scope:
            raise PolicyError("approval scope mismatch")
        if approval.expires_at:
            exp = datetime.fromisoformat(approval.expires_at)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > exp:
                approval.decision = "EXPIRED"
                self.repo.update_approval(approval)
                raise PolicyError("approval expired")

    # --- tasks ---
    def create_task(
        self,
        goal_id: str,
        description: str,
        *,
        depends_on: Optional[List[str]] = None,
        task_id: Optional[str] = None,
    ) -> Task:
        goal = self._require_goal(goal_id)
        deps = list(depends_on or [])
        for dep in deps:
            dep_task = self.repo.get_task(dep)
            if not dep_task:
                raise KeyError(f"unknown dependency task: {dep}")
            if dep_task.project_id != goal.project_id:
                raise PolicyError("cross-project dependency rejected")
        task = Task(
            task_id=task_id or new_id("task"),
            goal_id=goal.goal_id,
            project_id=goal.project_id,
            description=description,
            depends_on=deps,
            lifecycle_state="PLANNED",
            execution_eligible=False,
        )
        self.repo.insert_task(task)
        self._emit(
            aggregate_type="task",
            aggregate_id=task.task_id,
            event_type="task.created",
            payload=task.to_dict(),
        )
        self.recalculate_task_eligibility(project_id=goal.project_id)
        return self.repo.get_task(task.task_id)  # type: ignore[return-value]

    def recalculate_task_eligibility(self, *, project_id: str) -> List[Task]:
        tasks = self.repo.list_tasks(project_id=project_id)
        by_id = {t.task_id: t for t in tasks}
        updated: List[Task] = []
        for task in tasks:
            if task.lifecycle_state in {"DONE", "CANCELLED", "RUNNING", "REVIEW"}:
                continue
            unmet = [
                d
                for d in task.depends_on
                if d not in by_id or by_id[d].lifecycle_state != "DONE"
            ]
            version = task.version
            if unmet:
                task.execution_eligible = False
                task.blocked_reason = f"waiting_on:{','.join(unmet)}"
                if task.lifecycle_state in {"READY", "PLANNED"}:
                    if task.lifecycle_state == "READY":
                        assert_transition("task", "READY", "BLOCKED", TASK_TRANSITIONS)
                        task.lifecycle_state = "BLOCKED"
                    elif task.lifecycle_state == "PLANNED" and unmet:
                        assert_transition("task", "PLANNED", "BLOCKED", TASK_TRANSITIONS)
                        task.lifecycle_state = "BLOCKED"
            else:
                task.blocked_reason = None
                task.execution_eligible = True
                if task.lifecycle_state in {"PLANNED", "BLOCKED", "FAILED"}:
                    target = "READY"
                    assert_transition(
                        "task", task.lifecycle_state, target, TASK_TRANSITIONS
                    )
                    task.lifecycle_state = target
            task = self.repo.update_task(task, expected_version=version)
            updated.append(task)
            by_id[task.task_id] = task
        return updated

    def list_ready_tasks(self, project_id: str) -> List[Task]:
        self.recalculate_task_eligibility(project_id=project_id)
        return [
            t
            for t in self.repo.list_tasks(project_id=project_id, state="READY")
            if t.execution_eligible
        ]

    def task_ineligibility_reason(self, task_id: str) -> Optional[str]:
        task = self._require_task(task_id)
        if task.lifecycle_state == "READY" and task.execution_eligible:
            return None
        if task.blocked_reason:
            return task.blocked_reason
        return f"state={task.lifecycle_state}"

    # --- executions ---
    def prepare_synthetic_execution(
        self, task_id: str, *, idempotency_key: Optional[str] = None
    ) -> Execution:
        task = self._require_task(task_id)
        goal = self._require_goal(task.goal_id)
        if goal.lifecycle_state != "ACTIVE":
            raise PolicyError("goal must be ACTIVE before execution")
        if goal.approval_state != "APPROVED":
            raise PolicyError("goal approval required")
        self.recalculate_task_eligibility(project_id=task.project_id)
        task = self._require_task(task_id)
        if not task.execution_eligible or task.lifecycle_state != "READY":
            raise PolicyError(
                f"task not eligible: {self.task_ineligibility_reason(task_id)}"
            )
        key = idempotency_key or f"synth:{task.task_id}:{self.repo.next_attempt_number(task_id)}"
        existing = self.repo.get_execution_by_idempotency(key)
        if existing:
            return existing
        attempt = self.repo.next_attempt_number(task.task_id)
        if attempt > self.max_attempts:
            raise PolicyError("execution retry budget exhausted")
        execution = Execution(
            execution_id=new_id("exec"),
            task_id=task.task_id,
            project_id=task.project_id,
            execution_contract_ref=f"synthetic-contract:{task.task_id}",
            runner_type="SYNTHETIC",
            attempt_number=attempt,
            status="PREPARED",
            idempotency_key=key,
            synthetic=True,
        )
        self.repo.insert_execution(execution)
        self._emit(
            aggregate_type="execution",
            aggregate_id=execution.execution_id,
            event_type="execution.prepared",
            payload=execution.to_dict(),
            correlation_id=key,
        )
        return execution

    def dispatch_execution(
        self, execution_id: str, *, live: bool = False
    ) -> Execution:
        execution = self._require_execution(execution_id)
        task = self._require_task(execution.task_id)
        if live:
            # Synthetic Owner approvals never authorize live ACP.
            if self.sandbox_gate != "PASS":
                raise PolicyError(
                    "live_execution_disabled_sandbox_not_pass"
                )
            adapter = self.live
        else:
            adapter = self.synthetic
            if execution.runner_type != "SYNTHETIC":
                raise PolicyError("non-synthetic runner requires live path")

        version = execution.version
        assert_transition("execution", execution.status, "DISPATCHED", EXECUTION_TRANSITIONS)
        execution.status = "DISPATCHED"
        execution.started_at = utc_now()
        execution = self.repo.update_execution(execution, expected_version=version)

        t_version = task.version
        assert_transition("task", task.lifecycle_state, "RUNNING", TASK_TRANSITIONS)
        task.lifecycle_state = "RUNNING"
        task = self.repo.update_task(task, expected_version=t_version)

        version = execution.version
        assert_transition("execution", execution.status, "RUNNING", EXECUTION_TRANSITIONS)
        execution.status = "RUNNING"
        execution = self.repo.update_execution(execution, expected_version=version)

        result = adapter.dispatch(
            DispatchRequest(
                execution_id=execution.execution_id,
                task_id=execution.task_id,
                project_id=execution.project_id,
                attempt_number=execution.attempt_number,
                contract_ref=execution.execution_contract_ref,
                correlation_id=execution.idempotency_key,
            )
        )
        # Evidence criteria: require at least one evidence ref on success.
        version = execution.version
        if result.ok and result.evidence:
            store_key = self.evidence.store(
                execution.execution_id, result.evidence, result.details
            )
            execution.evidence_refs = list(result.evidence) + [store_key]
            assert_transition(
                "execution", execution.status, "SUCCEEDED", EXECUTION_TRANSITIONS
            )
            execution.status = "SUCCEEDED"
            execution.ended_at = utc_now()
            execution = self.repo.update_execution(execution, expected_version=version)
            t_version = task.version
            task = self._require_task(task.task_id)
            assert_transition("task", task.lifecycle_state, "REVIEW", TASK_TRANSITIONS)
            task.lifecycle_state = "REVIEW"
            task = self.repo.update_task(task, expected_version=t_version)
            t_version = task.version
            assert_transition("task", task.lifecycle_state, "DONE", TASK_TRANSITIONS)
            task.lifecycle_state = "DONE"
            task.execution_eligible = False
            task = self.repo.update_task(task, expected_version=t_version)
            self._emit(
                aggregate_type="execution",
                aggregate_id=execution.execution_id,
                event_type="execution.succeeded_synthetic",
                payload={"evidence": execution.evidence_refs, "details": result.details},
            )
        else:
            reason = result.failure_reason or "missing_evidence_or_adapter_failure"
            # Zero exit without evidence is not success — already enforced.
            assert_transition("execution", execution.status, "FAILED", EXECUTION_TRANSITIONS)
            execution.status = "FAILED"
            execution.failure_reason = reason
            execution.evidence_refs = list(result.evidence)
            execution.ended_at = utc_now()
            execution = self.repo.update_execution(execution, expected_version=version)
            task = self._require_task(task.task_id)
            t_version = task.version
            assert_transition("task", task.lifecycle_state, "FAILED", TASK_TRANSITIONS)
            task.lifecycle_state = "FAILED"
            task.blocked_reason = reason
            task = self.repo.update_task(task, expected_version=t_version)
            self._emit(
                aggregate_type="execution",
                aggregate_id=execution.execution_id,
                event_type="execution.failed",
                payload={"reason": reason},
            )
        self.recalculate_task_eligibility(project_id=execution.project_id)
        return self._require_execution(execution.execution_id)

    def simulate_task(self, task_id: str) -> Execution:
        execution = self.prepare_synthetic_execution(task_id)
        return self.dispatch_execution(execution.execution_id, live=False)

    # --- overview / status ---
    def overview(self) -> Dict[str, Any]:
        projects = self.repo.list_projects()
        goals = self.repo.list_goals()
        tasks = self.repo.list_tasks()
        executions = self.repo.list_executions()
        events = self.repo.list_events(limit=20)
        by_state: Dict[str, int] = {}
        for t in tasks:
            by_state[t.lifecycle_state] = by_state.get(t.lifecycle_state, 0) + 1
        return {
            "projects": len(projects),
            "active_goals": sum(1 for g in goals if g.lifecycle_state == "ACTIVE"),
            "tasks_by_state": by_state,
            "pending_approvals": len(self.repo.list_approvals(pending_only=True)),
            "recent_executions": [e.to_dict() for e in executions[-10:]],
            "failed_or_blocked": [
                t.to_dict()
                for t in tasks
                if t.lifecycle_state in {"FAILED", "BLOCKED"}
            ],
            "recent_events": [e.to_dict() for e in events[-20:]],
            "sandbox_gate": self.sandbox_gate,
            "live_execution_enabled": self.sandbox_gate == "PASS",
        }

    def status_summary(self) -> Dict[str, Any]:
        return {
            "db_path": self.repo.db_path,
            "sandbox_gate": self.sandbox_gate,
            "projects": len(self.repo.list_projects()),
            "goals": len(self.repo.list_goals()),
            "tasks": len(self.repo.list_tasks()),
            "executions": len(self.repo.list_executions()),
            "events": len(self.repo.list_events(limit=10000)),
        }

    # --- demo ---
    def demo_snapshot(self, project_id: str = DEMO_PROJECT_ID) -> Dict[str, Any]:
        """Return current demo project state for dashboard/CLI inspection."""
        project = self.repo.get_project(project_id)
        if not project:
            return {"seeded": False, "project_id": project_id}
        goals = self.repo.list_goals(project_id=project_id)
        tasks = self.repo.list_tasks(project_id=project_id)
        executions = self.repo.list_executions(project_id=project_id)
        return {
            "seeded": True,
            "mode": "SYNTHETIC",
            "project": project.to_dict(),
            "goals": [g.to_dict() for g in goals],
            "tasks": [t.to_dict() for t in tasks],
            "executions": [e.to_dict() for e in executions],
            "ready_tasks": [t.task_id for t in self.list_ready_tasks(project_id)],
            "sandbox_gate": self.sandbox_gate,
            "live_execution_enabled": False,
        }

    def ensure_persistent_demo(self) -> Dict[str, Any]:
        """Idempotently seed the stable synthetic demo into the active database.

        Safe to run repeatedly. Does not authorize live ACP.
        """
        existing = self.repo.get_project(DEMO_PROJECT_ID)
        if existing:
            snap = self.demo_snapshot(DEMO_PROJECT_ID)
            snap["created"] = False
            snap["idempotent"] = True
            snap["message"] = "demo already present; returning persisted state"
            return snap

        project = self.create_project(
            "Synthetic Demo Project",
            DEMO_REPOSITORY_IDENTITY,
            project_id=DEMO_PROJECT_ID,
        )
        goal = Goal(
            goal_id=DEMO_GOAL_ID,
            project_id=project.project_id,
            title="Demonstrate control-plane workflow",
            description="Create dependent tasks and simulate execution",
            priority=100,
            approval_state="PENDING",
            lifecycle_state="DRAFT",
        )
        self.repo.insert_goal(goal)
        self._emit(
            aggregate_type="goal",
            aggregate_id=goal.goal_id,
            event_type="goal.created",
            payload=goal.to_dict(),
        )
        t1 = self.create_task(
            goal.goal_id, "First synthetic task", task_id=DEMO_TASK1_ID
        )
        t2 = self.create_task(
            goal.goal_id,
            "Second synthetic task",
            depends_on=[t1.task_id],
            task_id=DEMO_TASK2_ID,
        )
        goal, approval = self.approve_goal(goal.goal_id)
        ready = self.list_ready_tasks(project.project_id)
        if not ready or ready[0].task_id != t1.task_id:
            raise RuntimeError("expected first task READY")
        exec1 = self.simulate_task(t1.task_id)
        if exec1.status != "SUCCEEDED":
            raise RuntimeError(f"first execution failed: {exec1.failure_reason}")
        ready2 = self.list_ready_tasks(project.project_id)
        if not ready2 or ready2[0].task_id != t2.task_id:
            raise RuntimeError("expected second task READY after dependency")
        snap = self.demo_snapshot(DEMO_PROJECT_ID)
        snap.update(
            {
                "created": True,
                "idempotent": True,
                "goal_id": goal.goal_id,
                "task1_id": t1.task_id,
                "task2_id": t2.task_id,
                "execution1": exec1.to_dict(),
                "approval_id": approval.approval_id,
                "ready_after": [t.task_id for t in ready2],
                "message": "demo seeded into persistent database",
            }
        )
        return snap

    def run_demo(self, *, ephemeral: bool = True) -> Dict[str, Any]:
        """Run the synthetic demonstration.

        ephemeral=True creates a one-shot demo with generated IDs (tests/temp).
        ephemeral=False seeds the stable persistent demo (idempotent).
        """
        if not ephemeral:
            return self.ensure_persistent_demo()

        project = self.create_project(
            "Synthetic Demo Project", DEMO_REPOSITORY_IDENTITY
        )
        goal = self.create_goal(
            project.project_id,
            "Demonstrate control-plane workflow",
            "Create dependent tasks and simulate execution",
        )
        t1 = self.create_task(goal.goal_id, "First synthetic task")
        t2 = self.create_task(
            goal.goal_id, "Second synthetic task", depends_on=[t1.task_id]
        )
        goal, approval = self.approve_goal(goal.goal_id)
        ready = self.list_ready_tasks(project.project_id)
        if not ready or ready[0].task_id != t1.task_id:
            raise RuntimeError("expected first task READY")
        exec1 = self.simulate_task(t1.task_id)
        if exec1.status != "SUCCEEDED":
            raise RuntimeError(f"first execution failed: {exec1.failure_reason}")
        ready2 = self.list_ready_tasks(project.project_id)
        if not ready2 or ready2[0].task_id != t2.task_id:
            raise RuntimeError("expected second task READY after dependency")
        return {
            "project_id": project.project_id,
            "goal_id": goal.goal_id,
            "task1_id": t1.task_id,
            "task2_id": t2.task_id,
            "execution1": exec1.to_dict(),
            "approval_id": approval.approval_id,
            "ready_after": [t.task_id for t in ready2],
            "mode": "SYNTHETIC",
            "created": True,
            "idempotent": False,
        }

    # --- helpers ---
    def _require_goal(self, goal_id: str) -> Goal:
        goal = self.repo.get_goal(goal_id)
        if not goal:
            raise KeyError(f"unknown goal: {goal_id}")
        return goal

    def _require_task(self, task_id: str) -> Task:
        task = self.repo.get_task(task_id)
        if not task:
            raise KeyError(f"unknown task: {task_id}")
        return task

    def _require_execution(self, execution_id: str) -> Execution:
        execution = self.repo.get_execution(execution_id)
        if not execution:
            raise KeyError(f"unknown execution: {execution_id}")
        return execution


def dumps(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, default=str)
