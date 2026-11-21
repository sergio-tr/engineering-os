"""Application services for Engineering OS control plane."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
import json
import os

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
from engineering_os.infrastructure.evidence import (
    CACHED,
    ERROR,
    EXTERNALLY_VERIFIED,
    LIVE_READ_ONLY,
    SYNTHETIC_IN_MEMORY,
    SYNTHETIC_OCI_EXECUTED,
    UNVERIFIED,
    is_synthetic,
)
from engineering_os.infrastructure.integrations.github.github_adapter import GitHubReadOnlyRepositoryAdapter
from engineering_os.infrastructure.integrations.github.github_client import (
    DEFAULT_API_BASE,
    GitHubClientError,
    GitHubReadOnlyClient,
    HttpTransport,
    parse_repository,
)
from engineering_os.infrastructure.acp.acp_adapter import AcpExecutionAdapter
from engineering_os.infrastructure.acp.sessions.acp_session import AcpSessionManager
from engineering_os.infrastructure.acp.transports.acp_transport import (
    CursorAcpAdapter,
    DisabledLiveAcpTransport,
    InMemoryAcpTransport,
    OpenClawAcpxExecutionTransport,
)
from engineering_os.infrastructure.acp.acpx.acpx_bridge import AcpxSandboxBridge
from engineering_os.infrastructure.security.credentials.credential_provider import (
    FixtureCursorCredentialProvider,
    UnavailableCursorCredentialProvider,
)
from engineering_os.infrastructure.runtime.cursor.cursor_bridge import CursorBridge, RUNTIME_MODES
from engineering_os.infrastructure.runtime.cursor.cursor_runtime import CursorRuntimePlanner
from engineering_os.infrastructure.network.policy.network_policy import (
    FixtureAllowlistNetworkPolicy,
    UnenforcedNetworkPolicy,
)
from engineering_os.infrastructure.security.authorization.runtime_authorization import (
    RuntimeAuthorization,
    RuntimeAuthorizationVerifier,
)
from engineering_os.infrastructure.runtime.cursor.workspace_prep import WorkspacePreparer
from engineering_os.infrastructure.integrations.openclaw.gateway_client import (
    InMemoryGatewayTransport,
    OpenClawGatewayClient,
    default_gateway_client,
)
from engineering_os.infrastructure.runtime.oci.oci_acp_transport import OciAcpStdioTransport
from engineering_os.infrastructure.runtime.oci.podman_executor import (
    FixtureLaunchRequest,
    OwnerGateError,
    PodmanSandboxExecutor,
    default_injected_factory,
    probe_podman_runtime,
    require_owner_execution_gates,
    resolve_local_fixture_image,
    sha256_text,
)
from engineering_os.infrastructure.integrations.openclaw.openclaw_adapter import OpenClawCoordinatorAdapter
from engineering_os.infrastructure.integrations.openclaw.openclaw_client import OpenClawCliClient
from engineering_os.infrastructure.integrations.paperclip.paperclip_adapter import PaperclipOrganizationAdapter
from engineering_os.infrastructure.integrations.paperclip.paperclip_client import (
    DEFAULT_PAPERCLIP_URL,
    PaperclipClient,
    PaperclipClientError,
)
from engineering_os.infrastructure.runtime.sandbox.sandbox_launcher import PodmanAcpSandboxLauncher
from engineering_os.infrastructure.persistence.sqlite import Repository, default_db_path

# Stable IDs for the persistent synthetic demonstration (idempotent seed).
DEMO_PROJECT_ID = "proj-eos-mvp-demo"
DEMO_GOAL_ID = "goal-eos-mvp-demo"
DEMO_TASK1_ID = "task-eos-mvp-demo-1"
DEMO_TASK2_ID = "task-eos-mvp-demo-2"
DEMO_REPOSITORY_IDENTITY = "local/synthetic-demo"


class PolicyError(ValueError):
    pass


class ControlPlane:
    """Compatibility facade over focused application services.

    Prefer constructing via ``from_dependencies`` / ``bootstrap.open_control_plane``.
    Legacy keyword arguments remain supported for tests and callers.
    """

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
        github_transport: Optional[HttpTransport] = None,
        github_api_base: str = DEFAULT_API_BASE,
        github_token_provider: Optional[Callable[[], Optional[str]]] = None,
        paperclip_transport: Optional[HttpTransport] = None,
        paperclip_url: Optional[str] = None,
        paperclip_token_provider: Optional[Callable[[], Optional[str]]] = None,
        paperclip_company_id: Optional[str] = None,
        openclaw_client: Optional[OpenClawCliClient] = None,
        acp_scenario: str = "success",
        gateway_client: Optional[OpenClawGatewayClient] = None,
        acpx_bridge: Optional[AcpxSandboxBridge] = None,
        oci_executor: Optional[PodmanSandboxExecutor] = None,
        cursor_bridge: Optional[CursorBridge] = None,
        _deps: Optional[Any] = None,
    ) -> None:
        if _deps is not None:
            self._apply_dependencies(_deps)
            return

        from engineering_os.bootstrap import build_dependencies
        from engineering_os.config import ControlPlaneConfiguration

        deps = build_dependencies(
            repo,
            config=ControlPlaneConfiguration(
                sandbox_gate=sandbox_gate,
                max_attempts=max_attempts,
                acp_scenario=acp_scenario,
                github_api_base=github_api_base,
                paperclip_url=paperclip_url
                or os.environ.get("EOS_PAPERCLIP_URL")
                or DEFAULT_PAPERCLIP_URL,
                paperclip_company_id=paperclip_company_id
                or os.environ.get("EOS_PAPERCLIP_COMPANY_ID"),
            ),
            execution_adapter=execution_adapter,
            live_adapter=live_adapter,
            evidence=evidence,
            repo_integration=repo_integration,
            approval_provider=approval_provider,
            github_transport=github_transport,
            github_token_provider=github_token_provider,
            paperclip_transport=paperclip_transport,
            paperclip_token_provider=paperclip_token_provider,
            openclaw_client=openclaw_client,
            gateway_client=gateway_client,
            acpx_bridge=acpx_bridge,
            oci_executor=oci_executor,
            cursor_bridge=cursor_bridge,
        )
        self._apply_dependencies(deps)

    def _apply_dependencies(self, deps: Any) -> None:
        from engineering_os.application.use_cases.goals import GoalService
        from engineering_os.application.use_cases.projects import ProjectService

        self.repo = deps.repo
        self.synthetic = deps.synthetic
        self.live = deps.live
        self.evidence = deps.evidence
        self.repo_integration = deps.repo_integration
        self.approval_provider = deps.approval_provider
        self.sandbox_gate = deps.config.sandbox_gate
        self.max_attempts = deps.config.max_attempts
        self._github_transport = deps.github_transport
        self._github_api_base = deps.config.github_api_base
        self._github_token_provider = deps.github_token_provider or (
            lambda: os.environ.get("EOS_GITHUB_TOKEN") or None
        )
        self._paperclip_transport = deps.paperclip_transport
        self._paperclip_url = deps.config.paperclip_url or DEFAULT_PAPERCLIP_URL
        self._paperclip_token_provider = deps.paperclip_token_provider or (
            lambda: os.environ.get("EOS_PAPERCLIP_TOKEN") or None
        )
        self._paperclip_company_id = deps.config.paperclip_company_id
        self.openclaw = deps.openclaw
        self._acp_scenario = deps.config.acp_scenario
        self.acp = deps.acp
        self.gateway = deps.gateway
        self.acpx = deps.acpx
        self.oci = deps.oci
        self.cursor = deps.cursor
        self._deps = deps
        self._projects = ProjectService(self.repo, emit=self._emit)
        self._goals = GoalService(
            self.repo,
            self.repo,
            projects=self._projects,
            emit=self._emit,
        )

    @classmethod
    def from_dependencies(cls, deps: Any) -> "ControlPlane":
        return cls(deps.repo, _deps=deps)

    # --- factories ---
    @classmethod
    def open(cls, db_path: Optional[str | Path] = None) -> "ControlPlane":
        from engineering_os.bootstrap import open_control_plane

        return open_control_plane(db_path)

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
        return self._projects.create(
            name, repository_identity, project_id=project_id
        )

    def list_projects(self) -> List[Project]:
        return self._projects.list()

    def get_project(self, project_id: str) -> Project:
        return self._projects.get(project_id)

    # --- goals ---
    def create_goal(
        self,
        project_id: str,
        title: str,
        description: str = "",
        *,
        priority: int = 100,
    ) -> Goal:
        return self._goals.create(
            project_id, title, description, priority=priority
        )

    def submit_goal_for_approval(self, goal_id: str) -> Goal:
        return self._goals.submit_for_approval(goal_id)

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

    # --- GitHub read-only integration (EOS-04) ---
    def _runtime_github_token(self) -> Optional[str]:
        token = self._github_token_provider()
        if token is not None and not isinstance(token, str):
            raise PolicyError("invalid_token_provider_result")
        return token or None

    def _build_github_adapter(
        self, owner: str, repo: str
    ) -> GitHubReadOnlyRepositoryAdapter:
        client = GitHubReadOnlyClient(
            api_base=self._github_api_base,
            token=self._runtime_github_token(),
            transport=self._github_transport,
        )
        return GitHubReadOnlyRepositoryAdapter(client, owner=owner, repo=repo)

    def configure_github_connection(
        self, project_id: str, repository: str, *, api_base: Optional[str] = None
    ) -> Dict[str, Any]:
        self.get_project(project_id)
        owner, repo = parse_repository(repository)
        base = (api_base or self._github_api_base).rstrip("/")
        conn = self.repo.upsert_github_connection(
            {
                "project_id": project_id,
                "owner": owner,
                "repo": repo,
                "repository_identity": f"{owner}/{repo}",
                "api_base": base,
            }
        )
        self._emit(
            aggregate_type="project",
            aggregate_id=project_id,
            event_type="github.connection_configured",
            payload={
                "repository_identity": conn["repository_identity"],
                "api_base": conn["api_base"],
                "token_configured": bool(self._runtime_github_token()),
            },
        )
        # Never include token material in returned payload.
        return {
            **conn,
            "token_configured": bool(self._runtime_github_token()),
            "mode": "LIVE_READ_ONLY" if not self._github_transport else "FIXTURE",
        }

    def list_github_connections(self) -> List[Dict[str, Any]]:
        return [
            {**c, "token_configured": bool(self._runtime_github_token())}
            for c in self.repo.list_github_connections()
        ]

    def github_status(self, project_id: str) -> Dict[str, Any]:
        self.get_project(project_id)
        conn = self.repo.get_github_connection(project_id)
        latest = self.repo.latest_github_observation(project_id=project_id)
        links = self.repo.list_execution_pr_links(project_id=project_id)
        return {
            "project_id": project_id,
            "connection": conn,
            "latest_observation": latest,
            "pr_links": links,
            "sandbox_gate": self.sandbox_gate,
            "live_acp_enabled": False,
            "token_configured": bool(self._runtime_github_token()),
            "evidence_note": "GitHub observations are read-only; synthetic merges remain separate",
        }

    def sync_github_repository(self, project_id: str) -> Dict[str, Any]:
        conn = self.repo.get_github_connection(project_id)
        if not conn:
            raise PolicyError("github_connection_not_configured")
        adapter = self._build_github_adapter(conn["owner"], conn["repo"])
        meta = adapter.observe_repository()
        evidence_class = str(meta.get("evidence_class") or ERROR)
        error = meta.get("error")
        updated = self.repo.upsert_github_connection(
            {
                **conn,
                "default_branch": meta.get("default_branch"),
                "head_sha": meta.get("head_sha"),
                "last_sync_at": utc_now(),
                "last_error": error,
            }
        )
        obs = self.repo.insert_github_observation(
            {
                "observation_id": new_id("ghobs"),
                "project_id": project_id,
                "execution_id": None,
                "repository_identity": conn["repository_identity"],
                "pr_number": None,
                "evidence_class": evidence_class,
                "payload": meta,
            }
        )
        self._emit(
            aggregate_type="project",
            aggregate_id=project_id,
            event_type="github.repository_synced",
            payload={
                "repository_identity": conn["repository_identity"],
                "evidence_class": evidence_class,
                "observation_id": obs["observation_id"],
                "error": error,
            },
        )
        return {
            "connection": updated,
            "observation": obs,
            "metadata": meta,
            "token_configured": bool(self._runtime_github_token()),
        }

    def list_github_pull_requests(
        self, project_id: str, *, state: str = "all", use_cache: bool = False
    ) -> Dict[str, Any]:
        conn = self.repo.get_github_connection(project_id)
        if not conn:
            raise PolicyError("github_connection_not_configured")
        if use_cache:
            cached = self.repo.latest_github_observation(project_id=project_id)
            if cached and cached.get("payload", {}).get("pull_requests") is not None:
                payload = dict(cached["payload"])
                payload["evidence_class"] = CACHED
                payload["stale"] = cached.get("stale", False)
                return payload
        adapter = self._build_github_adapter(conn["owner"], conn["repo"])
        try:
            prs = adapter.list_pull_requests(state=state)
            evidence_class = LIVE_READ_ONLY
            error = None
        except GitHubClientError as exc:
            prs = []
            evidence_class = ERROR
            error = {"code": exc.code, "status": exc.status, "message": str(exc)}
        payload = {
            "repository_identity": conn["repository_identity"],
            "pull_requests": prs,
            "evidence_class": evidence_class,
            "error": error,
            "state_filter": state,
        }
        obs = self.repo.insert_github_observation(
            {
                "observation_id": new_id("ghobs"),
                "project_id": project_id,
                "repository_identity": conn["repository_identity"],
                "evidence_class": evidence_class,
                "payload": payload,
            }
        )
        return {**payload, "observation_id": obs["observation_id"]}

    def link_execution_to_pr(
        self,
        execution_id: str,
        pr_number: int,
        *,
        expected_base_ref: Optional[str] = None,
        expected_head_sha: Optional[str] = None,
    ) -> Dict[str, Any]:
        execution = self._require_execution(execution_id)
        conn = self.repo.get_github_connection(execution.project_id)
        if not conn:
            raise PolicyError("github_connection_not_configured")
        if pr_number <= 0:
            raise PolicyError("invalid_pr_number")
        # Explicit association only — never inferred from titles/branches.
        link = self.repo.upsert_execution_pr_link(
            {
                "execution_id": execution_id,
                "project_id": execution.project_id,
                "repository_identity": conn["repository_identity"],
                "pr_number": pr_number,
                "expected_base_ref": expected_base_ref,
                "expected_head_sha": expected_head_sha,
            }
        )
        self._emit(
            aggregate_type="execution",
            aggregate_id=execution_id,
            event_type="github.pr_linked",
            payload={
                "pr_number": pr_number,
                "repository_identity": conn["repository_identity"],
            },
        )
        return link

    def sync_linked_pull_request(self, execution_id: str) -> Dict[str, Any]:
        execution = self._require_execution(execution_id)
        link = self.repo.get_execution_pr_link(execution_id)
        if not link:
            raise PolicyError("execution_pr_link_required")
        conn = self.repo.get_github_connection(execution.project_id)
        if not conn:
            raise PolicyError("github_connection_not_configured")
        if link["repository_identity"] != conn["repository_identity"]:
            raise PolicyError("repository_mismatch")
        adapter = self._build_github_adapter(conn["owner"], conn["repo"])
        observation = adapter.observe(
            execution.project_id,
            execution_id,
            pr_number=int(link["pr_number"]),
        )
        # Validate expected associations when provided.
        details = dict(observation.details or {})
        mismatches: List[str] = []
        if link.get("expected_base_ref") and details.get("base_ref") not in {
            None,
            link["expected_base_ref"],
        }:
            mismatches.append("base_ref")
        if link.get("expected_head_sha") and details.get("head_sha") not in {
            None,
            link["expected_head_sha"],
        }:
            mismatches.append("head_sha")
        if mismatches:
            observation.evidence_class = ERROR
            details["association_mismatch"] = mismatches
            observation.details = details
        stored = self.repo.insert_github_observation(
            {
                "observation_id": new_id("ghobs"),
                "project_id": execution.project_id,
                "execution_id": execution_id,
                "repository_identity": conn["repository_identity"],
                "pr_number": int(link["pr_number"]),
                "evidence_class": observation.evidence_class,
                "payload": observation.to_dict(),
            }
        )
        self._emit(
            aggregate_type="execution",
            aggregate_id=execution_id,
            event_type="github.pr_synced",
            payload={
                "observation_id": stored["observation_id"],
                "evidence_class": observation.evidence_class,
                "pr_state": observation.pr_state,
            },
        )
        return {
            "link": link,
            "observation": stored,
            "live": observation.to_dict(),
        }

    def reconcile_github_merge(
        self, execution_id: str, *, complete_task: bool = False
    ) -> Dict[str, Any]:
        """Reconcile against a real GitHub observation path only.

        Synthetic Owner merge decisions are intentionally excluded.
        """
        execution = self._require_execution(execution_id)
        # Refuse to treat synthetic integration evidence as real.
        if execution.integration_state in {"merged_synthetic", "pr_pending"} and (
            execution.runner_type == "SYNTHETIC"
            and not self.repo.get_execution_pr_link(execution_id)
        ):
            # Still allow linking later; without an explicit PR link we cannot reconcile.
            pass
        link = self.repo.get_execution_pr_link(execution_id)
        if not link:
            raise PolicyError("execution_pr_link_required")
        synced = self.sync_linked_pull_request(execution_id)
        live = synced["live"]
        evidence_class = live.get("evidence_class")
        if is_synthetic(str(evidence_class)):
            raise PolicyError("synthetic_evidence_cannot_reconcile_github")
        if evidence_class == ERROR:
            return {
                "action": "reconcile_failed",
                "reason": "observation_error",
                "observation": synced["observation"],
            }
        if live.get("pr_state") != "merged":
            return {
                "action": "not_merged",
                "observation": synced["observation"],
                "evidence_class": evidence_class,
            }
        if not live.get("merge_commit_sha"):
            return {
                "action": "unverified",
                "reason": "missing_merge_commit_sha",
                "observation": synced["observation"],
                "evidence_class": UNVERIFIED,
            }
        # Externally verified merge observation recorded.
        version = execution.version
        execution.integration_state = "merged_github_verified"
        execution.evidence_refs = list(execution.evidence_refs) + [
            f"github-merge:{live['merge_commit_sha']}",
            f"evidence:{EXTERNALLY_VERIFIED}",
        ]
        # Mark observation provenance as externally verified for audit.
        verified = self.repo.insert_github_observation(
            {
                "observation_id": new_id("ghobs"),
                "project_id": execution.project_id,
                "execution_id": execution_id,
                "repository_identity": link["repository_identity"],
                "pr_number": int(link["pr_number"]),
                "evidence_class": EXTERNALLY_VERIFIED,
                "payload": {
                    **live,
                    "evidence_class": EXTERNALLY_VERIFIED,
                    "note": "verified against GitHub merged state + merge SHA",
                },
            }
        )
        if complete_task and execution.status == "AWAITING_INTEGRATION":
            assert_transition(
                "execution", execution.status, "SUCCEEDED", EXECUTION_TRANSITIONS
            )
            execution.status = "SUCCEEDED"
            execution.ended_at = utc_now()
            execution = self.repo.update_execution(execution, expected_version=version)
            task = self._require_task(execution.task_id)
            t_version = task.version
            if task.lifecycle_state == "RUNNING":
                assert_transition("task", "RUNNING", "REVIEW", TASK_TRANSITIONS)
                task.lifecycle_state = "REVIEW"
                task = self.repo.update_task(task, expected_version=t_version)
                t_version = task.version
            if task.lifecycle_state == "REVIEW":
                assert_transition("task", "REVIEW", "DONE", TASK_TRANSITIONS)
                task.lifecycle_state = "DONE"
                task.execution_eligible = False
                self.repo.update_task(task, expected_version=t_version)
            self.repo.clear_claim(execution.project_id)
            self.recalculate_task_eligibility(project_id=execution.project_id)
            action = "reconciled_and_completed"
        else:
            execution = self.repo.update_execution(execution, expected_version=version)
            action = "reconciled_verified"
        self._emit(
            aggregate_type="execution",
            aggregate_id=execution_id,
            event_type="github.merge_reconciled",
            payload={
                "action": action,
                "merge_commit_sha": live.get("merge_commit_sha"),
                "evidence_class": EXTERNALLY_VERIFIED,
                "observation_id": verified["observation_id"],
                "complete_task": complete_task,
            },
        )
        return {
            "action": action,
            "execution": execution.to_dict(),
            "observation": verified,
            "evidence_class": EXTERNALLY_VERIFIED,
            "synthetic_path_used": False,
        }

    def cached_github_observation(
        self, project_id: str, *, execution_id: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        obs = self.repo.latest_github_observation(
            project_id=project_id, execution_id=execution_id, include_stale=True
        )
        if not obs:
            return None
        payload = dict(obs)
        if obs.get("stale"):
            payload["evidence_class"] = CACHED
            payload["display_class"] = CACHED
        return payload

    def run_github_fixture_demo(self) -> Dict[str, Any]:
        """Offline deterministic GitHub integration demonstration."""
        if self._github_transport is None:
            raise PolicyError("fixture_transport_required_for_offline_demo")
        project = self.create_project(
            "GitHub Integration Demo", "sergio-tr/engineering-os-demo"
        )
        goal = self.create_goal(project.project_id, "Observe real PR fixtures")
        task = self.create_task(goal.goal_id, "Link and reconcile fixture PR")
        self.approve_goal(goal.goal_id)
        execution = self.simulate_task(task.task_id)
        conn = self.configure_github_connection(
            project.project_id, "sergio-tr/engineering-os"
        )
        sync = self.sync_github_repository(project.project_id)
        prs = self.list_github_pull_requests(project.project_id)
        link = self.link_execution_to_pr(
            execution.execution_id,
            42,
            expected_base_ref="main",
        )
        synced = self.sync_linked_pull_request(execution.execution_id)
        # Restart persistence check is done by caller with same DB path.
        return {
            "mode": "FIXTURE_OFFLINE",
            "project_id": project.project_id,
            "connection": conn,
            "sync": {
                "evidence_class": sync["observation"]["evidence_class"],
                "head_sha": sync["connection"].get("head_sha"),
            },
            "pull_requests": prs.get("pull_requests"),
            "link": link,
            "synced_observation": synced["observation"],
            "execution_id": execution.execution_id,
            "note": "No live GitHub network requests were performed",
        }

    # --- Paperclip / OpenClaw integrations (EOS-05) ---
    def _paperclip_client(self) -> PaperclipClient:
        return PaperclipClient(
            base_url=self._paperclip_url,
            token=self._paperclip_token_provider(),
            transport=self._paperclip_transport,
        )

    def _paperclip_adapter(
        self, company_id: Optional[str] = None
    ) -> PaperclipOrganizationAdapter:
        return PaperclipOrganizationAdapter(
            self._paperclip_client(),
            company_id=company_id or self._paperclip_company_id,
        )

    def integrations_status(self) -> Dict[str, Any]:
        return {
            "paperclip": self.paperclip_status(),
            "openclaw": self.openclaw.status(),
            "github_connections": len(self.repo.list_github_connections()),
            "sandbox_gate": self.sandbox_gate,
            "live_acp_enabled": False,
        }

    def paperclip_status(self, company_id: Optional[str] = None) -> Dict[str, Any]:
        adapter = self._paperclip_adapter(company_id)
        diag = adapter.diagnostics()
        latest = self.repo.latest_integration_observation(
            system_name="paperclip",
            company_id=company_id or self._paperclip_company_id,
            include_stale=True,
        )
        return {
            **diag,
            "configured_company_id": company_id or self._paperclip_company_id,
            "latest_observation": latest,
            "token_configured": bool(self._paperclip_token_provider()),
            "base_url": self._paperclip_url,
        }

    def paperclip_list_companies(self) -> Dict[str, Any]:
        client = self._paperclip_client()
        companies = client.list_companies()
        return {
            "companies": companies,
            "evidence_class": "LIVE_READ_ONLY",
            "client": client.redact(),
        }

    def paperclip_list_agents(self, company_id: str) -> Dict[str, Any]:
        adapter = self._paperclip_adapter(company_id)
        agents = adapter.client.list_agents(company_id)
        return {
            "company_id": company_id,
            "agents": [adapter._public_agent(a) for a in agents],
            "evidence_class": "LIVE_READ_ONLY",
        }

    def paperclip_list_issues(self, company_id: str) -> Dict[str, Any]:
        adapter = self._paperclip_adapter(company_id)
        issues = adapter.client.list_issues(company_id)
        return {
            "company_id": company_id,
            "issues": [adapter._public_issue(i) for i in issues],
            "evidence_class": "LIVE_READ_ONLY",
        }

    def paperclip_sync(
        self, company_id: str, *, project_id: Optional[str] = None
    ) -> Dict[str, Any]:
        adapter = self._paperclip_adapter(company_id)
        try:
            snap = adapter.sync_snapshot()
        except PaperclipClientError as exc:
            obs = self.repo.insert_integration_observation(
                {
                    "observation_id": new_id("iobs"),
                    "system_name": "paperclip",
                    "project_id": project_id,
                    "company_id": company_id,
                    "evidence_class": "ERROR",
                    "payload": {"error": {"code": exc.code, "message": str(exc)}},
                }
            )
            raise PolicyError(f"paperclip_sync_failed:{exc.code}") from exc
        # Persist mappings for projects/goals/issues/agents discovered.
        mapped = []
        conflicts = []
        for project in snap["projects"]:
            ext_id = str(project.get("id"))
            if project.get("companyId") not in {None, company_id}:
                conflicts.append({"kind": "project", "id": ext_id, "reason": "cross_company"})
                continue
            if project_id:
                mapping = self.repo.upsert_external_mapping(
                    {
                        "mapping_id": new_id("map"),
                        "system_name": "paperclip",
                        "company_id": company_id,
                        "local_kind": "project",
                        "local_id": project_id,
                        "external_id": ext_id,
                        "evidence_class": "LIVE_READ_ONLY",
                        "payload": project,
                        "correlation_id": new_id("corr"),
                    }
                )
                mapped.append(mapping)
        for goal in snap["goals"]:
            self.repo.upsert_external_mapping(
                {
                    "mapping_id": new_id("map"),
                    "system_name": "paperclip",
                    "company_id": company_id,
                    "local_kind": "goal_external",
                    "local_id": f"ext-goal:{goal.get('id')}",
                    "external_id": str(goal.get("id")),
                    "evidence_class": "LIVE_READ_ONLY",
                    "payload": goal,
                }
            )
        for agent in snap["agents"]:
            self.repo.upsert_external_mapping(
                {
                    "mapping_id": new_id("map"),
                    "system_name": "paperclip",
                    "company_id": company_id,
                    "local_kind": "agent",
                    "local_id": f"ext-agent:{agent.get('id')}",
                    "external_id": str(agent.get("id")),
                    "evidence_class": "LIVE_READ_ONLY",
                    "payload": agent,
                }
            )
        for issue in snap["issues"]:
            self.repo.upsert_external_mapping(
                {
                    "mapping_id": new_id("map"),
                    "system_name": "paperclip",
                    "company_id": company_id,
                    "local_kind": "issue",
                    "local_id": f"ext-issue:{issue.get('id')}",
                    "external_id": str(issue.get("id")),
                    "external_revision": issue.get("updatedAt"),
                    "evidence_class": "LIVE_READ_ONLY",
                    "payload": issue,
                }
            )
        obs = self.repo.insert_integration_observation(
            {
                "observation_id": new_id("iobs"),
                "system_name": "paperclip",
                "project_id": project_id,
                "company_id": company_id,
                "evidence_class": snap["evidence_class"],
                "payload": {
                    "agents": len(snap["agents"]),
                    "projects": len(snap["projects"]),
                    "goals": len(snap["goals"]),
                    "issues": len(snap["issues"]),
                    "approvals": len(snap["approvals"]),
                    "org": snap["org"],
                    "company": snap["company"],
                    "issues_detail": snap["issues"],
                    "agents_detail": snap["agents"],
                    "projects_detail": snap["projects"],
                    "goals_detail": snap["goals"],
                    "approvals_detail": snap["approvals"],
                },
            }
        )
        self._emit(
            aggregate_type="integration",
            aggregate_id=company_id,
            event_type="paperclip.synced",
            payload={
                "observation_id": obs["observation_id"],
                "mapped": len(mapped),
                "conflicts": conflicts,
            },
        )
        return {
            "snapshot": {
                "company": snap["company"],
                "counts": {
                    "agents": len(snap["agents"]),
                    "projects": len(snap["projects"]),
                    "goals": len(snap["goals"]),
                    "issues": len(snap["issues"]),
                    "approvals": len(snap["approvals"]),
                },
                "evidence_class": snap["evidence_class"],
            },
            "observation": obs,
            "mappings": mapped,
            "conflicts": conflicts,
            "agents": snap["agents"],
            "issues": snap["issues"],
            "projects": snap["projects"],
            "goals": snap["goals"],
            "approvals": snap["approvals"],
            "org": snap["org"],
        }

    def paperclip_link_project(
        self, local_project_id: str, external_project_id: str, *, company_id: str
    ) -> Dict[str, Any]:
        self.get_project(local_project_id)
        existing = self.repo.get_external_mapping(
            "paperclip", "project", local_project_id
        )
        if existing and existing["external_id"] != external_project_id:
            if existing.get("company_id") != company_id:
                raise PolicyError("cross_company_mapping_rejected")
            raise PolicyError("duplicate_project_mapping_conflict")
        mapping = self.repo.upsert_external_mapping(
            {
                "mapping_id": new_id("map"),
                "system_name": "paperclip",
                "company_id": company_id,
                "local_kind": "project",
                "local_id": local_project_id,
                "external_id": external_project_id,
                "evidence_class": "LIVE_READ_ONLY",
                "payload": {"linked_by": "owner"},
                "correlation_id": new_id("corr"),
            }
        )
        self._emit(
            aggregate_type="project",
            aggregate_id=local_project_id,
            event_type="paperclip.project_linked",
            payload={
                "external_id": external_project_id,
                "company_id": company_id,
            },
        )
        return mapping

    def paperclip_create_issue(
        self,
        company_id: str,
        payload: Dict[str, Any],
        *,
        apply: bool = False,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        client = self._paperclip_client()
        key = idempotency_key or new_id("pciss")
        # Duplicate suppression via mapping of correlation key.
        prior = self.repo.get_external_mapping(
            "paperclip", "issue_create", key
        )
        if prior and apply:
            return {
                "suppressed_duplicate": True,
                "existing": prior,
                "dry_run": False,
            }
        result = client.create_issue(
            company_id, payload, apply=apply, idempotency_key=key
        )
        if apply and not result.get("dry_run"):
            issue = result.get("issue") or {}
            self.repo.upsert_external_mapping(
                {
                    "mapping_id": new_id("map"),
                    "system_name": "paperclip",
                    "company_id": company_id,
                    "local_kind": "issue_create",
                    "local_id": key,
                    "external_id": str(issue.get("id") or key),
                    "evidence_class": "LIVE_READ_ONLY",
                    "payload": {"issue": issue, "note": "owner_apply_only"},
                    "correlation_id": key,
                }
            )
        # Never start agents / heartbeats / spending — create issue only.
        result["agent_work_triggered"] = False
        result["token_configured"] = bool(self._paperclip_token_provider())
        return result

    def openclaw_refresh(self) -> Dict[str, Any]:
        observation = self.openclaw.refresh()
        obs = self.repo.insert_integration_observation(
            {
                "observation_id": new_id("iobs"),
                "system_name": "openclaw",
                "evidence_class": observation.get("evidence_class") or "UNAVAILABLE",
                "payload": observation,
            }
        )
        self._emit(
            aggregate_type="integration",
            aggregate_id="openclaw",
            event_type="openclaw.refreshed",
            payload={"observation_id": obs["observation_id"]},
        )
        return {"observation": obs, "status": observation}

    def openclaw_status(self) -> Dict[str, Any]:
        latest = self.repo.latest_integration_observation(
            system_name="openclaw", include_stale=True
        )
        return {
            **self.openclaw.status(),
            "latest_observation": latest,
            "live_dispatch_permitted": False,
        }

    def orchestration_plan(self, project_id: str) -> Dict[str, Any]:
        from engineering_os.application.orchestrator import SequentialOrchestrator

        orch = SequentialOrchestrator(self)
        return orch.build_plan(project_id)

    # --- ACP / Cursor (EOS-06) ---
    def acp_status(self) -> Dict[str, Any]:
        return {
            **self.acp.runtime_status(),
            "sessions": len(self.repo.list_acp_sessions()),
        }

    def acp_capabilities(self) -> Dict[str, Any]:
        return {
            "protocol_version_supported": 1,
            "methods": [
                "initialize",
                "authenticate",
                "session/new",
                "session/prompt",
                "session/cancel",
                "session/update",
                "session/request_permission",
            ],
            "permission_policy": "deny_by_default",
            "live_transport": self.acp.select_transport(live=True).availability().to_dict(),
            "synthetic_transport": InMemoryAcpTransport().availability().to_dict(),
            "openclaw_acpx": OpenClawAcpxExecutionTransport().availability().to_dict(),
            "direct_process_bypass": "rejected_without_sandbox_authorization",
        }

    def list_acp_sessions(self, project_id: Optional[str] = None) -> List[Dict[str, Any]]:
        return self.repo.list_acp_sessions(project_id=project_id)

    def get_acp_session_for_execution(self, execution_id: str) -> Dict[str, Any]:
        session = self.repo.get_acp_session_by_execution(execution_id)
        if not session:
            raise KeyError(f"unknown acp session for execution: {execution_id}")
        events = self.repo.list_acp_events(session["session_id"])
        return {"session": session, "events": events, "mode": "SYNTHETIC"}

    def cancel_acp_session(self, execution_id: str, *, synthetic: bool = True) -> Dict[str, Any]:
        session = self.repo.get_acp_session_by_execution(execution_id)
        if not session:
            raise KeyError(f"unknown acp session for execution: {execution_id}")
        transport = InMemoryAcpTransport(scenario="success")
        manager = AcpSessionManager(self.repo, transport, sandbox_gate=self.sandbox_gate)
        updated = manager.cancel(session, synthetic=synthetic)
        return updated

    def request_live_acp_transport(self) -> Dict[str, Any]:
        """Demonstrate live ACP rejection while SANDBOX is unapproved."""
        # Do not trust caller-supplied gate strings — only self.sandbox_gate.
        transport = self.acp.select_transport(live=True)
        avail = transport.availability()
        try:
            transport.send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            rejected = False
            error = None
        except Exception as exc:  # noqa: BLE001
            rejected = True
            error = str(exc)
        return {
            "rejected": rejected or not avail.available,
            "availability": avail.to_dict(),
            "sandbox_gate": self.sandbox_gate,
            "error": error,
            "note": "live ACP cannot start while SANDBOX is NOT_TESTED",
        }

    def simulate_acp_task(self, task_id: str) -> Dict[str, Any]:
        """Prepare execution and dispatch through synthetic ACP adapter."""
        execution = self.prepare_synthetic_execution(task_id)
        # Use ACP adapter instead of default synthetic executor.
        task = self._require_task(task_id)
        version = execution.version
        from engineering_os.domain.states import EXECUTION_TRANSITIONS, TASK_TRANSITIONS

        assert_transition("execution", execution.status, "DISPATCHED", EXECUTION_TRANSITIONS)
        execution.status = "DISPATCHED"
        execution.started_at = utc_now()
        execution.runner_type = "ACP_SYNTHETIC"
        execution = self.repo.update_execution(execution, expected_version=version)

        t_version = task.version
        assert_transition("task", task.lifecycle_state, "RUNNING", TASK_TRANSITIONS)
        task.lifecycle_state = "RUNNING"
        task = self.repo.update_task(task, expected_version=t_version)

        version = execution.version
        assert_transition("execution", execution.status, "RUNNING", EXECUTION_TRANSITIONS)
        execution.status = "RUNNING"
        execution = self.repo.update_execution(execution, expected_version=version)

        result = self.acp.dispatch(
            DispatchRequest(
                execution_id=execution.execution_id,
                task_id=execution.task_id,
                project_id=execution.project_id,
                attempt_number=execution.attempt_number,
                contract_ref=execution.execution_contract_ref,
                correlation_id=execution.idempotency_key,
            )
        )
        version = execution.version
        if result.ok and result.evidence:
            store_key = self.evidence.store(
                execution.execution_id, result.evidence, result.details
            )
            execution.evidence_refs = list(result.evidence) + [store_key]
            assert_transition(
                "execution", execution.status, "AWAITING_INTEGRATION", EXECUTION_TRANSITIONS
            )
            execution.status = "AWAITING_INTEGRATION"
            execution.integration_state = "pr_pending"
            execution = self.repo.update_execution(execution, expected_version=version)
            self.repo_integration.simulate_pr(execution.project_id, execution.execution_id)
            self.repo_integration.complete_ci(execution.execution_id, success=True)
            self._emit(
                aggregate_type="execution",
                aggregate_id=execution.execution_id,
                event_type="execution.acp_synthetic_awaiting_integration",
                payload={
                    "evidence": execution.evidence_refs,
                    "acp": result.details,
                    "note": "synthetic ACP success is not real Cursor execution",
                },
            )
        else:
            assert_transition("execution", execution.status, "FAILED", EXECUTION_TRANSITIONS)
            execution.status = "FAILED"
            execution.failure_reason = result.failure_reason
            execution.ended_at = utc_now()
            execution = self.repo.update_execution(execution, expected_version=version)
            task = self._require_task(task.task_id)
            t_version = task.version
            assert_transition("task", task.lifecycle_state, "FAILED", TASK_TRANSITIONS)
            task.lifecycle_state = "FAILED"
            self.repo.update_task(task, expected_version=t_version)
            self._emit(
                aggregate_type="execution",
                aggregate_id=execution.execution_id,
                event_type="execution.acp_synthetic_failed",
                payload={"reason": result.failure_reason},
            )
        session = self.repo.get_acp_session_by_execution(execution.execution_id)
        return {
            "execution": execution.to_dict(),
            "session": session,
            "dispatch": {
                "ok": result.ok,
                "status": result.status,
                "details": result.details,
            },
            "mode": "SYNTHETIC",
        }

    def run_acp_fixture_demo(self) -> Dict[str, Any]:
        project = self.create_project("ACP Demo Project", "local/acp-demo")
        goal = self.create_goal(project.project_id, "Demonstrate synthetic ACP")
        t1 = self.create_task(goal.goal_id, "ACP synthetic task")
        t2 = self.create_task(goal.goal_id, "Follow-up task", depends_on=[t1.task_id])
        self.approve_goal(goal.goal_id)
        simulated = self.simulate_acp_task(t1.task_id)
        execution_id = simulated["execution"]["execution_id"]
        if simulated["execution"]["status"] != "AWAITING_INTEGRATION":
            raise RuntimeError("expected ACP execution awaiting integration")
        from engineering_os.application.orchestrator import SequentialOrchestrator

        orch = SequentialOrchestrator(self)
        # Claim for integration completion path
        self.repo.set_claim(
            project.project_id,
            execution_id=execution_id,
            task_id=t1.task_id,
            claim_token="acp-demo",
        )
        integrated = orch.complete_integration(execution_id, approve_merge=True)
        live_reject = self.request_live_acp_transport()
        return {
            "mode": "ACP_FIXTURE_OFFLINE",
            "project_id": project.project_id,
            "task1_id": t1.task_id,
            "task2_id": t2.task_id,
            "simulated": simulated,
            "integration": {
                "action": integrated.get("action"),
                "evidence_class": integrated.get("evidence_class"),
            },
            "ready_after": [t.task_id for t in self.list_ready_tasks(project.project_id)],
            "live_acp_rejected": live_reject,
            "note": "Synthetic ACP and synthetic merge only; not real Cursor/GitHub",
        }

    def run_eos05_fixture_demo(self) -> Dict[str, Any]:
        if self._paperclip_transport is None:
            raise PolicyError("paperclip_fixture_transport_required")
        from engineering_os.infrastructure.eos05_fixtures import COMPANY_ID, PROJECT_EXT

        project = self.create_project("EOS-05 Demo", "local/eos05")
        goal = self.create_goal(project.project_id, "Integrate Paperclip/OpenClaw")
        t1 = self.create_task(goal.goal_id, "Import org observations")
        t2 = self.create_task(
            goal.goal_id, "Plan orchestration", depends_on=[t1.task_id]
        )
        self.approve_goal(goal.goal_id)
        self.paperclip_link_project(project.project_id, PROJECT_EXT, company_id=COMPANY_ID)
        sync = self.paperclip_sync(COMPANY_ID, project_id=project.project_id)
        oc = self.openclaw_refresh()
        plan = self.orchestration_plan(project.project_id)
        return {
            "mode": "FIXTURE_OFFLINE",
            "project_id": project.project_id,
            "task1_id": t1.task_id,
            "task2_id": t2.task_id,
            "paperclip_sync": sync["snapshot"],
            "openclaw": {
                "evidence_class": oc["status"].get("evidence_class"),
                "installation_available": oc["status"].get("installation_available"),
            },
            "plan": plan,
            "live_acp_enabled": False,
            "note": "No live Paperclip/OpenClaw network or process calls in fixture mode",
        }

    # --- EOS-07 runtime / ACPX / sandbox bridge ---
    def runtime_status(self) -> Dict[str, Any]:
        return self.acpx.runtime_status()

    def runtime_inspect(self) -> Dict[str, Any]:
        return self.acpx.inspect()

    def sandbox_readiness(self) -> Dict[str, Any]:
        return self.acpx.sandbox.readiness()

    def sandbox_plan(self, execution_id: str) -> Dict[str, Any]:
        prep = self.repo.get_runtime_preparation_by_execution(execution_id)
        if prep:
            return {
                "preparation": prep,
                "launch_plan": prep.get("launch_plan_json"),
                "real_launch_blocked": True,
            }
        execution = self.repo.get_execution(execution_id)
        if not execution:
            raise KeyError(f"unknown execution: {execution_id}")
        spec = self.acpx.build_spec_for_execution(
            execution_id=execution.execution_id,
            project_id=execution.project_id,
            task_id=execution.task_id,
            correlation_id=execution.idempotency_key,
            idempotency_key=execution.idempotency_key,
        )
        plan = self.acpx.sandbox.plan(spec)
        return {
            "spec": spec.to_dict(),
            "launch_plan": plan.to_dict(),
            "real_launch_blocked": True,
        }

    def acpx_status(self) -> Dict[str, Any]:
        return {
            **self.runtime_status(),
            "bypass_sessions_spawn": self.acpx.reject_sessions_spawn_bypass(),
        }

    def acpx_sessions(self, project_id: Optional[str] = None) -> List[Dict[str, Any]]:
        return self.repo.list_runtime_preparations(project_id=project_id)

    def acpx_prepare(self, execution_id: str) -> Dict[str, Any]:
        execution = self.repo.get_execution(execution_id)
        if not execution:
            raise KeyError(f"unknown execution: {execution_id}")
        return self.acpx.prepare(
            DispatchRequest(
                execution_id=execution.execution_id,
                task_id=execution.task_id,
                project_id=execution.project_id,
                attempt_number=execution.attempt_number,
                contract_ref=execution.execution_contract_ref,
                correlation_id=execution.idempotency_key,
            )
        )

    def prepare_acpx_task(self, task_id: str) -> Dict[str, Any]:
        """Prepare execution through ACPX sandbox bridge (awaiting authorized dispatch)."""
        execution = self.prepare_synthetic_execution(task_id)
        prepared = self.acpx.prepare(
            DispatchRequest(
                execution_id=execution.execution_id,
                task_id=execution.task_id,
                project_id=execution.project_id,
                attempt_number=execution.attempt_number,
                contract_ref=execution.execution_contract_ref,
                correlation_id=execution.idempotency_key,
            )
        )
        self._emit(
            aggregate_type="execution",
            aggregate_id=execution.execution_id,
            event_type="execution.acpx_prepared",
            payload={
                "preparation_id": prepared["preparation"]["preparation_id"],
                "real_launch_blocked": True,
                "status": prepared["preparation"]["status"],
            },
        )
        return {
            "execution": execution.to_dict(),
            "prepared": prepared,
            "mode": "READY_FOR_AUTHORIZATION",
        }

    def run_acpx_fixture_demo(self) -> Dict[str, Any]:
        """Offline EOS-07 demo: prepare real-shaped path, block live, run mock sandbox+ACP."""
        # Fixture gateway (authenticated operator.read) + sandbox launcher.
        gateway = OpenClawGatewayClient(
            transport=InMemoryGatewayTransport(scenario="success")
        )
        gateway.connect()
        auth = RuntimeAuthorizationVerifier(
            secret=b"eos07-test-only-secret",
            issuance_enabled=True,
        )
        bridge = AcpxSandboxBridge(
            self.repo,
            gateway=gateway,
            sandbox=PodmanAcpSandboxLauncher(),
            auth_verifier=auth,
            sandbox_gate=self.sandbox_gate,
        )
        self.gateway = gateway
        self.acpx = bridge

        project = self.create_project("ACPX Bridge Demo", "local/acpx-demo")
        goal = self.create_goal(project.project_id, "Prepare sandbox ACP bridge")
        t1 = self.create_task(goal.goal_id, "ACPX prepared task")
        t2 = self.create_task(goal.goal_id, "Follow-up after integration", depends_on=[t1.task_id])
        self.approve_goal(goal.goal_id)

        prepared = self.prepare_acpx_task(t1.task_id)
        execution_id = prepared["execution"]["execution_id"]
        prep_record = prepared["prepared"]["preparation"]

        # Real launch must remain blocked.
        real_attempt = bridge.sandbox.launch(
            bridge.build_spec_for_execution(
                execution_id=execution_id,
                project_id=project.project_id,
                task_id=t1.task_id,
                correlation_id=execution_id,
                idempotency_key=execution_id,
            ),
            mode="REAL",
        )
        bypass = bridge.reject_sessions_spawn_bypass()

        # Synthetic continuation through mock sandbox + ACP session manager.
        dispatch = bridge.run_synthetic_prepared(prep_record, acp_scenario="success")
        if not dispatch.ok:
            raise RuntimeError(f"synthetic bridge failed: {dispatch.failure_reason}")

        # Advance execution through legal lifecycle to integration checkpoint.
        execution = self.repo.get_execution(execution_id)
        assert execution is not None
        task = self._require_task(t1.task_id)
        t_version = task.version
        assert_transition("task", task.lifecycle_state, "RUNNING", TASK_TRANSITIONS)
        task.lifecycle_state = "RUNNING"
        task = self.repo.update_task(task, expected_version=t_version)

        version = execution.version
        assert_transition("execution", execution.status, "DISPATCHED", EXECUTION_TRANSITIONS)
        execution.status = "DISPATCHED"
        execution.started_at = utc_now()
        execution.runner_type = "ACPX_BRIDGE_SYNTHETIC"
        execution = self.repo.update_execution(execution, expected_version=version)

        version = execution.version
        assert_transition("execution", execution.status, "RUNNING", EXECUTION_TRANSITIONS)
        execution.status = "RUNNING"
        execution = self.repo.update_execution(execution, expected_version=version)

        version = execution.version
        store_key = self.evidence.store(
            execution.execution_id, dispatch.evidence, dispatch.details
        )
        execution.evidence_refs = list(dispatch.evidence) + [store_key]
        assert_transition(
            "execution", execution.status, "AWAITING_INTEGRATION", EXECUTION_TRANSITIONS
        )
        execution.status = "AWAITING_INTEGRATION"
        execution.integration_state = "pr_pending"
        execution = self.repo.update_execution(execution, expected_version=version)
        self.repo_integration.simulate_pr(execution.project_id, execution.execution_id)
        self.repo_integration.complete_ci(execution.execution_id, success=True)

        from engineering_os.application.orchestrator import SequentialOrchestrator

        orch = SequentialOrchestrator(self)
        self.repo.set_claim(
            project.project_id,
            execution_id=execution_id,
            task_id=t1.task_id,
            claim_token="acpx-demo",
        )
        integrated = orch.complete_integration(execution_id, approve_merge=True)

        return {
            "mode": "ACPX_FIXTURE_OFFLINE",
            "project_id": project.project_id,
            "task1_id": t1.task_id,
            "task2_id": t2.task_id,
            "prepared": prepared,
            "real_launch": real_attempt.to_dict(),
            "bypass_rejected": bypass,
            "dispatch": {
                "ok": dispatch.ok,
                "status": dispatch.status,
                "details": dispatch.details,
            },
            "integration": {
                "action": integrated.get("action"),
                "evidence_class": integrated.get("evidence_class"),
            },
            "ready_after": [t.task_id for t in self.list_ready_tasks(project.project_id)],
            "runtime": self.runtime_status(),
            "note": "No containers, Gateway WS, ACPX or Cursor processes were started",
        }

    # --- EOS-08 OCI ACP fixture ---
    def sandbox_fixture_readiness(self) -> Dict[str, Any]:
        return self.oci.readiness()

    def sandbox_fixture_plan(
        self,
        *,
        execution_id: Optional[str] = None,
        image_ref: str = "localhost/alpine:eos-fixture",
    ) -> Dict[str, Any]:
        if execution_id:
            execution = self.repo.get_execution(execution_id)
            if not execution:
                raise KeyError(f"unknown execution: {execution_id}")
            req = FixtureLaunchRequest(
                execution_id=execution.execution_id,
                project_id=execution.project_id,
                task_id=execution.task_id,
                image_ref=image_ref,
                image_digest=None,
                correlation_id=execution.idempotency_key,
            )
        else:
            req = FixtureLaunchRequest(
                execution_id="exec-plan-only",
                project_id="proj-plan",
                task_id="task-plan",
                image_ref=image_ref,
                image_digest=None,
                correlation_id="plan-only",
            )
        plan = self.oci.plan(req)
        return {"plan": plan.to_dict(), "readiness": self.oci.readiness()}

    def sandbox_fixture_history(self, project_id: Optional[str] = None) -> List[Dict[str, Any]]:
        return self.repo.list_oci_fixture_runs(project_id=project_id)

    def run_oci_acp_fixture(
        self,
        *,
        execute: bool = False,
        allow_phase_b: bool = False,
        owner_authorize_runtime_execution: bool = False,
        dry_run: bool = True,
        image_ref: str = "localhost/alpine:eos-fixture",
        scenario: str = "success",
        use_injected: bool = False,
    ) -> Dict[str, Any]:
        """Run ACP fixture through OCI executor + AcpSessionManager.

        Real Podman requires the Owner triple-gate and use_injected=False.
        Offline demos/tests pass use_injected=True to keep the process factory.
        """
        owner_real = bool(execute and not dry_run and not use_injected)
        probe = probe_podman_runtime()
        if image_ref in {"localhost/alpine:eos-fixture", "", None}:
            image_ref = (
                probe.get("image_ref")
                or resolve_local_fixture_image()
                or "localhost/alpine:eos-fixture"
            )
        if owner_real:
            require_owner_execution_gates(
                execute=execute,
                allow_phase_b=allow_phase_b,
                owner_authorize_runtime_execution=owner_authorize_runtime_execution,
            )
            if image_ref == "localhost/alpine:eos-fixture" or not image_ref:
                raise PolicyError("required_local_alpine_or_busybox_image_absent")
            if probe.get("rootless") is not True:
                raise PolicyError(
                    f"podman_rootless_required:{probe.get('rootless')}:{probe.get('error')}"
                )
            # Owner triple-gate selects the real Podman path (not injected).
            self.oci = PodmanSandboxExecutor(
                process_factory=None,
                allow_real_podman=True,
                podman_info_runner=lambda: probe,
                code_revision="eos08-owner",
                expected_image_digest=None,
            )
        elif self.oci.process_factory is not None:
            # Offline/demo paths keep the injected fixture peer.
            self.oci.process_factory = default_injected_factory(scenario)

        project = self.create_project("OCI ACP Fixture", "local/oci-fixture")
        goal = self.create_goal(project.project_id, "OCI fixture ACP session")
        task = self.create_task(goal.goal_id, "Run sandboxed ACP fixture")
        self.approve_goal(goal.goal_id)
        execution = self.prepare_synthetic_execution(task.task_id)

        # Idempotency: refuse duplicate active OCI run for same execution.
        existing = self.repo.get_oci_fixture_run_by_execution(execution.execution_id)
        if existing and existing["status"] in {"RUNNING", "STARTING"}:
            return {
                "action": "duplicate_suppressed",
                "run": existing,
                "evidence_class": existing["provenance"],
            }

        req = FixtureLaunchRequest(
            execution_id=execution.execution_id,
            project_id=project.project_id,
            task_id=task.task_id,
            image_ref=image_ref,
            image_digest=None,
            correlation_id=execution.idempotency_key,
        )

        start = self.oci.start(
            req,
            execute=execute and not dry_run,
            allow_phase_b=allow_phase_b,
            owner_authorize_runtime_execution=owner_authorize_runtime_execution,
            dry_run=dry_run or not execute,
        )
        if not start.get("started"):
            return {
                "action": start.get("action"),
                "dry_run": start,
                "execution": execution.to_dict(),
                "project_id": project.project_id,
                "live_cursor_acp": False,
            }

        handle = self.oci.last_handle
        assert handle is not None
        provenance = start["evidence_class"]
        run = {
            "run_id": new_id("ocirun"),
            "execution_id": execution.execution_id,
            "project_id": project.project_id,
            "task_id": task.task_id,
            "acp_session_id": None,
            "container_id": handle.container_id,
            "code_revision": start.get("code_revision") or "unknown",
            "image_ref": image_ref,
            "image_digest": None,
            "applied_limits": {
                "memory": req.memory_limit,
                "cpu": req.cpu_limit,
                "pids": req.pids_limit,
                "wall_clock": req.wall_clock_seconds,
                "tmpfs": req.tmpfs_size,
            },
            "runtime_controls": start["plan"]["controls"],
            "exit_code": None,
            "timeout_or_cancel": None,
            "exchange_summary": {},
            "host_observations": {"rootless_policy": True, "network": "none"},
            "cleanup_status": None,
            "evidence_refs": [],
            "evidence_hashes": {},
            "provenance": provenance,
            "status": "RUNNING",
            "failure_reason": None,
            "correlation_id": execution.idempotency_key,
            "created_at": utc_now(),
            "started_at": utc_now(),
            "completed_at": None,
        }
        run = self.repo.insert_oci_fixture_run(run)

        transport = OciAcpStdioTransport(handle, evidence_class=provenance)
        manager = AcpSessionManager(
            self.repo, transport, sandbox_gate=self.sandbox_gate
        )
        session = manager.create_session_record(
            execution_id=execution.execution_id,
            project_id=project.project_id,
            task_id=task.task_id,
            agent_id="eos-acp-fixture",
            backend="oci-fixture",
            transport_type=transport.name,
            correlation_id=execution.idempotency_key,
        )
        protocol_completed = False
        try:
            session = manager.run_to_completion(
                session,
                prompt_text="EOS-08 OCI ACP fixture prompt",
                mode="SYNTHETIC",
            )
            protocol_completed = session.get("status") == "COMPLETED"
            transport.mark_protocol_completed(protocol_completed)
        finally:
            # Graceful lifecycle: EOF/stdin → SIGTERM → SIGKILL only as fallback.
            cleanup = handle.cleanup(grace_seconds=2.0)
            result = handle.wait(timeout=1.0)
            transport.mark_protocol_completed(protocol_completed)
            if not transport.close_outcome():
                # Mirror close accounting when session manager did not close yet.
                transport.protocol_completed = protocol_completed
                transport.exit_code = cleanup.get("exit_code", result.returncode)
                transport.process_exited_cleanly = bool(
                    cleanup.get("process_exited_cleanly", result.process_exited_cleanly)
                )
                transport.termination_reason = cleanup.get(
                    "termination_reason", result.termination_reason
                )
                transport.cleanup_verified = bool(
                    cleanup.get("cleanup_verified", cleanup.get("cleaned_up"))
                )

        protocol_completed = session.get("status") == "COMPLETED"
        process_exited_cleanly = bool(
            cleanup.get("process_exited_cleanly", result.process_exited_cleanly)
        )
        termination_reason = cleanup.get(
            "termination_reason", result.termination_reason
        )
        cleanup_verified = bool(
            cleanup.get("cleanup_verified", cleanup.get("cleaned_up"))
        )
        exit_code = cleanup.get("exit_code", result.returncode)

        run["acp_session_id"] = session["session_id"]
        run["exit_code"] = exit_code
        run["timeout_or_cancel"] = (
            "timeout" if result.timed_out else ("cancelled" if result.cancelled else None)
        )
        run["exchange_summary"] = {
            **transport.summary(),
            "protocol_completed": protocol_completed,
            "process_exited_cleanly": process_exited_cleanly,
            "termination_reason": termination_reason,
            "cleanup_verified": cleanup_verified,
            "exit_code": exit_code,
        }
        run["cleanup_status"] = "ok" if cleanup.get("cleaned_up") else "failed"
        run["host_observations"] = {
            **run["host_observations"],
            "cleanup": cleanup,
            "stderr_bytes": len(handle.stderr_text.encode("utf-8")),
            "lifecycle": {
                "protocol_completed": protocol_completed,
                "process_exited_cleanly": process_exited_cleanly,
                "exit_code": exit_code,
                "termination_reason": termination_reason,
                "cleanup_verified": cleanup_verified,
                "sigkill_used": bool(cleanup.get("sigkill_used")),
            },
        }
        evidence = list(session.get("evidence_refs") or []) + [
            f"oci-run:{run['run_id']}",
            f"container:{handle.container_id}",
        ]
        run["evidence_refs"] = evidence
        run["evidence_hashes"] = {
            "exchange": sha256_text(str(transport.summary())),
            "controls": sha256_text(str(run["runtime_controls"])),
        }
        # Protocol success is independent of clean process exit (EOS-08 exit -9 fix).
        if protocol_completed and run["cleanup_status"] == "ok":
            run["status"] = "COMPLETED"
            if not process_exited_cleanly:
                run["failure_reason"] = None
                run["host_observations"]["lifecycle_note"] = (
                    "protocol_completed_with_nonclean_process_exit"
                )
        else:
            run["status"] = "FAILED"
            run["failure_reason"] = session.get("failure_reason") or run["timeout_or_cancel"]
        run["completed_at"] = utc_now()
        run = self.repo.update_oci_fixture_run(run)

        # Advance execution lifecycle without claiming GitHub verification.
        version = execution.version
        assert_transition("execution", execution.status, "DISPATCHED", EXECUTION_TRANSITIONS)
        execution.status = "DISPATCHED"
        execution.started_at = utc_now()
        execution.runner_type = "OCI_ACP_FIXTURE"
        execution = self.repo.update_execution(execution, expected_version=version)
        version = execution.version
        assert_transition("execution", execution.status, "RUNNING", EXECUTION_TRANSITIONS)
        execution.status = "RUNNING"
        execution = self.repo.update_execution(execution, expected_version=version)
        version = execution.version
        if run["status"] == "COMPLETED":
            store_key = self.evidence.store(
                execution.execution_id, evidence, {"oci_run": run["run_id"]}
            )
            execution.evidence_refs = evidence + [store_key]
            assert_transition(
                "execution", execution.status, "SUCCEEDED", EXECUTION_TRANSITIONS
            )
            execution.status = "SUCCEEDED"
            execution.ended_at = utc_now()
            execution = self.repo.update_execution(execution, expected_version=version)
            task_obj = self._require_task(task.task_id)
            t_version = task_obj.version
            assert_transition("task", task_obj.lifecycle_state, "RUNNING", TASK_TRANSITIONS)
            task_obj.lifecycle_state = "RUNNING"
            task_obj = self.repo.update_task(task_obj, expected_version=t_version)
            t_version = task_obj.version
            assert_transition("task", task_obj.lifecycle_state, "REVIEW", TASK_TRANSITIONS)
            task_obj.lifecycle_state = "REVIEW"
            task_obj = self.repo.update_task(task_obj, expected_version=t_version)
            t_version = task_obj.version
            assert_transition("task", task_obj.lifecycle_state, "DONE", TASK_TRANSITIONS)
            task_obj.lifecycle_state = "DONE"
            self.repo.update_task(task_obj, expected_version=t_version)
        else:
            assert_transition("execution", execution.status, "FAILED", EXECUTION_TRANSITIONS)
            execution.status = "FAILED"
            execution.failure_reason = run.get("failure_reason")
            execution.ended_at = utc_now()
            self.repo.update_execution(execution, expected_version=version)

        return {
            "action": "oci_fixture_completed",
            "run": run,
            "session": session,
            "execution": execution.to_dict(),
            "project_id": project.project_id,
            "provenance": provenance,
            "live_cursor_acp": False,
            "note": "SYNTHETIC_OCI path; never CURSOR_ACP_LIVE",
        }

    def run_sandbox_fixture_demo(self) -> Dict[str, Any]:
        """Offline demo: injected OCI boundary + real AcpSessionManager."""
        self.oci = PodmanSandboxExecutor(
            process_factory=default_injected_factory("success"),
            allow_real_podman=False,
            code_revision="eos08-demo",
            podman_info_runner=lambda: {
                "rootless": True,
                "image_present": True,
                "image_digest": "sha256:" + ("e" * 64),
            },
        )
        # Exercise incomplete gate rejection.
        gate_error = None
        try:
            require_owner_execution_gates(
                execute=True, allow_phase_b=False, owner_authorize_runtime_execution=False
            )
        except OwnerGateError as exc:
            gate_error = {"rejected": True, "code": exc.code, "message": str(exc)}

        result = self.run_oci_acp_fixture(
            execute=True,
            allow_phase_b=True,
            owner_authorize_runtime_execution=True,
            dry_run=False,
            scenario="success",
            use_injected=True,
        )
        # Restart recovery check
        run_id = result["run"]["run_id"]
        execution_id = result["execution"]["execution_id"]
        project_id = result["project_id"]
        # Ambiguous RUNNING would block redispatch — demo completed so OK.
        again = self.repo.get_oci_fixture_run_by_execution(execution_id)
        return {
            "mode": "SANDBOX_FIXTURE_OFFLINE",
            "gate_incomplete_rejected": gate_error,
            "result": result,
            "restart": {
                "run_status": again["status"] if again else None,
                "run_id": run_id,
                "history": len(self.repo.list_oci_fixture_runs(project_id=project_id)),
            },
            "dry_plan": self.sandbox_fixture_plan(image_ref="localhost/alpine:eos-fixture"),
            "live_cursor_acp": False,
            "note": "Injected OCI process only; no Podman/containers started",
        }

    # --- EOS-09/10 Cursor runtime ---
    def cursor_status(self) -> Dict[str, Any]:
        return self.cursor.status()

    def cursor_image_plan(self) -> Dict[str, Any]:
        return self.cursor.image_build_plan()

    def cursor_image_inspect(self) -> Dict[str, Any]:
        return self.cursor.image_inspect()

    def cursor_image_verify(self, **kwargs: Any) -> Dict[str, Any]:
        return self.cursor.image_verify(**kwargs)

    def cursor_readiness(self) -> Dict[str, Any]:
        return self.cursor.preflight()

    def runtime_requirements(self) -> Dict[str, Any]:
        return self.cursor.requirements()

    def cursor_integration_check(self) -> Dict[str, Any]:
        from engineering_os.infrastructure.acp.acpx.acpx_cursor_config import (
            propose_acpx_cursor_agent_config,
            validate_acpx_cursor_command,
        )

        proposal = propose_acpx_cursor_agent_config()
        return {
            "proposal": proposal,
            "validation": validate_acpx_cursor_command(proposal["proposed_command"]),
            "direct_host_rejected": validate_acpx_cursor_command(
                ["cursor-agent", "acp"]
            ),
            "requirements": self.runtime_requirements(),
            "live_cursor_acp": False,
        }

    def cursor_session_plan(self, execution_id: str) -> Dict[str, Any]:
        execution = self.repo.get_execution(execution_id)
        if not execution:
            raise KeyError(f"unknown execution: {execution_id}")
        return self.cursor.prepare_session(
            execution_id=execution.execution_id,
            project_id=execution.project_id,
            task_id=execution.task_id,
            correlation_id=execution.idempotency_key,
        )

    def cursor_sessions(self, project_id: Optional[str] = None) -> List[Dict[str, Any]]:
        return self.cursor.list_sessions(project_id=project_id)

    def cursor_evidence(self, execution_id: str) -> Dict[str, Any]:
        return self.cursor.evidence_for(execution_id)

    def prepare_cursor_task(self, task_id: str) -> Dict[str, Any]:
        execution = self.prepare_synthetic_execution(task_id)
        prepared = self.cursor.prepare_session(
            execution_id=execution.execution_id,
            project_id=execution.project_id,
            task_id=execution.task_id,
            correlation_id=execution.idempotency_key,
        )
        self._emit(
            aggregate_type="execution",
            aggregate_id=execution.execution_id,
            event_type="execution.cursor_prepared",
            payload={
                "preparation_id": prepared["preparation"]["preparation_id"],
                "live_blocked": True,
                "blockers": prepared["preparation"].get("blockers_json"),
            },
        )
        return {
            "execution": execution.to_dict(),
            "prepared": prepared,
            "mode": "READY_FOR_AUTHORIZATION",
            "live_cursor_acp": False,
        }

    def cursor_smoke(
        self,
        *,
        dry_run: bool = True,
        execute: bool = False,
        allow_phase_b: bool = False,
        owner_authorize_runtime_execution: bool = False,
        authorization: Optional[RuntimeAuthorization] = None,
    ) -> Dict[str, Any]:
        """Owner smoke workflow. Live path requires triple-gate + SANDBOX PASS + auth."""
        from engineering_os.infrastructure.runtime.cursor.cursor_smoke_workflow import CursorSmokeWorkflow

        project = self.create_project("Cursor Smoke", "local/cursor-smoke")
        goal = self.create_goal(project.project_id, "Cursor ACP smoke readiness")
        task = self.create_task(
            goal.goal_id,
            "Read the provided README and return a concise summary. "
            "Do not modify files or execute commands.",
        )
        self.approve_goal(goal.goal_id)
        execution = self.prepare_synthetic_execution(task.task_id)
        ws = self.cursor.workspace.prepare(
            execution_id=execution.execution_id, project_id=project.project_id
        )
        workflow = CursorSmokeWorkflow(
            self.repo,
            runtime=self.cursor.runtime,
            credentials=self.cursor.credentials,
            auth_verifier=self.cursor.auth_verifier,
            sandbox_gate=self.sandbox_gate,
            launcher=self.cursor.launcher if hasattr(self.cursor, "launcher") else None,
        )
        if dry_run or not execute:
            result = workflow.dry_run()
            # Also include launch plan diagnostics.
            plan = self.cursor.smoke_dry_run(
                execution_id=execution.execution_id,
                project_id=project.project_id,
                task_id=task.task_id,
                workspace_id=ws.workspace_id,
                workspace_host_path=ws.host_path,
            )
            result["execution_id"] = execution.execution_id
            result["project_id"] = project.project_id
            result["launch_plan"] = plan
            result["owner_path"] = "dry_run"
            result["started"] = False
            return result
        result = workflow.execute(
            project_id=project.project_id,
            task_id=task.task_id,
            execution_id=execution.execution_id,
            workspace_id=ws.workspace_id,
            workspace_host_path=ws.host_path,
            authorization=authorization,
            execute=execute,
            allow_phase_b=allow_phase_b,
            owner_authorize_runtime_execution=owner_authorize_runtime_execution,
            dry_run=False,
        )
        result["execution_id"] = execution.execution_id
        result["project_id"] = project.project_id
        return result

    def run_cursor_fixture_demo(self) -> Dict[str, Any]:
        """Offline Cursor integration demo with fixture credentials/network."""
        verifier = RuntimeAuthorizationVerifier(
            secret=b"eos10-fixture-secret", issuance_enabled=True
        )
        self.cursor = CursorBridge(
            self.repo,
            credentials=FixtureCursorCredentialProvider(),
            network=FixtureAllowlistNetworkPolicy(),
            workspace=WorkspacePreparer(),
            runtime=CursorRuntimePlanner(
                image_digest="sha256:" + ("f" * 64),
                image_present=True,
                cursor_version="fixture-0.0.0",
                available_binaries=["agent", "cursor-agent"],
            ),
            auth_verifier=verifier,
            sandbox_gate=self.sandbox_gate,
        )
        project = self.create_project("Cursor Runtime Demo", "local/cursor-demo")
        goal = self.create_goal(project.project_id, "Prepare Cursor ACP runtime")
        t1 = self.create_task(goal.goal_id, "Cursor preparation task")
        t2 = self.create_task(
            goal.goal_id, "Follow-up after cursor prep", depends_on=[t1.task_id]
        )
        self.approve_goal(goal.goal_id)
        prepared = self.prepare_cursor_task(t1.task_id)
        demo = self.cursor.run_demo_synthetic(prepared["prepared"]["preparation"])
        smoke = self.cursor.smoke_dry_run(
            execution_id=prepared["execution"]["execution_id"],
            project_id=project.project_id,
            task_id=t1.task_id,
            workspace_id=prepared["prepared"]["preparation"]["sandbox_identity"],
            workspace_host_path=prepared["prepared"]["preparation"]["workspace_json"][
                "host_path"
            ],
        )
        reqs = self.runtime_requirements()
        denied = self.cursor.network.evaluate("evil.example")
        ip_denied = self.cursor.network.evaluate("1.2.3.4")
        return {
            "mode": "CURSOR_FIXTURE_OFFLINE",
            "project_id": project.project_id,
            "task1_id": t1.task_id,
            "task2_id": t2.task_id,
            "prepared": prepared,
            "demo": demo,
            "smoke_dry_run": smoke,
            "requirements": reqs,
            "unauthorized_egress_denied": denied.to_dict(),
            "ip_literal_denied": ip_denied.to_dict(),
            "integration_check": self.cursor_integration_check(),
            "runtime_modes": list(RUNTIME_MODES),
            "preflight": self.cursor.preflight(),
            "live_cursor_acp": False,
            "note": "No Cursor/OpenClaw/containers/network/credentials used",
        }

    def network_status(self) -> Dict[str, Any]:
        from engineering_os.infrastructure.network.broker.broker_runtime import (
            BrokerRuntime,
            proxy_compatibility_matrix,
        )
        from engineering_os.infrastructure.network.broker.egress_broker import TrustedEgressBroker
        from engineering_os.infrastructure.network.policy.egress_enforcer import (
            PastaAllowlistEgressPolicy,
            select_egress_policy,
        )
        from engineering_os.infrastructure.runtime.oci.podman_capabilities import (
            probe_podman_capabilities,
        )

        caps = probe_podman_capabilities()
        pasta = PastaAllowlistEgressPolicy(capabilities=caps)
        selected = select_egress_policy(capabilities=caps)
        broker = TrustedEgressBroker()
        runtime = getattr(self, "_broker_runtime", None) or BrokerRuntime()
        return {
            "podman": caps.to_dict(),
            "pasta_policy": pasta.readiness(),
            "selected_policy": selected.readiness(),
            "broker": broker.readiness(),
            "broker_runtime": runtime.status(),
            "proxy_compatibility": proxy_compatibility_matrix(),
            "enforcement": selected.readiness().get("enforcement", "NOT_ENFORCED"),
            "live_cursor_acp": False,
            "note": (
                "Podman 3.4.4 cannot use pasta network mode. "
                "Use --network=none + UDS broker; never treat pasta binary as ENFORCED."
            ),
        }

    def network_broker_status(self) -> Dict[str, Any]:
        return self.network_status()

    def network_probe(
        self,
        *,
        dry_run: bool = True,
        execute: bool = False,
        allow_phase_b: bool = False,
        owner_authorize_runtime_execution: bool = False,
        use_injected: bool = True,
        image_ref: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Owner network enforcement probe.

        Default use_injected=True keeps automation/offline safe.
        Owner real Podman path: use_injected=False with triple-gate.
        Image selection is dedicated — never resolve_local_fixture_image().
        """
        from engineering_os.infrastructure.network.broker.broker_runtime import BrokerRuntime
        from engineering_os.infrastructure.network.probe.network_probe_executor import (
            NetworkProbeExecutor,
            NetworkProbeRequest,
            default_injected_probe_factory,
        )
        from engineering_os.infrastructure.network.probe.probe_image import (
            ProbeImageError,
            synthetic_probe_image,
            validate_probe_image_ref,
        )

        owner_real = bool(execute and not dry_run and not use_injected)
        # Composition root: only Owner-real path installs the live upstream
        # opener + DNS resolver. Offline/injected paths keep blocked_connect.
        from engineering_os.infrastructure.network.broker.egress_broker import (
            blocked_connect,
            default_resolve,
            live_open_upstream,
        )

        if owner_real:
            if not image_ref:
                raise PolicyError("probe_image_ref_required")
            try:
                image_ref = validate_probe_image_ref(image_ref)
            except ProbeImageError as exc:
                raise PolicyError(str(exc)) from exc
            runtime = BrokerRuntime(
                connect_fn=live_open_upstream,
                resolve_fn=default_resolve,
            )
        else:
            runtime = BrokerRuntime(connect_fn=blocked_connect)
            if image_ref:
                try:
                    image_ref = validate_probe_image_ref(image_ref)
                except ProbeImageError:
                    # Offline dry-run with bad/legacy tag → synthetic placeholder.
                    image_ref = synthetic_probe_image().requested_ref
            else:
                image_ref = "" if dry_run or not execute else synthetic_probe_image().requested_ref
        self._broker_runtime = runtime
        executor = NetworkProbeExecutor(
            broker_runtime=runtime,
            process_factory=(
                None if owner_real else default_injected_probe_factory()
            ),
            allow_real_podman=owner_real,
            use_live_connect=owner_real,
        )
        project = self.create_project("Network Probe", "local/net-probe")
        goal = self.create_goal(project.project_id, "Broker enforcement probe")
        task = self.create_task(goal.goal_id, "Disposable network probe")
        self.approve_goal(goal.goal_id)
        execution = self.prepare_synthetic_execution(task.task_id)
        req = NetworkProbeRequest(
            execution_id=execution.execution_id,
            project_id=project.project_id,
            image_ref=image_ref or "",
            correlation_id=execution.idempotency_key,
        )
        result = executor.run(
            req,
            execute=execute and not dry_run,
            allow_phase_b=allow_phase_b,
            owner_authorize_runtime_execution=owner_authorize_runtime_execution,
            dry_run=dry_run or not execute,
        )
        payload = result.to_dict()
        payload["execution_id"] = execution.execution_id
        payload["project_id"] = project.project_id
        payload["action"] = "dry_run" if result.dry_run else (
            "executed" if result.executed else result.status.lower()
        )
        # Evidence-backed success only — never treat incomplete observations as PASS.
        if result.dry_run:
            payload["all_ok"] = bool(result.cases) and all(
                c.get("ok") for c in result.cases
            )
        else:
            payload["all_ok"] = (
                result.status == "COMPLETED"
                and result.policy_validated
                and (result.transport_verified or result.enforcement_verified)
            )
        payload["owner_path"] = "dry_run" if result.dry_run else "owner_execute"
        payload["cli_ok"] = result.dry_run or result.status == "COMPLETED"
        # Persist durable evidence reference without secrets.
        self.evidence.store(
            execution.execution_id,
            [f"netprobe:{result.run_id}"],
            {
                k: payload[k]
                for k in (
                    "run_id",
                    "executed",
                    "dry_run",
                    "status",
                    "provenance",
                    "cases",
                    "evidence_hashes",
                    "cleanup",
                )
                if k in payload
            },
        )
        self._emit(
            aggregate_type="execution",
            aggregate_id=execution.execution_id,
            event_type="execution.network_probe",
            payload={
                "run_id": result.run_id,
                "executed": result.executed,
                "status": result.status,
                "dry_run": result.dry_run,
            },
        )
        return payload

    def cursor_live_preflight(self) -> Dict[str, Any]:
        from engineering_os.infrastructure.runtime.cursor.live_preflight import CursorLivePreflight

        return CursorLivePreflight(
            runtime=self.cursor.runtime,
            credentials=self.cursor.credentials,
            network=self.cursor.network,
            workspace=self.cursor.workspace,
            auth_verifier=self.cursor.auth_verifier,
            sandbox_gate=self.sandbox_gate,
        ).run()

    def cursor_image_build(self, *, print_only: bool = True) -> Dict[str, Any]:
        """Owner-operated build instructions. Never builds during automation."""
        plan = self.cursor_image_plan()
        commands = [
            s.get("command")
            for s in (plan.get("steps") or [])
            if isinstance(s, dict) and s.get("command")
        ]
        return {
            "action": "print_only" if print_only else "refused_auto_build",
            "built": False,
            "downloaded": False,
            "plan": plan,
            "owner_commands": commands,
            "live_cursor_acp": False,
            "note": "EOS-12 does not build or download images in automation",
        }

    def cursor_smoke_evidence(self, execution_id: str) -> Dict[str, Any]:
        base = self.cursor_evidence(execution_id)
        base["smoke_prompt"] = (
            "Read the provided README and return a concise summary. "
            "Do not modify files or execute commands."
        )
        return base

    def owner_deployment_sequence(self) -> Dict[str, Any]:
        """Exact Owner-operated stages A–F plus legacy 8-step checklist."""
        from engineering_os.infrastructure.runtime.cursor.deployment_stages import deployment_stages
        from engineering_os.infrastructure.runtime.oci.podman_capabilities import (
            probe_podman_capabilities,
            version_tuple_to_str,
        )

        caps = probe_podman_capabilities()
        stages = deployment_stages(
            sandbox_gate=self.sandbox_gate,
            podman_version=version_tuple_to_str(caps.version),
        )
        # Preserve EOS-10/11 `steps` shape for regression tests and existing docs.
        steps = [
            {
                "step": 1,
                "title": "Verify Podman capabilities",
                "commands": [
                    "podman --version",
                    "podman info --format '{{.Host.Security.Rootless}}'",
                    "python3 scripts/eos.py network status",
                    "python3 scripts/eos.py network broker status",
                ],
            },
            {
                "step": 2,
                "title": "Build Cursor image",
                "commands": [
                    "python3 scripts/eos.py cursor image build-plan",
                    "python3 scripts/eos.py cursor image build --print-only",
                    "# Owner runs printed podman build commands manually",
                ],
            },
            {
                "step": 3,
                "title": "Verify image identity from local OCI + artifact bytes",
                "commands": [
                    "python3 scripts/eos.py cursor image inspect",
                    "python3 scripts/eos.py cursor image verify --use-local-inspect "
                    "--artifact-path containers/cursor-acp/vendor/cursor-agent "
                    "--cursor-version <VER> --base-digest sha256:<BASE> --write-evidence",
                ],
                "note": "Do not write evidence from manually invented checksums alone",
            },
            {
                "step": 4,
                "title": "Configure credential delivery (still disabled for live)",
                "commands": [
                    "install -m 600 /dev/null \"$HOME/.config/eos/cursor_api_key\"",
                    "export EOS_CURSOR_API_KEY_FILE=\"$HOME/.config/eos/cursor_api_key\"",
                    "# Keep provider disabled until network probe passes",
                ],
            },
            {
                "step": 5,
                "title": "Configure UDS egress broker (not pasta)",
                "commands": [
                    "python3 scripts/eos.py network status",
                    "python3 scripts/eos.py network probe --dry-run",
                    "python3 scripts/eos.py network broker probe --dry-run",
                    "# Owner-gated real probe (launches disposable workload):",
                    "python3 scripts/eos.py network probe --execute --allow-phase-b "
                    "--owner-authorize-runtime-execution",
                ],
                "blocker_if_missing": "uds_broker_enforcement_unproven",
            },
            {
                "step": 6,
                "title": "Unified live preflight",
                "commands": [
                    "python3 scripts/eos.py cursor live-preflight",
                    "python3 scripts/eos.py runtime requirements",
                ],
            },
            {
                "step": 7,
                "title": "Harmless sandboxed Cursor binary preflight",
                "commands": [
                    "podman run --rm --network none --read-only "
                    "--tmpfs /runtime/tmp:rw,size=32m --user 65534:65534 "
                    "localhost/eos-cursor-acp-runtime:eos10 agent --version",
                ],
            },
            {
                "step": 8,
                "title": "Authorized live ACP smoke (only after SANDBOX PASS + probe)",
                "commands": [
                    "python3 scripts/eos.py cursor smoke --dry-run",
                    "python3 scripts/eos.py cursor smoke --execute --allow-phase-b "
                    "--owner-authorize-runtime-execution",
                    "python3 scripts/eos.py cursor smoke evidence <EXECUTION_ID>",
                ],
                "note": "UI sandbox_gate never launches; env SANDBOX_GATE alone insufficient",
            },
        ]
        return {
            **stages,
            "steps": steps,
            "podman_note": (
                "Host observed Podman 3.4.4: do NOT install passt expecting pasta "
                "mode; use --network=none + UDS egress broker."
            ),
            "network_status": self.network_status(),
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
