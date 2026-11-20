"""Durable sequential orchestrator for per-project workflows."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
import uuid

from engineering_os.application.services import ControlPlane, PolicyError
from engineering_os.domain.models import Execution, new_id, utc_now
from engineering_os.domain.states import EXECUTION_TRANSITIONS, assert_transition
from engineering_os.infrastructure.adapters import (
    LocalCoordinatorAdapter,
    LocalOrganizationAdapter,
    RepositoryObservation,
)


class SequentialOrchestrator:
    """One active execution per project by default; dependency-aware scheduling."""

    def __init__(
        self,
        plane: ControlPlane,
        *,
        max_concurrent_per_project: int = 1,
        organization: Optional[LocalOrganizationAdapter] = None,
        coordinator: Optional[LocalCoordinatorAdapter] = None,
    ) -> None:
        self.plane = plane
        self.max_concurrent = max_concurrent_per_project
        self.organization = organization or LocalOrganizationAdapter()
        self.coordinator = coordinator or LocalCoordinatorAdapter()

    def active_execution(self, project_id: str) -> Optional[Execution]:
        claim = self.plane.repo.get_claim(project_id)
        if claim and claim.get("execution_id"):
            return self.plane.repo.get_execution(claim["execution_id"])
        running = [
            e
            for e in self.plane.repo.list_executions(project_id=project_id)
            if e.status
            in {"PREPARED", "DISPATCHED", "RUNNING", "AWAITING_INTEGRATION"}
        ]
        return running[-1] if running else None

    def next_eligible_task(self, project_id: str) -> Optional[str]:
        self.plane.recalculate_task_eligibility(project_id=project_id)
        ready = self.plane.list_ready_tasks(project_id)
        hint = self.coordinator.next_hint(project_id)
        if hint and any(t.task_id == hint for t in ready):
            return hint
        return ready[0].task_id if ready else None

    def tick(
        self,
        project_id: str,
        *,
        auto_integration: bool = True,
        approve_merge: bool = True,
    ) -> Dict[str, Any]:
        """Advance one orchestration step for a project (idempotent where possible)."""
        self.plane.get_project(project_id)
        active = self.active_execution(project_id)
        if active:
            return self._progress_active(
                active, auto_integration=auto_integration, approve_merge=approve_merge
            )
        task_id = self.next_eligible_task(project_id)
        if not task_id:
            return {
                "action": "idle",
                "reason": "no_eligible_task",
                "org": self.organization.describe_org(),
            }
        # Durable claim before dispatch
        token = uuid.uuid4().hex
        existing = self.plane.repo.get_claim(project_id)
        if existing and existing.get("claim_token") and existing.get("execution_id"):
            # Another claim holds work — do not duplicate.
            return {
                "action": "claim_held",
                "execution_id": existing.get("execution_id"),
                "task_id": existing.get("task_id"),
            }
        execution = self.plane.prepare_synthetic_execution(task_id)
        self.plane.repo.set_claim(
            project_id,
            execution_id=execution.execution_id,
            task_id=task_id,
            claim_token=token,
        )
        # Run synthetic work then enter integration checkpoint
        execution = self._dispatch_to_integration(execution)
        return {
            "action": "dispatched",
            "execution": execution.to_dict(),
            "task_id": task_id,
        }

    def _dispatch_to_integration(self, execution: Execution) -> Execution:
        """Run synthetic executor then move to AWAITING_INTEGRATION instead of DONE."""
        task = self.plane._require_task(execution.task_id)
        version = execution.version
        assert_transition("execution", execution.status, "DISPATCHED", EXECUTION_TRANSITIONS)
        execution.status = "DISPATCHED"
        execution.started_at = utc_now()
        execution = self.plane.repo.update_execution(execution, expected_version=version)

        from engineering_os.domain.states import TASK_TRANSITIONS

        t_version = task.version
        assert_transition("task", task.lifecycle_state, "RUNNING", TASK_TRANSITIONS)
        task.lifecycle_state = "RUNNING"
        task = self.plane.repo.update_task(task, expected_version=t_version)

        version = execution.version
        assert_transition("execution", execution.status, "RUNNING", EXECUTION_TRANSITIONS)
        execution.status = "RUNNING"
        execution = self.plane.repo.update_execution(execution, expected_version=version)

        from engineering_os.infrastructure.adapters import DispatchRequest

        result = self.plane.synthetic.dispatch(
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
        if not (result.ok and result.evidence):
            assert_transition("execution", execution.status, "FAILED", EXECUTION_TRANSITIONS)
            execution.status = "FAILED"
            execution.failure_reason = result.failure_reason or "synthetic_failed"
            execution.ended_at = utc_now()
            execution = self.plane.repo.update_execution(execution, expected_version=version)
            task = self.plane._require_task(task.task_id)
            t_version = task.version
            assert_transition("task", task.lifecycle_state, "FAILED", TASK_TRANSITIONS)
            task.lifecycle_state = "FAILED"
            self.plane.repo.update_task(task, expected_version=t_version)
            self.plane.repo.clear_claim(execution.project_id)
            self.plane.recalculate_task_eligibility(project_id=execution.project_id)
            return execution

        store_key = self.plane.evidence.store(
            execution.execution_id, result.evidence, result.details
        )
        execution.evidence_refs = list(result.evidence) + [store_key]
        assert_transition(
            "execution", execution.status, "AWAITING_INTEGRATION", EXECUTION_TRANSITIONS
        )
        execution.status = "AWAITING_INTEGRATION"
        execution.integration_state = "pr_pending"
        obs = self.plane.repo_integration.simulate_pr(
            execution.project_id, execution.execution_id
        )
        self.plane.repo_integration.complete_ci(execution.execution_id, success=True)
        execution = self.plane.repo.update_execution(execution, expected_version=version)
        self.plane._emit(
            aggregate_type="execution",
            aggregate_id=execution.execution_id,
            event_type="execution.awaiting_integration_synthetic",
            payload={"observation": obs.__dict__, "evidence": execution.evidence_refs},
        )
        return execution

    def _progress_active(
        self,
        execution: Execution,
        *,
        auto_integration: bool,
        approve_merge: bool,
    ) -> Dict[str, Any]:
        if execution.status == "AWAITING_INTEGRATION":
            if not auto_integration:
                return {
                    "action": "awaiting_owner_decision",
                    "execution_id": execution.execution_id,
                }
            return self.complete_integration(
                execution.execution_id, approve_merge=approve_merge
            )
        if execution.status in {"SUCCEEDED", "FAILED", "CANCELLED"}:
            self.plane.repo.clear_claim(execution.project_id)
            return {"action": "cleared_finished_claim", "execution_id": execution.execution_id}
        return {
            "action": "wait",
            "execution_id": execution.execution_id,
            "status": execution.status,
        }

    def complete_integration(
        self, execution_id: str, *, approve_merge: bool = True
    ) -> Dict[str, Any]:
        execution = self.plane._require_execution(execution_id)
        if execution.status != "AWAITING_INTEGRATION":
            raise PolicyError(f"execution not awaiting integration: {execution.status}")
        obs = self.plane.repo_integration.record_owner_merge_decision(
            execution_id, approved=approve_merge
        )
        # Simulated merge is never proof of a real merge.
        if obs.evidence_class != "simulated_integration":
            raise PolicyError("unexpected evidence class")
        version = execution.version
        from engineering_os.domain.states import TASK_TRANSITIONS

        if not approve_merge or obs.pr_state != "merged":
            assert_transition(
                "execution",
                execution.status,
                "INTEGRATION_FAILED",
                EXECUTION_TRANSITIONS,
            )
            execution.status = "INTEGRATION_FAILED"
            execution.failure_reason = "synthetic_merge_rejected"
            execution.integration_state = "rejected"
            execution = self.plane.repo.update_execution(
                execution, expected_version=version
            )
            self.plane._emit(
                aggregate_type="execution",
                aggregate_id=execution.execution_id,
                event_type="integration.rejected_synthetic",
                payload={"observation": obs.__dict__},
            )
            return {
                "action": "integration_rejected",
                "execution": execution.to_dict(),
                "observation": obs.__dict__,
            }

        assert_transition(
            "execution", execution.status, "SUCCEEDED", EXECUTION_TRANSITIONS
        )
        execution.status = "SUCCEEDED"
        execution.integration_state = "merged_synthetic"
        execution.ended_at = utc_now()
        execution.evidence_refs = list(execution.evidence_refs) + [
            f"sim-merge:{obs.merge_commit_sha}"
        ]
        execution = self.plane.repo.update_execution(execution, expected_version=version)

        task = self.plane._require_task(execution.task_id)
        t_version = task.version
        if task.lifecycle_state == "RUNNING":
            assert_transition("task", "RUNNING", "REVIEW", TASK_TRANSITIONS)
            task.lifecycle_state = "REVIEW"
            task = self.plane.repo.update_task(task, expected_version=t_version)
            t_version = task.version
        assert_transition("task", task.lifecycle_state, "DONE", TASK_TRANSITIONS)
        task.lifecycle_state = "DONE"
        task.execution_eligible = False
        self.plane.repo.update_task(task, expected_version=t_version)

        self.plane.repo.clear_claim(execution.project_id)
        self.plane.recalculate_task_eligibility(project_id=execution.project_id)
        self.plane._emit(
            aggregate_type="execution",
            aggregate_id=execution.execution_id,
            event_type="integration.merged_synthetic",
            payload={
                "observation": obs.__dict__,
                "note": "simulated merge only; not externally verified",
            },
        )
        next_task = self.next_eligible_task(execution.project_id)
        return {
            "action": "integration_completed",
            "execution": execution.to_dict(),
            "observation": obs.__dict__,
            "next_eligible_task": next_task,
            "evidence_class": "simulated_integration",
        }

    def recover(self, project_id: str) -> Dict[str, Any]:
        """Reconcile interrupted synthetic work after process restart."""
        claim = self.plane.repo.get_claim(project_id)
        active = self.active_execution(project_id)
        if not active:
            self.plane.repo.clear_claim(project_id)
            return {"action": "recovered_idle", "claim": claim}
        if active.status == "AWAITING_INTEGRATION":
            return {
                "action": "resume_awaiting_integration",
                "execution_id": active.execution_id,
            }
        if active.status in {"DISPATCHED", "RUNNING", "PREPARED"}:
            # Re-enter integration path idempotently if synthetic work can be redone
            # without duplicating SUCCEEDED records.
            if active.status == "PREPARED":
                active = self._dispatch_to_integration(active)
            return {
                "action": "reconciled_active",
                "execution": active.to_dict(),
            }
        self.plane.repo.clear_claim(project_id)
        return {"action": "cleared_stale", "execution": active.to_dict()}

    def run_full_synthetic_lifecycle(self, project_id: str) -> Dict[str, Any]:
        steps: List[Dict[str, Any]] = []
        # Cap steps to avoid infinite loops in tests
        for _ in range(20):
            step = self.tick(project_id, auto_integration=True, approve_merge=True)
            steps.append(step)
            if step.get("action") == "idle":
                break
            if step.get("action") == "integration_completed":
                # Continue to unlock next task
                continue
        return {
            "project_id": project_id,
            "steps": steps,
            "tasks": [t.to_dict() for t in self.plane.repo.list_tasks(project_id=project_id)],
            "executions": [
                e.to_dict()
                for e in self.plane.repo.list_executions(project_id=project_id)
            ],
            "org": self.organization.describe_org(),
        }

    def queue_snapshot(self, project_id: str) -> Dict[str, Any]:
        active = self.active_execution(project_id)
        return {
            "active_execution": active.to_dict() if active else None,
            "next_eligible_task": self.next_eligible_task(project_id),
            "ready_tasks": [t.to_dict() for t in self.plane.list_ready_tasks(project_id)],
            "claim": self.plane.repo.get_claim(project_id),
            "sandbox_gate": self.plane.sandbox_gate,
        }

    def build_plan(self, project_id: str) -> Dict[str, Any]:
        """Deterministic orchestration plan from local + observed external state."""
        self.plane.get_project(project_id)
        next_task_id = self.next_eligible_task(project_id)
        next_task = (
            self.plane._require_task(next_task_id).to_dict() if next_task_id else None
        )
        tasks = self.plane.repo.list_tasks(project_id=project_id)
        blockers = []
        for task in tasks:
            if task.lifecycle_state in {"BLOCKED", "FAILED"}:
                blockers.append(
                    {
                        "task_id": task.task_id,
                        "state": task.lifecycle_state,
                        "reason": task.blocked_reason,
                    }
                )
        paperclip_obs = self.plane.repo.latest_integration_observation(
            system_name="paperclip", project_id=project_id, include_stale=True
        )
        openclaw = self.plane.openclaw_status()
        github = self.plane.github_status(project_id)
        project_map = self.plane.repo.get_external_mapping(
            "paperclip", "project", project_id
        )
        issue_maps = self.plane.repo.list_external_mappings(
            system_name="paperclip", local_kind="issue"
        )
        assigned_agent = None
        external_issue = None
        if paperclip_obs and isinstance(paperclip_obs.get("payload"), dict):
            issues = paperclip_obs["payload"].get("issues_detail") or []
            agents = paperclip_obs["payload"].get("agents_detail") or []
            if issues:
                external_issue = issues[0]
                agent_id = external_issue.get("assigneeAgentId")
                for agent in agents:
                    if agent.get("id") == agent_id:
                        assigned_agent = agent
                        break
        live_execution_permitted = self.plane.sandbox_gate == "PASS"
        coordinator_reachable = False
        if isinstance(openclaw.get("gateway"), dict):
            coordinator_reachable = bool(openclaw["gateway"].get("available"))
        elif isinstance(openclaw.get("status"), dict):
            coordinator_reachable = bool(openclaw["status"].get("available"))
        elif openclaw.get("evidence_class") == "LIVE_READ_ONLY":
            coordinator_reachable = True

        return {
            "project_id": project_id,
            "next_eligible_task": next_task,
            "assigned_agent": assigned_agent,
            "blockers": blockers,
            "external_issue_mapping": {
                "project": project_map,
                "issues": issue_maps[:20],
                "sample_issue": external_issue,
            },
            "coordinator_reachable": coordinator_reachable,
            "openclaw": {
                "evidence_class": openclaw.get("evidence_class"),
                "installation_available": openclaw.get("installation_available"),
                "live_dispatch_permitted": False,
            },
            "github": {
                "connected": bool(github.get("connection")),
                "repository": (github.get("connection") or {}).get(
                    "repository_identity"
                ),
            },
            "sandbox_gate": self.plane.sandbox_gate,
            "synthetic_execution_permitted": True,
            "live_execution_permitted": live_execution_permitted,
            "live_acp_enabled": False,
            "evidence": {
                "paperclip": (paperclip_obs or {}).get("evidence_class"),
                "paperclip_stale": bool((paperclip_obs or {}).get("stale")),
                "openclaw": openclaw.get("evidence_class"),
            },
            "decision_notes": [
                "Paperclip is organizational observation only",
                "OpenClaw is coordinator availability only",
                "Local execution eligibility remains authoritative",
                "SANDBOX gate blocks live ACP regardless of Paperclip/OpenClaw status",
            ],
        }
