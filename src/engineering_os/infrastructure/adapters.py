"""Execution and integration adapters (synthetic + disabled live)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import uuid

from engineering_os.domain.models import utc_now


@dataclass
class DispatchRequest:
    execution_id: str
    task_id: str
    project_id: str
    attempt_number: int
    contract_ref: str
    budget_units: int = 1
    correlation_id: str = ""


@dataclass
class DispatchResult:
    ok: bool
    status: str
    evidence: List[str] = field(default_factory=list)
    failure_reason: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


class ExecutionAdapter(ABC):
    name: str

    @abstractmethod
    def dispatch(self, request: DispatchRequest) -> DispatchResult:
        raise NotImplementedError


class SyntheticExecutionAdapter(ExecutionAdapter):
    """In-process simulated jobs only — no subprocess/container/ACP."""

    name = "synthetic"

    def __init__(self, *, fail_task_ids: Optional[set[str]] = None) -> None:
        self.fail_task_ids = fail_task_ids or set()
        self.dispatched: List[str] = []

    def dispatch(self, request: DispatchRequest) -> DispatchResult:
        self.dispatched.append(request.execution_id)
        if request.budget_units <= 0:
            return DispatchResult(
                ok=False,
                status="FAILED",
                failure_reason="execution_budget_exhausted",
            )
        if request.task_id in self.fail_task_ids:
            return DispatchResult(
                ok=False,
                status="FAILED",
                failure_reason="synthetic_forced_failure",
                evidence=[f"synth-fail:{request.execution_id}"],
            )
        evidence_id = f"synth-evidence-{uuid.uuid4().hex[:10]}"
        return DispatchResult(
            ok=True,
            status="SUCCEEDED",
            evidence=[evidence_id],
            details={
                "mode": "SYNTHETIC",
                "completed_at": utc_now(),
                "note": "in-process simulation; not real agent execution",
            },
        )


class DisabledLiveExecutionAdapter(ExecutionAdapter):
    """Rejects real/live execution while SANDBOX gate is unapproved."""

    name = "live-disabled"

    def dispatch(self, request: DispatchRequest) -> DispatchResult:
        return DispatchResult(
            ok=False,
            status="FAILED",
            failure_reason="live_execution_disabled_sandbox_not_pass",
            details={"sandbox_gate": "NOT_TESTED"},
        )


class OrganizationAdapter(ABC):
    @abstractmethod
    def describe_org(self) -> Dict[str, Any]:
        raise NotImplementedError


class LocalOrganizationAdapter(OrganizationAdapter):
    def describe_org(self) -> Dict[str, Any]:
        return {"org": "local-synthetic", "mode": "SYNTHETIC"}


class CoordinatorAdapter(ABC):
    @abstractmethod
    def next_hint(self, project_id: str) -> Optional[str]:
        raise NotImplementedError


class LocalCoordinatorAdapter(CoordinatorAdapter):
    def next_hint(self, project_id: str) -> Optional[str]:
        return None


class EvidenceAdapter(ABC):
    @abstractmethod
    def store(self, execution_id: str, refs: List[str], payload: Dict[str, Any]) -> str:
        raise NotImplementedError


class LocalEvidenceAdapter(EvidenceAdapter):
    def __init__(self) -> None:
        self.store_map: Dict[str, Dict[str, Any]] = {}

    def store(self, execution_id: str, refs: List[str], payload: Dict[str, Any]) -> str:
        key = f"local-ev-{execution_id}"
        self.store_map[key] = {"refs": refs, "payload": payload, "at": utc_now()}
        return key


@dataclass
class RepositoryObservation:
    pr_identity: Optional[str]
    pr_state: str
    ci_status: str
    merge_commit_sha: Optional[str]
    base_branch_sha: Optional[str]
    review_status: str
    evidence_class: str  # simulated_integration | externally_verified


class RepositoryIntegrationAdapter(ABC):
    @abstractmethod
    def observe(self, project_id: str, execution_id: str) -> RepositoryObservation:
        raise NotImplementedError

    @abstractmethod
    def simulate_pr(self, project_id: str, execution_id: str) -> RepositoryObservation:
        raise NotImplementedError

    @abstractmethod
    def record_owner_merge_decision(
        self, execution_id: str, *, approved: bool
    ) -> RepositoryObservation:
        raise NotImplementedError


class SimulatedRepositoryIntegrationAdapter(RepositoryIntegrationAdapter):
    """Fixture-driven simulated GitHub/CI observations — never live API."""

    def __init__(self) -> None:
        self._by_exec: Dict[str, RepositoryObservation] = {}
        self._merge_decisions: Dict[str, bool] = {}

    def simulate_pr(self, project_id: str, execution_id: str) -> RepositoryObservation:
        obs = RepositoryObservation(
            pr_identity=f"sim-pr-{execution_id[-8:]}",
            pr_state="open",
            ci_status="pending",
            merge_commit_sha=None,
            base_branch_sha="sim-base-sha",
            review_status="pending",
            evidence_class="simulated_integration",
        )
        self._by_exec[execution_id] = obs
        return obs

    def observe(self, project_id: str, execution_id: str) -> RepositoryObservation:
        if execution_id in self._by_exec:
            return self._by_exec[execution_id]
        return RepositoryObservation(
            pr_identity=None,
            pr_state="absent",
            ci_status="unknown",
            merge_commit_sha=None,
            base_branch_sha=None,
            review_status="unknown",
            evidence_class="simulated_integration",
        )

    def complete_ci(self, execution_id: str, *, success: bool = True) -> RepositoryObservation:
        obs = self._by_exec.get(execution_id) or self.simulate_pr("unknown", execution_id)
        obs.ci_status = "success" if success else "failure"
        obs.pr_state = "open"
        self._by_exec[execution_id] = obs
        return obs

    def record_owner_merge_decision(
        self, execution_id: str, *, approved: bool
    ) -> RepositoryObservation:
        self._merge_decisions[execution_id] = approved
        obs = self._by_exec.get(execution_id) or self.simulate_pr("unknown", execution_id)
        if approved:
            if obs.ci_status != "success":
                obs.ci_status = "success"
            obs.pr_state = "merged"
            obs.merge_commit_sha = f"sim-merge-{execution_id[-8:]}"
            obs.review_status = "approved_synthetic"
        else:
            obs.pr_state = "open"
            obs.review_status = "rejected_synthetic"
            obs.merge_commit_sha = None
        obs.evidence_class = "simulated_integration"
        self._by_exec[execution_id] = obs
        return obs


class ApprovalProvider(ABC):
    @abstractmethod
    def decide(
        self, *, action: str, scope: str, approver: str, approve: bool
    ) -> Dict[str, Any]:
        raise NotImplementedError


class LocalOwnerDecisionProvider(ApprovalProvider):
    def decide(
        self, *, action: str, scope: str, approver: str, approve: bool
    ) -> Dict[str, Any]:
        return {
            "action": action,
            "scope": scope,
            "approver": approver,
            "decision": "APPROVED" if approve else "REJECTED",
            "synthetic": True,
            "note": "explicit synthetic Owner decision; not technical authorization",
        }
