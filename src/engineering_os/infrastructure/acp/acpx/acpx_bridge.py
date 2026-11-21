"""OpenClaw/ACPX/Cursor bridge with sandbox-enforced launcher routing.

Engineering OS owns authorization and sandbox enforcement. OpenClaw/ACPX may
own ACP session control, but Cursor must not spawn on the host.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from engineering_os.domain.models import new_id, utc_now
from engineering_os.infrastructure.acp_session import AcpSessionManager
from engineering_os.infrastructure.acp_transport import (
    CursorAcpAdapter,
    InMemoryAcpTransport,
)
from engineering_os.infrastructure.acpx_readiness import AcpxReadinessProbe
from engineering_os.infrastructure.adapters import DispatchRequest, DispatchResult
from engineering_os.infrastructure.evidence import ERROR, SYNTHETIC
from engineering_os.infrastructure.gateway_client import OpenClawGatewayClient
from engineering_os.infrastructure.runtime_authorization import (
    RuntimeAuthorization,
    RuntimeAuthorizationVerifier,
)
from engineering_os.infrastructure.sandbox_launcher import (
    PodmanAcpSandboxLauncher,
    RejectHostDirectLauncher,
    SandboxLauncher,
)
from engineering_os.infrastructure.sandbox_spec import (
    SandboxExecutionSpec,
    build_default_spec,
    validate_sandbox_spec,
)
from engineering_os.infrastructure.sqlite_repo import Repository


class AcpxBridgeError(RuntimeError):
    def __init__(self, message: str, *, code: str = "acpx_bridge_error") -> None:
        super().__init__(message)
        self.code = code


class AcpxSandboxBridge:
    """Prepares real-shaped ACP executions; real launch remains blocked in EOS-07."""

    def __init__(
        self,
        repo: Repository,
        *,
        gateway: Optional[OpenClawGatewayClient] = None,
        sandbox: Optional[SandboxLauncher] = None,
        host_reject: Optional[SandboxLauncher] = None,
        auth_verifier: Optional[RuntimeAuthorizationVerifier] = None,
        readiness_probe: Optional[AcpxReadinessProbe] = None,
        sandbox_gate: str = "NOT_TESTED",
    ) -> None:
        self.repo = repo
        self.gateway = gateway
        self.sandbox = sandbox or PodmanAcpSandboxLauncher()
        self.host_reject = host_reject or RejectHostDirectLauncher()
        self.auth_verifier = auth_verifier
        self.sandbox_gate = sandbox_gate
        self.readiness_probe = readiness_probe
        self.last_prepare: Optional[Dict[str, Any]] = None

    def _probe(self) -> AcpxReadinessProbe:
        if self.readiness_probe is not None:
            return self.readiness_probe
        if self.gateway is None:
            from engineering_os.infrastructure.gateway_client import default_gateway_client

            self.gateway = default_gateway_client()
        return AcpxReadinessProbe(self.gateway, self.sandbox)

    def runtime_status(self) -> Dict[str, Any]:
        probe = self._probe()
        if self.gateway is not None:
            # Best-effort connect for status (injected/unavailable transports only).
            try:
                self.gateway.connect()
            except Exception:  # noqa: BLE001
                pass
        report = probe.observe()
        return {
            "sandbox_gate": self.sandbox_gate,
            "gateway": self.gateway.status() if self.gateway else None,
            "sandbox": self.sandbox.readiness(),
            "host_direct": self.host_reject.readiness(),
            "acpx": report.to_dict(),
            "live_execution_enabled": False,
            "note": "sandbox_gate string alone is insufficient for launch authorization",
        }

    def inspect(self) -> Dict[str, Any]:
        status = self.runtime_status()
        return {
            **status,
            "prepared_executions": self.repo.list_runtime_preparations(),
            "openclaw_acp_host_note": (
                "OpenClaw ACP sessions run on the host runtime; "
                "sandbox=require does not isolate ACP harness processes"
            ),
        }

    def build_spec_for_execution(
        self,
        *,
        execution_id: str,
        project_id: str,
        task_id: str,
        correlation_id: str,
        idempotency_key: str,
        **overrides: Any,
    ) -> SandboxExecutionSpec:
        return build_default_spec(
            execution_id=execution_id,
            project_id=project_id,
            task_id=task_id,
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
            **overrides,
        )

    def prepare(
        self,
        request: DispatchRequest,
        *,
        authorization: Optional[RuntimeAuthorization] = None,
    ) -> Dict[str, Any]:
        existing = self.repo.get_runtime_preparation_by_execution(request.execution_id)
        if existing and existing["status"] in {
            "PREPARED",
            "AWAITING_AUTHORIZED_DISPATCH",
            "MOCK_RUNNING",
            "COMPLETED",
        }:
            return {
                "action": "idempotent_existing",
                "preparation": existing,
            }

        spec = self.build_spec_for_execution(
            execution_id=request.execution_id,
            project_id=request.project_id,
            task_id=request.task_id,
            correlation_id=request.correlation_id or request.execution_id,
            idempotency_key=request.correlation_id or request.execution_id,
        )
        validation_errors = validate_sandbox_spec(spec)
        plan = self.sandbox.plan(spec)
        host = self.host_reject.launch(spec, mode="REAL")
        probe = self._probe().observe()

        auth_state = "absent"
        if authorization is not None and self.auth_verifier is not None:
            try:
                self.auth_verifier.verify(
                    authorization,
                    execution_id=spec.execution_id,
                    project_id=spec.project_id,
                    workspace_id=spec.workspace_id,
                    agent_id=spec.agent_id,
                    image_digest=spec.image_digest,
                    network_mode=spec.network_mode,
                    cpu_limit=spec.cpu_limit,
                    memory_limit=spec.memory_limit,
                    pids_limit=spec.pids_limit,
                )
                auth_state = "verified_consumed"
            except Exception as exc:  # noqa: BLE001
                auth_state = f"rejected:{exc}"

        # Real path never proceeds in EOS-07.
        real_blocked = True
        blocked_reasons = list(plan.validation_errors) + [
            i.key for i in probe.items if not i.ok
        ]
        if self.sandbox_gate == "PASS":
            blocked_reasons.append("sandbox_gate_pass_insufficient_without_host_auth")
        blocked_reasons.append("real_launch_disabled_eos07")
        if host.failure_reason:
            blocked_reasons.append(host.failure_reason)

        record = {
            "preparation_id": new_id("rtprep"),
            "execution_id": request.execution_id,
            "project_id": request.project_id,
            "task_id": request.task_id,
            "spec_id": spec.spec_id,
            "spec_json": spec.to_dict(),
            "acpx_session_id": None,
            "cursor_session_id": None,
            "readiness_json": probe.to_dict(),
            "authorization_state": auth_state,
            "image_digest": spec.image_digest,
            "status": "AWAITING_AUTHORIZED_DISPATCH",
            "mode": "REAL_SHAPED_PREPARE",
            "blocked_reasons": sorted(set(blocked_reasons)),
            "launch_plan_json": plan.to_dict(),
            "evidence_refs": [],
            "cleanup_status": None,
            "failure_reason": None,
            "correlation_id": request.correlation_id or request.execution_id,
            "created_at": utc_now(),
            "started_at": None,
            "completed_at": None,
            "provenance": {
                "real_launch_blocked": real_blocked,
                "validation_errors": validation_errors,
                "sandbox_gate": self.sandbox_gate,
            },
        }
        stored = self.repo.insert_runtime_preparation(record)
        self.last_prepare = stored
        return {
            "action": "prepared",
            "preparation": stored,
            "real_launch_blocked": True,
            "host_direct_rejected": not host.ok,
        }

    def run_synthetic_prepared(
        self,
        preparation: Dict[str, Any],
        *,
        acp_scenario: str = "success",
    ) -> DispatchResult:
        """Mock sandbox + synthetic ACP through real session manager."""
        prep = dict(preparation)
        if prep["status"] == "COMPLETED":
            return DispatchResult(
                ok=True,
                status="SUCCEEDED",
                evidence=list(prep.get("evidence_refs") or []),
                details={"mode": SYNTHETIC, "idempotent": True},
            )
        prep["status"] = "MOCK_RUNNING"
        prep["started_at"] = utc_now()
        prep["mode"] = "SYNTHETIC"
        prep = self.repo.update_runtime_preparation(prep)

        # Mock sandbox launch
        spec = build_default_spec(
            execution_id=prep["execution_id"],
            project_id=prep["project_id"],
            task_id=prep["task_id"],
            correlation_id=prep["correlation_id"],
            idempotency_key=prep["correlation_id"],
            image_digest=prep["image_digest"],
        )
        # Override disk policy acknowledgment for mock-only path.
        from dataclasses import replace

        mock_spec = replace(
            spec,
            disk_limit_policy="enforced_quota",
            spec_id=prep["spec_id"],
        )
        launch = self.sandbox.launch(mock_spec, mode="SYNTHETIC")
        if not launch.ok:
            prep["status"] = "FAILED"
            prep["failure_reason"] = launch.failure_reason
            prep["completed_at"] = utc_now()
            self.repo.update_runtime_preparation(prep)
            return DispatchResult(
                ok=False,
                status="FAILED",
                failure_reason=launch.failure_reason,
                details=launch.to_dict(),
            )

        transport = CursorAcpAdapter(InMemoryAcpTransport(scenario=acp_scenario))
        manager = AcpSessionManager(
            self.repo, transport, sandbox_gate=self.sandbox_gate
        )
        session = manager.create_session_record(
            execution_id=prep["execution_id"],
            project_id=prep["project_id"],
            task_id=prep["task_id"],
            agent_id="cursor",
            backend="acpx-sandbox-bridge-synthetic",
            transport_type=transport.name,
            correlation_id=prep["correlation_id"],
        )
        session = manager.run_to_completion(
            session,
            prompt_text=f"EOS-07 synthetic ACP for {prep['task_id']}",
            mode="SYNTHETIC",
        )
        evidence = list(launch.evidence_refs) + list(session.get("evidence_refs") or [])
        prep["acpx_session_id"] = (session.get("runtime_provenance") or {}).get(
            "remote_session_id"
        )
        prep["cursor_session_id"] = session["session_id"]
        prep["evidence_refs"] = evidence
        prep["cleanup_status"] = launch.details.get("cleanup_status")
        if session["status"] == "COMPLETED":
            prep["status"] = "COMPLETED"
            prep["completed_at"] = utc_now()
            prep["provenance"] = {
                **(prep.get("provenance") or {}),
                "evidence_class": SYNTHETIC,
                "note": "synthetic bridge path; not real Cursor/ACPX",
            }
            self.repo.update_runtime_preparation(prep)
            return DispatchResult(
                ok=True,
                status="SUCCEEDED",
                evidence=evidence,
                details={
                    "mode": SYNTHETIC,
                    "preparation_id": prep["preparation_id"],
                    "acp_session_id": session["session_id"],
                    "launch": launch.to_dict(),
                },
            )
        prep["status"] = "FAILED"
        prep["failure_reason"] = session.get("failure_reason")
        prep["completed_at"] = utc_now()
        self.repo.update_runtime_preparation(prep)
        return DispatchResult(
            ok=False,
            status="FAILED",
            failure_reason=session.get("failure_reason"),
            evidence=evidence,
            details={"mode": SYNTHETIC, "acp_status": session["status"]},
        )

    def reject_sessions_spawn_bypass(self) -> Dict[str, Any]:
        return {
            "rejected": True,
            "reason": "sessions_spawn_runtime_acp_bypass_forbidden",
            "note": (
                "OpenClaw sessions_spawn(runtime=acp) must not bypass Engineering OS "
                "authorization and external sandbox launcher"
            ),
            "evidence_class": ERROR,
        }
