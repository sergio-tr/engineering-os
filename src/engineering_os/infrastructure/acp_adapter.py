"""ACP execution adapter bridging ControlPlane executions to AcpSessionManager."""

from __future__ import annotations

from typing import Any, Dict, Optional

from engineering_os.infrastructure.adapters import (
    DispatchRequest,
    DispatchResult,
    ExecutionAdapter,
)
from engineering_os.infrastructure.acp_session import AcpSessionManager
from engineering_os.infrastructure.acp_transport import (
    AcpTransport,
    CursorAcpAdapter,
    DisabledLiveAcpTransport,
    InMemoryAcpTransport,
    OpenClawAcpxExecutionTransport,
)
from engineering_os.infrastructure.evidence import SYNTHETIC
from engineering_os.infrastructure.sqlite_repo import Repository


class AcpExecutionAdapter(ExecutionAdapter):
    """Dispatches executions through ACP session manager + selected transport."""

    name = "acp"

    def __init__(
        self,
        repo: Repository,
        *,
        sandbox_gate: str = "NOT_TESTED",
        synthetic_scenario: str = "success",
        prefer_live: bool = False,
    ) -> None:
        self.repo = repo
        self.sandbox_gate = sandbox_gate
        self.synthetic_scenario = synthetic_scenario
        self.prefer_live = prefer_live
        self.last_session: Optional[Dict[str, Any]] = None

    def select_transport(self, *, live: bool = False) -> AcpTransport:
        # Enforce sandbox at transport selection — ignore caller-supplied gate strings.
        authorized = self.sandbox_gate == "PASS"
        if live or self.prefer_live:
            if not authorized:
                return DisabledLiveAcpTransport(sandbox_gate=self.sandbox_gate)
            # Even if PASS, OpenClaw ACPX live path is prepared but not launched in EOS-06.
            return OpenClawAcpxExecutionTransport(
                enabled=True, sandbox_authorized=authorized
            )
        peer = InMemoryAcpTransport(scenario=self.synthetic_scenario)
        return CursorAcpAdapter(
            peer, allow_direct_process=False, sandbox_authorized=authorized
        )

    def runtime_status(self) -> Dict[str, Any]:
        synthetic = InMemoryAcpTransport().availability().to_dict()
        live = DisabledLiveAcpTransport(sandbox_gate=self.sandbox_gate).availability().to_dict()
        openclaw = OpenClawAcpxExecutionTransport(
            sandbox_authorized=self.sandbox_gate == "PASS"
        ).availability().to_dict()
        return {
            "sandbox_gate": self.sandbox_gate,
            "live_acp_enabled": False,
            "synthetic": synthetic,
            "live_disabled": live,
            "openclaw_acpx": openclaw,
            "cursor_commands": ["cursor-agent acp", "agent acp"],
            "note": "Live ACP remains blocked while SANDBOX is NOT_TESTED",
        }

    def dispatch(self, request: DispatchRequest) -> DispatchResult:
        live = False  # ACP adapter never starts live from dispatch alone.
        transport = self.select_transport(live=live)
        manager = AcpSessionManager(
            self.repo, transport, sandbox_gate=self.sandbox_gate
        )
        session = manager.create_session_record(
            execution_id=request.execution_id,
            project_id=request.project_id,
            task_id=request.task_id,
            agent_id="cursor",
            backend=transport.availability().backend,
            transport_type=transport.name,
            correlation_id=request.correlation_id or request.execution_id,
        )
        prompt = (
            f"Engineering OS synthetic ACP task {request.task_id} "
            f"execution {request.execution_id}"
        )
        session = manager.run_to_completion(session, prompt_text=prompt, mode="SYNTHETIC")
        self.last_session = session
        if session["status"] == "COMPLETED" and session.get("evidence_refs"):
            return DispatchResult(
                ok=True,
                status="SUCCEEDED",
                evidence=list(session["evidence_refs"]),
                details={
                    "mode": SYNTHETIC,
                    "acp_session_id": session["session_id"],
                    "acp_status": session["status"],
                    "backend": session["acp_backend"],
                    "note": "synthetic ACP protocol simulation; not real Cursor execution",
                },
            )
        return DispatchResult(
            ok=False,
            status="FAILED",
            failure_reason=session.get("failure_reason") or f"acp_{session['status'].lower()}",
            evidence=list(session.get("evidence_refs") or []),
            details={
                "mode": SYNTHETIC,
                "acp_session_id": session["session_id"],
                "acp_status": session["status"],
            },
        )
