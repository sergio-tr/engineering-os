"""Cursor ACP runtime bridge — preparation path reusing EOS-08 OCI/ACP stack."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from engineering_os.domain.models import new_id, utc_now
from engineering_os.infrastructure.acp_session import AcpSessionManager
from engineering_os.infrastructure.acp_transport import (
    CursorAcpAdapter,
    InMemoryAcpTransport,
)
from engineering_os.infrastructure.acpx_cursor_config import (
    propose_acpx_cursor_agent_config,
    validate_acpx_cursor_command,
)
from engineering_os.infrastructure.credential_provider import (
    CredentialProvider,
    UnavailableCursorCredentialProvider,
    redact_secrets,
)
from engineering_os.infrastructure.cursor_runtime import CursorRuntimePlanner
from engineering_os.infrastructure.evidence import ERROR, SYNTHETIC, SYNTHETIC_IN_MEMORY
from engineering_os.infrastructure.network_policy import (
    NetworkPolicy,
    UnenforcedNetworkPolicy,
)
from engineering_os.infrastructure.oci_acp_transport import OciAcpStdioTransport
from engineering_os.infrastructure.oci_process import InjectedFixtureProcess
from engineering_os.infrastructure.runtime_authorization import (
    RuntimeAuthorizationVerifier,
)
from engineering_os.infrastructure.sqlite_repo import Repository
from engineering_os.infrastructure.workspace_prep import WorkspacePreparer


class CursorBridge:
    def __init__(
        self,
        repo: Repository,
        *,
        credentials: Optional[CredentialProvider] = None,
        network: Optional[NetworkPolicy] = None,
        workspace: Optional[WorkspacePreparer] = None,
        runtime: Optional[CursorRuntimePlanner] = None,
        auth_verifier: Optional[RuntimeAuthorizationVerifier] = None,
        sandbox_gate: str = "NOT_TESTED",
    ) -> None:
        self.repo = repo
        self.credentials = credentials or UnavailableCursorCredentialProvider()
        self.network = network or UnenforcedNetworkPolicy()
        self.workspace = workspace or WorkspacePreparer()
        self.runtime = runtime or CursorRuntimePlanner()
        self.auth_verifier = auth_verifier
        self.sandbox_gate = sandbox_gate

    def status(self) -> Dict[str, Any]:
        rt = self.runtime.readiness().to_dict()
        return {
            "cursor": rt,
            "image_plan": self.runtime.image_plan(),
            "command": self.runtime.command().to_dict(),
            "credentials": self.credentials.readiness(),
            "network": self.network.readiness(),
            "workspace": self.workspace.readiness(),
            "acpx": propose_acpx_cursor_agent_config(),
            "sandbox_gate": self.sandbox_gate,
            "live_cursor_acp_enabled": False,
            "note": "EOS-09 prepares Cursor runtime; live launch remains blocked",
        }

    def requirements(self) -> Dict[str, Any]:
        st = self.status()
        missing: List[str] = []
        missing.extend(st["cursor"].get("missing") or [])
        if not st["credentials"].get("available"):
            missing.append("credential_provider")
        if st["network"].get("status") == "BLOCKED":
            missing.append("network_policy_enforcement")
        if not st["cursor"].get("items"):
            missing.append("cursor_runtime")
        # Image digest null in profile
        if not self.runtime.image_digest:
            if "image_digest_verified" not in missing:
                missing.append("verified_image_digest")
        return {
            "missing": sorted(set(missing)),
            "live_blocked": True,
            "status": "BLOCKED" if missing else "READY_FOR_AUTHORIZATION",
            "details": st,
        }

    def prepare_session(
        self,
        *,
        execution_id: str,
        project_id: str,
        task_id: str,
        correlation_id: str,
    ) -> Dict[str, Any]:
        existing = self.repo.get_cursor_preparation_by_execution(execution_id)
        if existing and existing["status"] in {
            "PREPARED",
            "AWAITING_AUTHORIZED_DISPATCH",
            "COMPLETED",
        }:
            return {"action": "idempotent_existing", "preparation": existing}

        blockers: List[str] = []
        rt = self.runtime.readiness()
        blockers.extend(rt.to_dict()["missing"])
        cred = self.credentials.readiness()
        if not cred.get("available"):
            blockers.append("credential_provider_unavailable")
        net = self.network.readiness()
        if net.get("status") == "BLOCKED":
            blockers.append("network_policy_blocked")
        # Sample egress check
        egress = self.network.evaluate("api.cursor.com")
        if not egress.allowed and net.get("status") != "READY_FIXTURE":
            blockers.append("cursor_egress_denied")
        ws = self.workspace.prepare(execution_id=execution_id, project_id=project_id)
        acpx = propose_acpx_cursor_agent_config()
        acpx_val = validate_acpx_cursor_command(acpx["proposed_command"])
        if not acpx_val["ok"]:
            blockers.extend(acpx_val["errors"])
        if self.sandbox_gate == "PASS":
            blockers.append("sandbox_gate_pass_insufficient_without_host_auth")
        blockers.append("live_cursor_launch_disabled_eos09")

        lease_ref = None
        try:
            if cred.get("available"):
                lease = self.credentials.lease(execution_id=execution_id)
                lease_ref = lease.to_dict()
        except Exception as exc:  # noqa: BLE001
            blockers.append(f"credential_lease_failed:{exc}")

        record = {
            "preparation_id": new_id("curprep"),
            "execution_id": execution_id,
            "project_id": project_id,
            "task_id": task_id,
            "cursor_version": self.runtime.cursor_version,
            "image_digest": self.runtime.image_digest,
            "agent_id": "cursor",
            "acp_session_id": None,
            "sandbox_identity": ws.workspace_id,
            "authorization_ref": None,
            "network_policy_id": net.get("policy_id"),
            "credential_provider_ref": lease_ref.get("reference") if lease_ref else cred.get("provider_id"),
            "resource_ceilings_json": {
                "memory": "512m",
                "cpus": "1.0",
                "pids": 128,
                "workspace_bytes": ws.size_limit_bytes,
            },
            "workspace_json": ws.to_dict(),
            "acpx_config_json": acpx,
            "blockers_json": sorted(set(blockers)),
            "status": "AWAITING_AUTHORIZED_DISPATCH",
            "mode": "CURSOR_RUNTIME_PREPARE",
            "provenance": SYNTHETIC,
            "evidence_refs": [],
            "cleanup_status": None,
            "failure_reason": None,
            "correlation_id": correlation_id,
            "created_at": utc_now(),
            "started_at": None,
            "completed_at": None,
        }
        # Redact any accidental secrets in stored JSON blobs.
        blob = redact_secrets(str(record))
        if "[REDACTED]" in blob and "sk-" in str(record):
            record["failure_reason"] = "secret_redaction_triggered"
        stored = self.repo.insert_cursor_preparation(record)
        return {
            "action": "prepared",
            "preparation": stored,
            "live_blocked": True,
            "egress": egress.to_dict(),
            "acpx_validation": acpx_val,
        }

    def run_demo_synthetic(self, preparation: Dict[str, Any]) -> Dict[str, Any]:
        """Injected Cursor-shaped ACP transport; not live Cursor."""
        prep = dict(preparation)
        prep["status"] = "MOCK_RUNNING"
        prep["started_at"] = utc_now()
        prep["mode"] = "SYNTHETIC_CURSOR_TRANSPORT"
        prep = self.repo.update_cursor_preparation(prep)

        # Synthetic Cursor-shaped ACP via session manager (not live Cursor).
        transport = CursorAcpAdapter(InMemoryAcpTransport(scenario="success"))
        manager = AcpSessionManager(
            self.repo, transport, sandbox_gate=self.sandbox_gate
        )
        session = manager.create_session_record(
            execution_id=prep["execution_id"],
            project_id=prep["project_id"],
            task_id=prep["task_id"],
            agent_id="cursor",
            backend="cursor-runtime-synthetic",
            transport_type=transport.name,
            correlation_id=prep["correlation_id"],
        )
        session = manager.run_to_completion(
            session,
            prompt_text="EOS-09 synthetic Cursor ACP prompt",
            mode="SYNTHETIC",
        )
        # Cancellation path demonstration through OCI stdio injected process.
        from engineering_os.infrastructure.acp_protocol import (
            initialize_params,
            make_request,
        )
        from engineering_os.infrastructure.workspace_prep import WorkspaceSpec

        cancel_handle = InjectedFixtureProcess(scenario="success")
        cancel_transport = OciAcpStdioTransport(
            cancel_handle, evidence_class=SYNTHETIC_IN_MEMORY
        )
        cancel_transport.send(make_request("initialize", initialize_params()))
        cancel_transport.send(make_request("session/cancel", {"sessionId": "x"}))
        cancel_transport.close()

        ws_cleanup = self.workspace.cleanup(
            WorkspaceSpec(
                workspace_id=prep["sandbox_identity"],
                execution_id=prep["execution_id"],
                project_id=prep["project_id"],
                host_path=prep["workspace_json"]["host_path"],
            )
        )

        prep["acp_session_id"] = session["session_id"]
        prep["evidence_refs"] = list(session.get("evidence_refs") or [])
        prep["cleanup_status"] = "ok" if ws_cleanup.get("cleaned") else "failed"
        if session["status"] == "COMPLETED":
            prep["status"] = "COMPLETED"
        else:
            prep["status"] = "FAILED"
            prep["failure_reason"] = session.get("failure_reason")
        prep["completed_at"] = utc_now()
        prep["provenance"] = SYNTHETIC_IN_MEMORY
        prep = self.repo.update_cursor_preparation(prep)
        return {
            "preparation": prep,
            "session": session,
            "cancel_demo": cancel_transport.summary(),
            "workspace_cleanup": ws_cleanup,
            "live_cursor_acp": False,
        }
