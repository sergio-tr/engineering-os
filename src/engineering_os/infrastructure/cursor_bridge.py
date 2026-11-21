"""Cursor ACP runtime bridge — preparation, preflight and gated smoke (EOS-10)."""

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
from engineering_os.infrastructure.cursor_image import (
    build_plan,
    inspect_image_definition,
    verify_image_identity,
)
from engineering_os.infrastructure.cursor_launcher import (
    CursorAcpLauncher,
    CursorLaunchRequest,
    default_cursor_injected_factory,
)
from engineering_os.infrastructure.cursor_runtime import CursorRuntimePlanner
from engineering_os.infrastructure.evidence import (
    ERROR,
    SYNTHETIC,
    SYNTHETIC_IN_MEMORY,
)
from engineering_os.infrastructure.network_policy import (
    NetworkPolicy,
    UnenforcedNetworkPolicy,
)
from engineering_os.infrastructure.oci_acp_transport import OciAcpStdioTransport
from engineering_os.infrastructure.oci_process import InjectedFixtureProcess
from engineering_os.infrastructure.runtime_authorization import (
    AuthorizationError,
    RuntimeAuthorization,
    RuntimeAuthorizationVerifier,
)
from engineering_os.infrastructure.runtime_preflight import CursorRuntimePreflight
from engineering_os.infrastructure.sqlite_repo import Repository
from engineering_os.infrastructure.workspace_prep import WorkspacePreparer, WorkspaceSpec


RUNTIME_MODES = (
    "SYNTHETIC_IN_MEMORY",
    "SYNTHETIC_OCI_EXECUTED",
    "CURSOR_ACP_LIVE",
)


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
        launcher: Optional[CursorAcpLauncher] = None,
    ) -> None:
        self.repo = repo
        self.credentials = credentials or UnavailableCursorCredentialProvider()
        self.network = network or UnenforcedNetworkPolicy()
        self.workspace = workspace or WorkspacePreparer()
        self.runtime = runtime or CursorRuntimePlanner()
        self.auth_verifier = auth_verifier
        self.sandbox_gate = sandbox_gate
        self.launcher = launcher or CursorAcpLauncher(
            runtime=self.runtime,
            credentials=self.credentials,
            network=self.network,
            auth_verifier=self.auth_verifier,
            sandbox_gate=sandbox_gate,
            process_factory=default_cursor_injected_factory("success"),
            allow_real_podman=False,
        )

    def status(self) -> Dict[str, Any]:
        rt = self.runtime.readiness().to_dict()
        preflight = self.preflight()
        return {
            "cursor": rt,
            "image_plan": self.runtime.image_plan(),
            "image_inspect": inspect_image_definition(),
            "command": self.runtime.command().to_dict(),
            "credentials": self.credentials.readiness(),
            "network": self.network.readiness(),
            "workspace": self.workspace.readiness(),
            "acpx": propose_acpx_cursor_agent_config(),
            "preflight": preflight,
            "sandbox_gate": self.sandbox_gate,
            "sandbox_authorization_status": self.sandbox_gate,
            "launch_eligibility": preflight.get("launch_eligible"),
            "live_cursor_acp_enabled": False,
            "runtime_modes": list(RUNTIME_MODES),
            "note": "EOS-10 operational readiness; live launch remains gated",
        }

    def preflight(self) -> Dict[str, Any]:
        return CursorRuntimePreflight(
            runtime=self.runtime,
            credentials=self.credentials,
            network=self.network,
            workspace=self.workspace,
            auth_verifier=self.auth_verifier,
            sandbox_gate=self.sandbox_gate,
        ).run()

    def requirements(self) -> Dict[str, Any]:
        st = self.status()
        missing: List[str] = []
        missing.extend(st["cursor"].get("missing") or [])
        missing.extend(st["preflight"].get("missing") or [])
        if not st["credentials"].get("available"):
            missing.append("credential_provider")
        if st["network"].get("status") == "BLOCKED":
            missing.append("network_policy_enforcement")
        if not self.runtime.image_digest:
            if "image_digest_verified" not in missing:
                missing.append("verified_image_digest")
        if self.auth_verifier is None:
            missing.append("runtime_authorization_verifier")
        return {
            "missing": sorted(set(missing)),
            "live_blocked": True,
            "status": "BLOCKED" if missing else "READY_FOR_AUTHORIZATION",
            "details": st,
            "launch_eligible": False,
        }

    def image_inspect(self) -> Dict[str, Any]:
        return inspect_image_definition()

    def image_build_plan(self) -> Dict[str, Any]:
        return build_plan()

    def image_verify(self, **kwargs: Any) -> Dict[str, Any]:
        return verify_image_identity(**kwargs)

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
        egress = self.network.evaluate("api.cursor.com")
        if not egress.allowed and net.get("status") != "READY_FIXTURE":
            blockers.append("cursor_egress_denied")
        # Bypass probes
        if self.network.evaluate("8.8.8.8").allowed:
            blockers.append("ip_literal_bypass_open")
        ws = self.workspace.prepare(execution_id=execution_id, project_id=project_id)
        acpx = propose_acpx_cursor_agent_config()
        acpx_val = validate_acpx_cursor_command(acpx["proposed_command"])
        if not acpx_val["ok"]:
            blockers.extend(acpx_val["errors"])
        if self.sandbox_gate == "PASS":
            blockers.append("sandbox_gate_pass_insufficient_without_host_auth")
        if self.auth_verifier is None:
            blockers.append("runtime_authorization_missing")
        blockers.append("live_cursor_launch_disabled_until_owner_gates")

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
            "credential_provider_ref": lease_ref.get("reference")
            if lease_ref
            else cred.get("provider_id"),
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

    def smoke_dry_run(
        self,
        *,
        execution_id: str,
        project_id: str,
        task_id: str,
        workspace_id: str,
        workspace_host_path: str,
    ) -> Dict[str, Any]:
        cmd = self.runtime.command()
        req = CursorLaunchRequest(
            execution_id=execution_id,
            project_id=project_id,
            task_id=task_id,
            workspace_id=workspace_id,
            workspace_host_path=workspace_host_path,
            image_ref=str(
                self.runtime.profile.get("expected_image_ref")
                or "localhost/eos-cursor-acp-runtime:eos10"
            ),
            image_digest=self.runtime.image_digest or "",
            acp_argv=cmd.argv,
            credential_provider_id=self.credentials.provider_id,
            network_policy_id=getattr(self.network, "policy_id", ""),
        )
        result = self.launcher.dry_run(req)
        result["preflight"] = self.preflight()
        result["mode"] = "CURSOR_SMOKE_DRY_RUN"
        result["live_cursor_acp"] = False
        return result

    def smoke_execute(
        self,
        *,
        execution_id: str,
        project_id: str,
        task_id: str,
        workspace_id: str,
        workspace_host_path: str,
        authorization: Optional[RuntimeAuthorization] = None,
        execute: bool = False,
        allow_phase_b: bool = False,
        owner_authorize_runtime_execution: bool = False,
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        """Owner-gated smoke. Does not run live Cursor during EOS-10 automation."""
        if dry_run or not execute:
            return self.smoke_dry_run(
                execution_id=execution_id,
                project_id=project_id,
                task_id=task_id,
                workspace_id=workspace_id,
                workspace_host_path=workspace_host_path,
            )
        if self.sandbox_gate != "PASS":
            raise AuthorizationError("sandbox_gate_not_pass", code="sandbox_gate")
        cmd = self.runtime.command()
        req = CursorLaunchRequest(
            execution_id=execution_id,
            project_id=project_id,
            task_id=task_id,
            workspace_id=workspace_id,
            workspace_host_path=workspace_host_path,
            image_ref=str(
                self.runtime.profile.get("expected_image_ref")
                or "localhost/eos-cursor-acp-runtime:eos10"
            ),
            image_digest=self.runtime.image_digest or "",
            acp_argv=cmd.argv,
            credential_provider_id=self.credentials.provider_id,
            network_policy_id=getattr(self.network, "policy_id", ""),
        )
        started = self.launcher.launch(
            req,
            authorization=authorization,
            execute=execute,
            allow_phase_b=allow_phase_b,
            owner_authorize_runtime_execution=owner_authorize_runtime_execution,
            dry_run=False,
        )
        handle = self.launcher.last_handle
        assert handle is not None
        transport = OciAcpStdioTransport(
            handle,
            evidence_class=started["evidence_class"],
            backend_label="cursor-acp-oci",
            agent_id="cursor",
            live_cursor=started.get("live_cursor_acp", False),
        )
        manager = AcpSessionManager(
            self.repo, transport, sandbox_gate=self.sandbox_gate
        )
        session = manager.create_session_record(
            execution_id=execution_id,
            project_id=project_id,
            task_id=task_id,
            agent_id="cursor",
            backend="cursor-acp",
            transport_type=transport.name,
            correlation_id=execution_id,
        )
        try:
            session = manager.run_to_completion(
                session,
                prompt_text="EOS-10 Cursor ACP smoke (read-only trivial)",
                mode="CURSOR" if started.get("live_cursor_acp") else "SYNTHETIC",
            )
            transport.mark_protocol_completed(session.get("status") == "COMPLETED")
        finally:
            transport.close()
            if self.launcher.last_lease:
                self.credentials.revoke(self.launcher.last_lease)
            if self.auth_verifier:
                self.auth_verifier.release_inflight(execution_id)

        outcome = transport.close_outcome()
        return {
            "action": "smoke_executed",
            "started": started,
            "session": session,
            "lifecycle": outcome,
            "protocol_completed": outcome.get("protocol_completed"),
            "process_exited_cleanly": outcome.get("process_exited_cleanly"),
            "exit_code": outcome.get("exit_code"),
            "termination_reason": outcome.get("termination_reason"),
            "cleanup_verified": outcome.get("cleanup_verified"),
            "live_cursor_acp": started.get("live_cursor_acp"),
            "provenance": started.get("evidence_class"),
        }

    def run_demo_synthetic(self, preparation: Dict[str, Any]) -> Dict[str, Any]:
        """Injected Cursor-shaped ACP transport; not live Cursor."""
        prep = dict(preparation)
        prep["status"] = "MOCK_RUNNING"
        prep["started_at"] = utc_now()
        prep["mode"] = "SYNTHETIC_CURSOR_TRANSPORT"
        prep = self.repo.update_cursor_preparation(prep)

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
            prompt_text="EOS-10 synthetic Cursor ACP prompt",
            mode="SYNTHETIC",
        )
        from engineering_os.infrastructure.acp_protocol import (
            initialize_params,
            make_request,
        )

        cancel_handle = InjectedFixtureProcess(scenario="success")
        cancel_transport = OciAcpStdioTransport(
            cancel_handle, evidence_class=SYNTHETIC_IN_MEMORY
        )
        cancel_transport.send(make_request("initialize", initialize_params()))
        cancel_transport.send(make_request("session/cancel", {"sessionId": "x"}))
        cancel_transport.mark_protocol_completed(True)
        cancel_transport.close()

        sticky = InjectedFixtureProcess(scenario="success", sticky_alive=True, ignore_terminate=True)
        sticky_transport = OciAcpStdioTransport(sticky, grace_seconds=0.05)
        sticky_transport.mark_protocol_completed(True)
        sticky_transport.close()
        sticky_outcome = sticky_transport.close_outcome()

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
            "graceful_kill_fallback": sticky_outcome,
            "workspace_cleanup": ws_cleanup,
            "live_cursor_acp": False,
        }

    def list_sessions(self, project_id: Optional[str] = None) -> List[Dict[str, Any]]:
        return self.repo.list_cursor_preparations(project_id=project_id)

    def evidence_for(self, execution_id: str) -> Dict[str, Any]:
        prep = self.repo.get_cursor_preparation_by_execution(execution_id)
        oci = self.repo.get_oci_fixture_run_by_execution(execution_id)
        session = self.repo.get_acp_session_by_execution(execution_id)
        return {
            "execution_id": execution_id,
            "cursor_preparation": prep,
            "oci_fixture_run": oci,
            "acp_session": session,
            "lifecycle": (oci or {}).get("host_observations", {}).get("lifecycle")
            if oci
            else None,
            "live_cursor_acp": False,
        }
