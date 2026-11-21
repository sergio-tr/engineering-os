"""First real Cursor ACP smoke workflow — Owner-gated (EOS-12).

Development never launches live Cursor. Injected transports cover offline tests.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
import hashlib

from engineering_os.domain.models import new_id, utc_now
from engineering_os.infrastructure.acp_session import AcpSessionManager
from engineering_os.infrastructure.broker_runtime import (
    BrokerRuntime,
    cursor_proxy_env,
    proxy_compatibility_matrix,
)
from engineering_os.infrastructure.credential_provider import (
    CredentialProvider,
    UnavailableCursorCredentialProvider,
    redact_secrets,
)
from engineering_os.infrastructure.cursor_launcher import (
    CursorAcpLauncher,
    CursorLaunchRequest,
    default_cursor_injected_factory,
)
from engineering_os.infrastructure.cursor_runtime import CursorRuntimePlanner
from engineering_os.infrastructure.egress_enforcer import UdsBrokerEgressPolicy
from engineering_os.infrastructure.evidence import (
    CURSOR_ACP_LIVE,
    SYNTHETIC_IN_MEMORY,
)
from engineering_os.infrastructure.oci_acp_transport import OciAcpStdioTransport
from engineering_os.infrastructure.runtime_authorization import (
    AuthorizationError,
    RuntimeAuthorization,
    RuntimeAuthorizationVerifier,
)
from engineering_os.infrastructure.sqlite_repo import Repository
from engineering_os.infrastructure.workspace_prep import WorkspacePreparer


SMOKE_PROMPT = (
    "Read the provided README and return a concise summary. "
    "Do not modify files or execute commands."
)


class CursorSmokeWorkflow:
    def __init__(
        self,
        repo: Repository,
        *,
        runtime: Optional[CursorRuntimePlanner] = None,
        credentials: Optional[CredentialProvider] = None,
        auth_verifier: Optional[RuntimeAuthorizationVerifier] = None,
        broker_runtime: Optional[BrokerRuntime] = None,
        sandbox_gate: str = "NOT_TESTED",
        launcher: Optional[CursorAcpLauncher] = None,
    ) -> None:
        self.repo = repo
        self.runtime = runtime or CursorRuntimePlanner()
        self.credentials = credentials or UnavailableCursorCredentialProvider()
        self.auth_verifier = auth_verifier
        self.broker_runtime = broker_runtime or BrokerRuntime()
        self.sandbox_gate = sandbox_gate
        self.workspace = WorkspacePreparer()
        self.launcher = launcher or CursorAcpLauncher(
            runtime=self.runtime,
            credentials=self.credentials,
            network=UdsBrokerEgressPolicy(broker_ready=False),
            auth_verifier=auth_verifier,
            sandbox_gate=sandbox_gate,
            process_factory=default_cursor_injected_factory("success"),
            allow_real_podman=False,
        )

    def dry_run(self) -> Dict[str, Any]:
        return {
            "action": "dry_run",
            "executed": False,
            "prompt": SMOKE_PROMPT,
            "proxy": proxy_compatibility_matrix(),
            "credentials": self.credentials.readiness(),
            "sandbox_gate": self.sandbox_gate,
            "deny_untrusted_tools": True,
            "smoke_mode": "ask",
            "github_credentials": False,
            "git_writes": False,
            "live_cursor_acp": False,
            "note": "Dry-run does not start Cursor or containers",
        }

    def execute(
        self,
        *,
        project_id: str,
        task_id: str,
        execution_id: str,
        workspace_id: str,
        workspace_host_path: str,
        authorization: Optional[RuntimeAuthorization] = None,
        execute: bool = False,
        allow_phase_b: bool = False,
        owner_authorize_runtime_execution: bool = False,
        dry_run: bool = True,
        readme_text: str = "# Smoke\nRead-only summary task.\n",
    ) -> Dict[str, Any]:
        if dry_run or not execute:
            return {**self.dry_run(), "execution_id": execution_id, "project_id": project_id}

        if self.sandbox_gate != "PASS":
            raise AuthorizationError("sandbox_gate_not_pass", code="sandbox_gate")
        if authorization is None or self.auth_verifier is None:
            raise AuthorizationError(
                "runtime_authorization_required", code="auth_required"
            )

        # Write README into disposable workspace (not credentials).
        from pathlib import Path

        ws = Path(workspace_host_path)
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "README.md").write_text(readme_text, encoding="utf-8")

        broker_instance = self.broker_runtime.start(execution_id=execution_id)
        self.launcher.network = UdsBrokerEgressPolicy(
            broker_ready=True,
            broker_socket_path=broker_instance.socket_path,
        )
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
            network_mode="none",
            credential_provider_id=self.credentials.provider_id,
            network_policy_id="uds-broker-network-none",
            broker_socket_host_path=broker_instance.socket_path,
            relay_host_path=broker_instance.relay_path,
            deny_untrusted_tools=True,
            smoke_mode="ask",
        )

        started = self.launcher.launch(
            req,
            authorization=authorization,
            execute=True,
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
            backend="cursor-acp-smoke",
            transport_type=transport.name,
            correlation_id=execution_id,
        )
        try:
            session = manager.run_to_completion(
                session,
                prompt_text=SMOKE_PROMPT,
                mode="CURSOR" if started.get("live_cursor_acp") else "SYNTHETIC",
            )
            transport.mark_protocol_completed(session.get("status") == "COMPLETED")
        finally:
            transport.close()
            if self.launcher.last_lease:
                self.credentials.revoke(self.launcher.last_lease)
            broker_cleanup = self.broker_runtime.stop(execution_id)
            if self.auth_verifier:
                self.auth_verifier.release_inflight(execution_id)

        outcome = transport.close_outcome()
        evidence = {
            "cursor_version": self.runtime.cursor_version,
            "acp_protocol_version": 1,
            "execution_id": execution_id,
            "acp_session_id": session.get("session_id"),
            "oci_image_identity": {
                "ref": req.image_ref,
                "digest": req.image_digest,
            },
            "container_id": handle.container_id,
            "network_policy_id": "uds-broker-network-none",
            "broker_id": broker_instance.broker_id,
            "protocol_completed": outcome.get("protocol_completed"),
            "process_exit_status": outcome.get("exit_code"),
            "process_exited_cleanly": outcome.get("process_exited_cleanly"),
            "termination_reason": outcome.get("termination_reason"),
            "cleanup_status": {
                "transport": outcome.get("cleanup_verified"),
                "broker": broker_cleanup.get("cleanup_verified"),
            },
            "proxy_env_keys": sorted(cursor_proxy_env().keys()),
            "deny_untrusted_tools": True,
            "provenance": started.get("evidence_class"),
            "started": redact_secrets(str(started.get("note"))),
        }
        blob = str(evidence)
        evidence["integrity_hash"] = hashlib.sha256(blob.encode("utf-8")).hexdigest()

        # Persist preparation-like record via cursor preparations table if present.
        return {
            "action": "smoke_executed",
            "executed": True,
            "session": session,
            "lifecycle": outcome,
            "evidence": evidence,
            "broker_cleanup": broker_cleanup,
            "live_cursor_acp": started.get("evidence_class") == CURSOR_ACP_LIVE,
            "note": "ACP completion is not a merged GitHub PR",
        }
