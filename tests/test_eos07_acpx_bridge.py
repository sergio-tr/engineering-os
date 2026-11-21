"""EOS-07 ACPX bridge, gateway client, sandbox launcher and authorization tests."""

from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from engineering_os.application.orchestrator import SequentialOrchestrator
from engineering_os.application.services import ControlPlane
from engineering_os.infrastructure.adapters import DispatchRequest
from engineering_os.infrastructure.acp.acpx.acpx_bridge import AcpxSandboxBridge
from engineering_os.infrastructure.integrations.openclaw.gateway_client import (
    GatewayClientError,
    InMemoryGatewayTransport,
    OpenClawGatewayClient,
)
from engineering_os.infrastructure.security.authorization.runtime_authorization import (
    AuthorizationError,
    RuntimeAuthorization,
    RuntimeAuthorizationVerifier,
)
from engineering_os.infrastructure.runtime.sandbox.sandbox_launcher import (
    PodmanAcpSandboxLauncher,
    RejectHostDirectLauncher,
    scan_argv_for_bypass,
)
from engineering_os.infrastructure.runtime.sandbox.sandbox_spec import (
    build_default_spec,
    validate_sandbox_spec,
)
from engineering_os.infrastructure.persistence.sqlite import Repository


def _tmp() -> Path:
    return Path(tempfile.mkdtemp(prefix="eos07-")) / "t.sqlite3"


class GatewayClientTests(unittest.TestCase):
    def test_auth_failure_and_pairing(self) -> None:
        c = OpenClawGatewayClient(transport=InMemoryGatewayTransport(scenario="auth_failure"))
        st = c.connect()
        self.assertFalse(st.authenticated)
        self.assertIn("auth", (st.last_error or "").lower())

        c2 = OpenClawGatewayClient(
            transport=InMemoryGatewayTransport(scenario="pairing_required")
        )
        st2 = c2.connect()
        self.assertEqual(st2.connection_lifecycle, "pairing_required")

    def test_unsupported_protocol_and_missing_scope(self) -> None:
        c = OpenClawGatewayClient(
            transport=InMemoryGatewayTransport(scenario="unsupported_protocol")
        )
        st = c.connect()
        self.assertEqual(st.connection_lifecycle, "protocol_mismatch")

        c2 = OpenClawGatewayClient(
            transport=InMemoryGatewayTransport(scenario="missing_scope")
        )
        st2 = c2.connect()
        self.assertEqual(st2.connection_lifecycle, "scope_denied")

    def test_success_and_interrupt(self) -> None:
        transport = InMemoryGatewayTransport(scenario="success")
        c = OpenClawGatewayClient(transport=transport)
        st = c.connect()
        self.assertTrue(st.authenticated)
        out = c.call("sessions.list", {})
        self.assertIn("result", out)

        c3 = OpenClawGatewayClient(transport=InMemoryGatewayTransport(scenario="interrupt"))
        st3 = c3.connect()
        self.assertFalse(st3.authenticated)

    def test_auto_pair_forbidden(self) -> None:
        c = OpenClawGatewayClient(
            transport=InMemoryGatewayTransport(), auto_pair=True
        )
        with self.assertRaises(GatewayClientError):
            c.connect()


class SandboxSpecLauncherTests(unittest.TestCase):
    def test_rejects_host_paths_shell_and_network(self) -> None:
        spec = build_default_spec(
            execution_id="exec-1",
            project_id="p",
            task_id="t",
            correlation_id="c",
            idempotency_key="c",
            network_mode="bridge",
        )
        from dataclasses import replace

        bad = replace(
            spec,
            allowed_mounts=("/home/user/.ssh:/mnt:rw",),
            acp_command=("bash", "-c", "curl evil"),
            privileged=True,
            image_digest="latest",
        )
        errors = validate_sandbox_spec(bad)
        self.assertIn("unapproved_network_access", errors)
        self.assertIn("privileged_mode_forbidden", errors)
        self.assertIn("arbitrary_shell_command_rejected", errors)
        self.assertIn("missing_or_mutable_image_identity", errors)

    def test_direct_host_and_real_launch_blocked(self) -> None:
        spec = build_default_spec(
            execution_id="exec-2",
            project_id="p",
            task_id="t",
            correlation_id="c",
            idempotency_key="c",
        )
        host = RejectHostDirectLauncher()
        self.assertFalse(host.launch(spec, mode="REAL").ok)
        launcher = PodmanAcpSandboxLauncher()
        real = launcher.launch(spec, mode="REAL")
        self.assertFalse(real.ok)
        self.assertEqual(real.status, "BLOCKED")
        mock = launcher.launch(
            replace_disk(spec),
            mode="SYNTHETIC",
        )
        self.assertTrue(mock.ok)
        issues = scan_argv_for_bypass(["podman", "run", "--privileged"])
        self.assertTrue(issues)


def replace_disk(spec):
    from dataclasses import replace

    return replace(spec, disk_limit_policy="enforced_quota")


class AuthorizationTests(unittest.TestCase):
    def test_expired_and_replay(self) -> None:
        now = int(time.time())
        verifier = RuntimeAuthorizationVerifier(
            secret=b"test-secret", issuance_enabled=True, clock=lambda: now
        )
        auth = verifier.issue_test_only(
            authorization_id="auth-1",
            execution_id="e",
            project_id="p",
            workspace_id="ws-e",
            agent_id="cursor",
            image_digest="sha256:" + ("b" * 64),
            cpu_limit="1.0",
            memory_limit="512m",
            pids_limit=128,
            network_mode="none",
            expires_at_unix=now + 60,
            nonce="n1",
        )
        ok = verifier.verify(
            auth,
            execution_id="e",
            project_id="p",
            workspace_id="ws-e",
            agent_id="cursor",
            image_digest=auth.image_digest,
            network_mode="none",
            cpu_limit="1.0",
            memory_limit="512m",
            pids_limit=128,
        )
        self.assertTrue(ok["ok"])
        with self.assertRaises(AuthorizationError):
            verifier.verify(
                auth,
                execution_id="e",
                project_id="p",
                workspace_id="ws-e",
                agent_id="cursor",
                image_digest=auth.image_digest,
                network_mode="none",
                cpu_limit="1.0",
                memory_limit="512m",
                pids_limit=128,
            )
        expired = RuntimeAuthorization(
            **{**auth.to_dict(), "expires_at_unix": now - 1, "authorization_id": "auth-2"}
        )
        expired = RuntimeAuthorization(
            authorization_id="auth-2",
            execution_id="e",
            project_id="p",
            workspace_id="ws-e",
            agent_id="cursor",
            image_digest=auth.image_digest,
            cpu_limit="1.0",
            memory_limit="512m",
            pids_limit=128,
            network_mode="none",
            expires_at_unix=now - 1,
            nonce="n2",
            signature=verifier.sign(
                RuntimeAuthorization(
                    authorization_id="auth-2",
                    execution_id="e",
                    project_id="p",
                    workspace_id="ws-e",
                    agent_id="cursor",
                    image_digest=auth.image_digest,
                    cpu_limit="1.0",
                    memory_limit="512m",
                    pids_limit=128,
                    network_mode="none",
                    expires_at_unix=now - 1,
                    nonce="n2",
                    signature="",
                )
            ),
        )
        with self.assertRaises(AuthorizationError):
            verifier.verify(
                expired,
                execution_id="e",
                project_id="p",
                workspace_id="ws-e",
                agent_id="cursor",
                image_digest=auth.image_digest,
                network_mode="none",
                cpu_limit="1.0",
                memory_limit="512m",
                pids_limit=128,
            )

    def test_issuance_disabled_by_default(self) -> None:
        verifier = RuntimeAuthorizationVerifier(secret=b"x", issuance_enabled=False)
        with self.assertRaises(AuthorizationError):
            verifier.issue_test_only(
                authorization_id="a",
                execution_id="e",
                project_id="p",
                workspace_id="ws",
                agent_id="cursor",
                image_digest="sha256:" + ("c" * 64),
                cpu_limit="1.0",
                memory_limit="512m",
                pids_limit=128,
                network_mode="none",
                expires_at_unix=int(time.time()) + 10,
                nonce="n",
            )


class BridgeServiceTests(unittest.TestCase):
    def test_demo_restart_and_real_blocked(self) -> None:
        path = _tmp()
        plane = ControlPlane.open(path)
        result = plane.run_acpx_fixture_demo()
        self.assertEqual(result["mode"], "ACPX_FIXTURE_OFFLINE")
        self.assertFalse(result["real_launch"]["ok"])
        self.assertTrue(result["bypass_rejected"]["rejected"])
        self.assertEqual(result["ready_after"], [result["task2_id"]])
        exec_id = result["prepared"]["execution"]["execution_id"]
        plane.close()
        plane2 = ControlPlane.open(path)
        preps = plane2.acpx_sessions(result["project_id"])
        self.assertEqual(len(preps), 1)
        self.assertEqual(preps[0]["status"], "COMPLETED")
        # Duplicate prepare is idempotent
        again = plane2.acpx_prepare(exec_id)
        self.assertEqual(again["action"], "idempotent_existing")
        plane2.close()

    def test_prepare_claim_and_gate_insufficient(self) -> None:
        plane = ControlPlane(Repository(_tmp()), sandbox_gate="PASS")
        try:
            project = plane.create_project("P", "r/p")
            goal = plane.create_goal(project.project_id, "g")
            task = plane.create_task(goal.goal_id, "t")
            plane.approve_goal(goal.goal_id)
            orch = SequentialOrchestrator(plane)
            first = orch.prepare_acpx(project.project_id)
            self.assertEqual(first["action"], "acpx_prepared")
            prep = first["prepared"]["preparation"]
            self.assertIn(
                "sandbox_gate_pass_insufficient_without_host_auth",
                prep["blocked_reasons"],
            )
            second = orch.prepare_acpx(project.project_id)
            self.assertEqual(second["action"], "claim_held")
            status = plane.runtime_status()
            self.assertFalse(status["live_execution_enabled"])
        finally:
            plane.close()

    def test_wrong_project_mapping_rejected_in_auth(self) -> None:
        verifier = RuntimeAuthorizationVerifier(
            secret=b"map", issuance_enabled=True
        )
        now = int(time.time())
        auth = verifier.issue_test_only(
            authorization_id="auth-x",
            execution_id="e",
            project_id="p1",
            workspace_id="ws-e",
            agent_id="cursor",
            image_digest="sha256:" + ("d" * 64),
            cpu_limit="1.0",
            memory_limit="512m",
            pids_limit=128,
            network_mode="none",
            expires_at_unix=now + 30,
            nonce="nx",
        )
        with self.assertRaises(AuthorizationError):
            verifier.verify(
                auth,
                execution_id="e",
                project_id="p2",
                workspace_id="ws-e",
                agent_id="cursor",
                image_digest=auth.image_digest,
                network_mode="none",
                cpu_limit="1.0",
                memory_limit="512m",
                pids_limit=128,
            )


if __name__ == "__main__":
    unittest.main()
