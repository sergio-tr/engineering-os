"""EOS-10 offline tests — Cursor live readiness without builds/network/containers."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from engineering_os.application.orchestrator import SequentialOrchestrator
from engineering_os.application.services import ControlPlane
from engineering_os.infrastructure.credential_provider import (
    FixtureCursorCredentialProvider,
    OwnerEnvFileCredentialProvider,
    UnavailableCursorCredentialProvider,
    assert_no_secret_leak,
    redact_secrets,
)
from engineering_os.infrastructure.cursor_bridge import CursorBridge
from engineering_os.infrastructure.cursor_image import build_plan, inspect_image_definition, verify_image_identity
from engineering_os.infrastructure.cursor_launcher import (
    CursorAcpLauncher,
    CursorLaunchRequest,
    build_cursor_podman_argv,
    default_cursor_injected_factory,
)
from engineering_os.infrastructure.cursor_runtime import CursorRuntimePlanner
from engineering_os.infrastructure.egress_enforcer import (
    FailClosedEgressPolicy,
    PastaAllowlistEgressPolicy,
    is_ip_literal,
)
from engineering_os.infrastructure.network_policy import FixtureAllowlistNetworkPolicy
from engineering_os.infrastructure.oci_acp_transport import OciAcpStdioTransport
from engineering_os.infrastructure.oci_process import (
    InjectedFixtureProcess,
    TERMINATION_SIGKILL,
    TERMINATION_STDIN_CLOSED,
    TERMINATION_SIGTERM,
    classify_exit,
)
from engineering_os.infrastructure.runtime_authorization import (
    AuthorizationError,
    RuntimeAuthorization,
    RuntimeAuthorizationVerifier,
)
from engineering_os.infrastructure.runtime_preflight import CursorRuntimePreflight
from engineering_os.infrastructure.workspace_prep import WorkspacePreparer


class LifecycleTests(unittest.TestCase):
    def test_classify_exit_sigkill_variants(self) -> None:
        self.assertTrue(classify_exit(-9)["killed_by_sigkill"])
        self.assertTrue(classify_exit(137)["killed_by_sigkill"])
        self.assertTrue(classify_exit(0)["process_exited_cleanly"])
        self.assertFalse(classify_exit(1)["process_exited_cleanly"])

    def test_graceful_stdin_close(self) -> None:
        handle = InjectedFixtureProcess(scenario="success")
        result = handle.shutdown_gracefully(grace_seconds=0.2)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.process_exited_cleanly)
        self.assertEqual(result.termination_reason, TERMINATION_STDIN_CLOSED)
        self.assertFalse(result.sigkill_used)

    def test_protocol_complete_process_exit_failure(self) -> None:
        handle = InjectedFixtureProcess(
            scenario="success", sticky_alive=True, ignore_terminate=True
        )
        transport = OciAcpStdioTransport(handle, grace_seconds=0.05)
        transport.mark_protocol_completed(True)
        transport.close()
        outcome = transport.close_outcome()
        self.assertTrue(outcome["protocol_completed"])
        self.assertFalse(outcome["process_exited_cleanly"])
        self.assertEqual(outcome["exit_code"], -9)
        self.assertEqual(outcome["termination_reason"], TERMINATION_SIGKILL)
        self.assertTrue(outcome["sigkill_used"])
        self.assertTrue(outcome["cleanup_verified"])

    def test_forced_kill_fallback(self) -> None:
        handle = InjectedFixtureProcess(
            scenario="success", sticky_alive=True, ignore_terminate=True
        )
        cleanup = handle.cleanup(grace_seconds=0.05)
        self.assertEqual(cleanup["termination_reason"], TERMINATION_SIGKILL)
        self.assertTrue(cleanup["sigkill_used"])
        self.assertEqual(cleanup["exit_code"], -9)


class ImageTests(unittest.TestCase):
    def test_inspect_and_build_plan(self) -> None:
        inspect = inspect_image_definition()
        self.assertTrue(inspect["containerfile_present"])
        self.assertFalse(inspect["build_authorized_in_automation"])
        plan = build_plan()
        self.assertTrue(plan["floating_latest_forbidden"])
        self.assertFalse(plan["install_sources"]["immutable_official_artifact"])
        self.assertGreaterEqual(len(plan["steps"]), 5)

    def test_image_identity_validation(self) -> None:
        bad = verify_image_identity(image_digest=None)
        self.assertEqual(bad["overall_status"], "BLOCKED")
        good = verify_image_identity(
            image_digest="sha256:" + ("a" * 64),
            cursor_version="0.1.0",
            artifact_checksum="sha256:" + ("b" * 64),
            base_digest="sha256:" + ("c" * 64),
            write_evidence=False,
        )
        # Profile digest still null → profile_digest_configured blocked
        self.assertIn("profile_digest_configured", good["missing"])


class CredentialTests(unittest.TestCase):
    def test_redaction_and_unavailable(self) -> None:
        text = redact_secrets("CURSOR_API_KEY=sk-abcdefghijk Bearer tok")
        self.assertIn("[REDACTED]", text)
        prov = UnavailableCursorCredentialProvider()
        self.assertFalse(prov.readiness()["available"])
        with self.assertRaises(Exception):
            prov.lease(execution_id="e1")

    def test_fixture_lifecycle_and_visibility(self) -> None:
        prov = FixtureCursorCredentialProvider(secret="fixture-secret-value")
        lease = prov.lease(execution_id="e1")
        self.assertFalse(lease.to_dict()["secret_present_in_record"])
        env = prov.materialize_env(lease)
        self.assertEqual(env["CURSOR_API_KEY"], "fixture-secret-value")
        with self.assertRaises(Exception):
            prov.materialize_env(lease)  # consumed
        record = {"lease": lease.to_dict(), "note": "ok"}
        assert_no_secret_leak(record, forbidden_substrings={"fixture-secret-value"})
        prov.revoke(lease)
        self.assertTrue(lease.revoked)

    def test_owner_envfile_disabled_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            secret_path = Path(tmp) / "key"
            secret_path.write_text("not-a-real-key", encoding="utf-8")
            disabled = OwnerEnvFileCredentialProvider(
                secret_file=str(secret_path), enabled=False
            )
            self.assertFalse(disabled.readiness()["available"])
            enabled = OwnerEnvFileCredentialProvider(
                secret_file=str(secret_path), enabled=True
            )
            self.assertTrue(enabled.readiness()["available"])
            lease = enabled.lease(execution_id="e2")
            env = enabled.materialize_env(lease)
            self.assertIn("CURSOR_API_KEY", env)
            self.assertNotIn(env["CURSOR_API_KEY"], json.dumps(lease.to_dict()))


class NetworkTests(unittest.TestCase):
    def test_pasta_policy_never_enforced(self) -> None:
        from engineering_os.infrastructure.podman_capabilities import PodmanCapabilities

        caps = PodmanCapabilities(
            podman_path="/usr/bin/podman",
            version=(3, 4, 4),
            rootless=True,
            pasta_binary_present=True,
            passt_binary_present=True,
            pasta_network_mode_supported=False,
            network_none_supported=True,
        )
        policy = PastaAllowlistEgressPolicy(
            pasta_available=True, rootless_podman=True, capabilities=caps
        )
        ready = policy.readiness()
        self.assertEqual(ready["status"], "BLOCKED")
        self.assertEqual(ready["enforcement"], "NOT_ENFORCED")
        self.assertFalse(policy.evaluate("api.cursor.com").allowed)
        self.assertFalse(policy.evaluate("1.2.3.4").allowed)
        self.assertTrue(is_ip_literal("8.8.8.8"))
        closed = FailClosedEgressPolicy()
        self.assertEqual(closed.readiness()["status"], "BLOCKED")

    def test_fail_closed_without_broker(self) -> None:
        policy = PastaAllowlistEgressPolicy(
            pasta_available=False, rootless_podman=True
        )
        self.assertEqual(policy.readiness()["status"], "BLOCKED")
        self.assertFalse(policy.evaluate("api.cursor.com").allowed)
        self.assertIn("uds", (policy.readiness().get("owner_action") or "").lower())
        closed = FailClosedEgressPolicy()
        self.assertEqual(closed.readiness()["status"], "BLOCKED")


class AuthorizationTests(unittest.TestCase):
    def _auth(self, verifier: RuntimeAuthorizationVerifier, **overrides):
        now = int(time.time())
        fields = {
            "authorization_id": "auth-x",
            "execution_id": "exec-1",
            "project_id": "proj-1",
            "task_id": "task-1",
            "workspace_id": "ws-1",
            "agent_id": "cursor",
            "image_digest": "sha256:" + ("d" * 64),
            "cpu_limit": "1.0",
            "memory_limit": "512m",
            "pids_limit": 128,
            "network_mode": "eos-cursor-egress",
            "network_policy_id": "pasta-allowlist-egress",
            "credential_provider_id": "cursor-api-key-fixture",
            "acp_command_profile": "agent acp",
            "expires_at_unix": now + 60,
            "nonce": "nonce-1",
        }
        fields.update(overrides)
        return verifier.issue_test_only(**fields)

    def test_expired_replay_duplicate(self) -> None:
        now = int(time.time())
        verifier = RuntimeAuthorizationVerifier(
            secret=b"eos10", issuance_enabled=True, clock=lambda: now
        )
        auth = self._auth(verifier)
        ok = verifier.verify(
            auth,
            execution_id="exec-1",
            project_id="proj-1",
            workspace_id="ws-1",
            agent_id="cursor",
            image_digest=auth.image_digest,
            network_mode="eos-cursor-egress",
            cpu_limit="1.0",
            memory_limit="512m",
            pids_limit=128,
            task_id="task-1",
            credential_provider_id="cursor-api-key-fixture",
            acp_command_profile="agent acp",
            network_policy_id="pasta-allowlist-egress",
        )
        self.assertTrue(ok["ok"])
        with self.assertRaises(AuthorizationError) as replay:
            verifier.verify(
                auth,
                execution_id="exec-1",
                project_id="proj-1",
                workspace_id="ws-1",
                agent_id="cursor",
                image_digest=auth.image_digest,
                network_mode="eos-cursor-egress",
                cpu_limit="1.0",
                memory_limit="512m",
                pids_limit=128,
                task_id="task-1",
                credential_provider_id="cursor-api-key-fixture",
                acp_command_profile="agent acp",
                network_policy_id="pasta-allowlist-egress",
            )
        self.assertEqual(replay.exception.code, "replay")

        auth2 = self._auth(verifier, authorization_id="auth-y", nonce="n2")
        with self.assertRaises(AuthorizationError) as dup:
            verifier.verify(
                auth2,
                execution_id="exec-1",  # still inflight
                project_id="proj-1",
                workspace_id="ws-1",
                agent_id="cursor",
                image_digest=auth2.image_digest,
                network_mode="eos-cursor-egress",
                cpu_limit="1.0",
                memory_limit="512m",
                pids_limit=128,
                task_id="task-1",
                credential_provider_id="cursor-api-key-fixture",
                acp_command_profile="agent acp",
                network_policy_id="pasta-allowlist-egress",
            )
        self.assertEqual(dup.exception.code, "duplicate_dispatch")
        verifier.release_inflight("exec-1")

        expired = self._auth(
            verifier,
            authorization_id="auth-z",
            nonce="n3",
            expires_at_unix=now - 1,
            execution_id="exec-2",
        )
        with self.assertRaises(AuthorizationError) as exp:
            verifier.verify(
                expired,
                execution_id="exec-2",
                project_id="proj-1",
                workspace_id="ws-1",
                agent_id="cursor",
                image_digest=expired.image_digest,
                network_mode="eos-cursor-egress",
                cpu_limit="1.0",
                memory_limit="512m",
                pids_limit=128,
                task_id="task-1",
                credential_provider_id="cursor-api-key-fixture",
                acp_command_profile="agent acp",
                network_policy_id="pasta-allowlist-egress",
            )
        self.assertEqual(exp.exception.code, "expired")

    def test_binding_mismatch(self) -> None:
        verifier = RuntimeAuthorizationVerifier(
            secret=b"eos10", issuance_enabled=True
        )
        auth = self._auth(verifier)
        with self.assertRaises(AuthorizationError):
            verifier.verify(
                auth,
                execution_id="wrong",
                project_id="proj-1",
                workspace_id="ws-1",
                agent_id="cursor",
                image_digest=auth.image_digest,
                network_mode="eos-cursor-egress",
                cpu_limit="1.0",
                memory_limit="512m",
                pids_limit=128,
            )


class LauncherTests(unittest.TestCase):
    def test_argv_policy_and_no_secret(self) -> None:
        argv = build_cursor_podman_argv(
            image_ref="localhost/eos-cursor-acp-runtime:eos10",
            container_name="eos-cursor-abcdefghijkl",
            workspace_host_path="/tmp/eos-workspaces/ws-x",
            acp_argv=["agent", "acp"],
        )
        self.assertIn("--network", argv)
        self.assertNotIn("host", argv)
        self.assertNotIn("CURSOR_API_KEY=", " ".join(argv))
        with self.assertRaises(Exception):
            build_cursor_podman_argv(
                image_ref="x",
                container_name="eos-cursor-abcdefghijkl",
                workspace_host_path="/tmp/x",
                acp_argv=["bash", "-c", "evil"],
            )

    def test_unavailable_runtime_dry_run_blocked(self) -> None:
        launcher = CursorAcpLauncher(
            runtime=CursorRuntimePlanner(),
            credentials=UnavailableCursorCredentialProvider(),
            network=FailClosedEgressPolicy(),
            sandbox_gate="NOT_TESTED",
        )
        req = CursorLaunchRequest(
            execution_id="exec-abcdef123456",
            project_id="p",
            task_id="t",
            workspace_id="ws",
            workspace_host_path="/tmp/eos-workspaces/ws",
            image_ref="localhost/eos-cursor-acp-runtime:eos10",
            image_digest="",
            acp_argv=["agent", "acp"],
        )
        plan = launcher.plan(req)
        self.assertEqual(plan.mode, "BLOCKED")
        self.assertIn("credential_provider_unavailable", plan.blocked_reasons)


class PreflightAndSmokeTests(unittest.TestCase):
    def test_preflight_lists_missing(self) -> None:
        pf = CursorRuntimePreflight(
            runtime=CursorRuntimePlanner(),
            credentials=UnavailableCursorCredentialProvider(),
            network=FailClosedEgressPolicy(),
            sandbox_gate="NOT_TESTED",
            podman_probe={"rootless": None, "error": "unverified"},
        ).run()
        self.assertEqual(pf["overall_status"], "BLOCKED")
        self.assertFalse(pf["launch_eligible"])
        self.assertIn("credential_broker_configured", pf["missing"])

    def test_smoke_dry_run_and_demo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "eos.sqlite3"
            plane = ControlPlane.open(db)
            try:
                demo = plane.run_cursor_fixture_demo()
                self.assertFalse(demo["live_cursor_acp"])
                self.assertEqual(demo["demo"]["preparation"]["status"], "COMPLETED")
                self.assertTrue(demo["ip_literal_denied"]["allowed"] is False)
                smoke = plane.cursor_smoke(dry_run=True)
                self.assertEqual(smoke["action"], "dry_run")
                self.assertFalse(smoke["started"])
                seq = plane.owner_deployment_sequence()
                self.assertEqual(len(seq["steps"]), 8)
                readiness = plane.cursor_readiness()
                self.assertIn("items", readiness)
            finally:
                plane.close()

    def test_orchestrator_runtime_modes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "eos.sqlite3"
            plane = ControlPlane.open(db)
            try:
                project = plane.create_project("Orch", "local/orch")
                goal = plane.create_goal(project.project_id, "g")
                plane.create_task(goal.goal_id, "t1")
                plane.approve_goal(goal.goal_id)
                orch = SequentialOrchestrator(plane)
                blocked = orch.dispatch_runtime(
                    project.project_id, runtime_mode="CURSOR_ACP_LIVE"
                )
                self.assertEqual(blocked["action"], "cursor_live_blocked")
                self.assertTrue(blocked["requires_cursor_auth"])
                plan = orch.build_plan(project.project_id)
                self.assertIn("CURSOR_ACP_LIVE", plan["runtime_modes"])
                self.assertFalse(plan["live_acp_enabled"])
            finally:
                plane.close()

    def test_injected_cursor_smoke_execute_with_gates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "eos.sqlite3"
            plane = ControlPlane.open(db)
            try:
                # SANDBOX still NOT_TESTED → must refuse execute
                with self.assertRaises(AuthorizationError):
                    plane.cursor.smoke_execute(
                        execution_id="e",
                        project_id="p",
                        task_id="t",
                        workspace_id="ws",
                        workspace_host_path="/tmp/eos-workspaces/ws",
                        execute=True,
                        allow_phase_b=True,
                        owner_authorize_runtime_execution=True,
                        dry_run=False,
                    )
            finally:
                plane.close()


class WorkspaceAndRegressionTests(unittest.TestCase):
    def test_workspace_size_and_oci_lifecycle_via_demo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "eos.sqlite3"
            plane = ControlPlane.open(db)
            try:
                oci = plane.run_sandbox_fixture_demo()
                self.assertFalse(oci["live_cursor_acp"])
                run = plane.repo.list_oci_fixture_runs()[0]
                life = run["host_observations"].get("lifecycle") or {}
                self.assertIn("protocol_completed", life)
                self.assertIn("process_exited_cleanly", life)
                self.assertIn("termination_reason", life)
                self.assertTrue(life.get("protocol_completed"))
                # Injected success exits cleanly via stdin close / terminate.
                self.assertTrue(life.get("process_exited_cleanly"))
                ws = WorkspacePreparer(root=Path(tmp) / "ws")
                ready = ws.readiness()
                self.assertEqual(ready["size_limit_bytes"], 64 * 1024 * 1024)
            finally:
                plane.close()

    def test_paperclip_openclaw_regression_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "eos.sqlite3"
            plane = ControlPlane.open(db)
            try:
                # Keep integrations status readable without live network.
                status = plane.integrations_status() if hasattr(plane, "integrations_status") else None
                if status is None:
                    status = {
                        "paperclip": "observed_offline",
                        "openclaw": plane.openclaw_status().get("evidence_class"),
                    }
                self.assertIsNotNone(status)
                # Synthetic ACP regression via existing demo path remains available.
                demo = plane.run_cursor_fixture_demo()
                self.assertEqual(demo["mode"], "CURSOR_FIXTURE_OFFLINE")
            finally:
                plane.close()


if __name__ == "__main__":
    unittest.main()
