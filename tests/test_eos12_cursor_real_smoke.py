"""EOS-12 offline tests — broker runtime, network probe, Cursor smoke workflow."""

from __future__ import annotations

import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from engineering_os.application.services import ControlPlane
from engineering_os.infrastructure.network.broker.broker_runtime import (
    BrokerRuntime,
    cursor_proxy_env,
    proxy_compatibility_matrix,
)
from engineering_os.infrastructure.runtime.cursor.cursor_smoke_workflow import SMOKE_PROMPT
from engineering_os.infrastructure.runtime.cursor.deployment_stages import (
    deployment_stages,
    evaluate_stage_gate,
)
from engineering_os.infrastructure.network.broker.egress_broker import (
    TrustedEgressBroker,
    blocked_connect,
)
from engineering_os.infrastructure.network.probe.network_probe_executor import (
    NetworkProbeExecutor,
    NetworkProbeRequest,
    build_probe_podman_argv,
    default_injected_probe_factory,
    write_probe_workload_script,
)
from engineering_os.infrastructure.security.authorization.runtime_authorization import (
    AuthorizationError,
    RuntimeAuthorizationVerifier,
)


class BrokerRuntimeTests(unittest.TestCase):
    def test_start_stop_permissions_and_interrupt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rt = BrokerRuntime(root=Path(tmp), connect_fn=blocked_connect)
            inst = rt.start(execution_id="exec-broker-1")
            self.assertTrue(Path(inst.socket_path).exists())
            mode = Path(inst.socket_path).stat().st_mode & 0o777
            self.assertEqual(mode, 0o600)
            self.assertTrue(Path(inst.relay_path).is_file())
            interrupted = rt.interrupt("exec-broker-1")
            self.assertTrue(interrupted["fail_closed"])
            self.assertFalse(interrupted["evaluate_api_cursor"]["allowed"])
            stopped = rt.stop("exec-broker-1")
            self.assertTrue(stopped["stopped"])
            self.assertTrue(stopped["cleanup_verified"])

    def test_duplicate_start_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rt = BrokerRuntime(root=Path(tmp), connect_fn=blocked_connect)
            rt.start(execution_id="exec-dup")
            with self.assertRaises(RuntimeError):
                rt.start(execution_id="exec-dup")
            rt.stop("exec-dup")

    def test_proxy_env_documented(self) -> None:
        env = cursor_proxy_env()
        self.assertEqual(env["NODE_USE_ENV_PROXY"], "1")
        self.assertIn("HTTPS_PROXY", env)
        self.assertIn("HTTP_PROXY", env)
        matrix = proxy_compatibility_matrix()
        self.assertTrue(matrix["auth_success_not_proxy_proof"])
        self.assertTrue(matrix["direct_network_fallback_forbidden"])


class DestinationAndConnectTests(unittest.TestCase):
    def test_allowed_and_blocked_destinations(self) -> None:
        broker = TrustedEgressBroker(connect_fn=blocked_connect)
        self.assertTrue(broker.evaluate_destination("api.cursor.com", 443).allowed)
        self.assertFalse(broker.evaluate_destination("evil.example", 443).allowed)
        self.assertFalse(broker.evaluate_destination("1.2.3.4", 443).allowed)
        self.assertFalse(broker.evaluate_destination("10.0.0.1", 443).allowed)
        self.assertFalse(broker.evaluate_destination("169.254.169.254", 80).allowed)
        self.assertFalse(broker.evaluate_destination("::1", 443).allowed)

    def test_dns_rebinding_denied(self) -> None:
        broker = TrustedEgressBroker(
            allowed_destinations={"api.cursor.com"},
            resolve_fn=lambda h: ["10.0.0.5"],
            connect_fn=blocked_connect,
        )
        d = broker.evaluate_destination("api.cursor.com", 443)
        self.assertFalse(d.allowed)
        self.assertIn("rebinding", d.reason)

    def test_connect_target_validation(self) -> None:
        broker = TrustedEgressBroker(connect_fn=blocked_connect)
        # CONNECT must not allow host bypass via absolute-form tricks.
        d = broker.evaluate_destination("https://evil.example", 443)
        self.assertFalse(d.allowed)
        broker.mark_crashed()
        self.assertFalse(broker.evaluate_destination("api.cursor.com", 443).allowed)


class ProbeExecutorTests(unittest.TestCase):
    def test_argv_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sock = Path(tmp) / "broker.sock"
            sock.write_text("", encoding="utf-8")
            relay = Path(tmp) / "relay.py"
            relay.write_text("print(1)\n", encoding="utf-8")
            workload = write_probe_workload_script(Path(tmp) / "run.py")
            argv = build_probe_podman_argv(
                image_ref="sha256:" + ("c" * 64),
                container_name="eos-netprobe-abcdefghijkl",
                socket_host_path=str(sock),
                relay_host_path=str(relay),
                workload_host_path=str(workload),
            )
            joined = " ".join(argv)
            self.assertIn("--network", argv)
            self.assertIn("none", argv)
            self.assertNotIn("--network=host", joined)
            self.assertNotIn("CURSOR_API_KEY=", joined)
            self.assertNotIn("podman.sock", joined)
            self.assertIn("NODE_USE_ENV_PROXY=1", joined)

    def test_injected_execute_and_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rt = BrokerRuntime(root=Path(tmp), connect_fn=blocked_connect)
            ex = NetworkProbeExecutor(
                broker_runtime=rt,
                process_factory=default_injected_probe_factory(),
                allow_real_podman=False,
            )
            req = NetworkProbeRequest(
                execution_id="exec-probe-abcdefgh",
                project_id="p",
                image_ref="localhost/alpine:eos-fixture",
            )
            dry = ex.run(req, dry_run=True)
            self.assertTrue(dry.dry_run)
            self.assertFalse(dry.executed)
            self.assertEqual(dry.status, "DRY_RUN")

            result = ex.run(
                req,
                dry_run=False,
                execute=True,
                allow_phase_b=True,
                owner_authorize_runtime_execution=True,
            )
            self.assertTrue(result.executed)
            self.assertFalse(result.dry_run)
            self.assertEqual(result.status, "COMPLETED")
            self.assertEqual(result.verification_level, "TRANSPORT_VERIFIED")
            self.assertTrue(
                any(c["case"] == "broker_shutdown_interrupts" for c in result.cases)
            )
            self.assertTrue(result.cleanup["container"].get("cleaned_up"))


class SmokeAndStagesTests(unittest.TestCase):
    def test_smoke_dry_run_and_auth_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "eos.sqlite3"
            plane = ControlPlane.open(db)
            try:
                dry = plane.cursor_smoke(dry_run=True)
                self.assertEqual(dry["action"], "dry_run")
                self.assertFalse(dry["executed"])
                self.assertEqual(dry["prompt"], SMOKE_PROMPT)
                self.assertIn("NODE_USE_ENV_PROXY", dry["proxy"]["configured"])

                with self.assertRaises(AuthorizationError):
                    plane.cursor.smoke_execute(
                        execution_id="e",
                        project_id="p",
                        task_id="t",
                        workspace_id="ws",
                        workspace_host_path=str(Path(tmp) / "ws"),
                        execute=True,
                        allow_phase_b=True,
                        owner_authorize_runtime_execution=True,
                        dry_run=False,
                    )
            finally:
                plane.close()

    def test_stages_and_gates(self) -> None:
        stages = deployment_stages(sandbox_gate="NOT_TESTED", podman_version="3.4.4")
        self.assertEqual(len(stages["stages"]), 6)
        self.assertTrue(stages["auto_advance_forbidden"])
        gate = evaluate_stage_gate(
            "F",
            facts={
                "sandbox_gate": "NOT_TESTED",
                "authorization_present": False,
                "broker_enforced": False,
            },
        )
        self.assertFalse(gate["ok"])
        self.assertIn("sandbox_gate_not_pass", gate["missing"])

    def test_service_probe_injected_execute(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "eos.sqlite3"
            plane = ControlPlane.open(db)
            try:
                result = plane.network_probe(
                    dry_run=False,
                    execute=True,
                    allow_phase_b=True,
                    owner_authorize_runtime_execution=True,
                    use_injected=True,
                )
                self.assertTrue(result["executed"])
                self.assertNotEqual(result["action"], "dry_run")
                self.assertFalse(result["live_cursor_acp"])
                status = plane.network_broker_status()
                self.assertIn("broker_runtime", status)
                seq = plane.owner_deployment_sequence()
                self.assertEqual(seq["stages"][0]["stage"], "A")
                build = plane.cursor_image_build(print_only=True)
                self.assertFalse(build["built"])
                evidence = plane.cursor_smoke_evidence(result["execution_id"])
                self.assertIn("execution_id", evidence)
            finally:
                plane.close()

    def test_replay_auth_still_blocked(self) -> None:
        now = int(time.time())
        verifier = RuntimeAuthorizationVerifier(
            secret=b"eos12", issuance_enabled=True, clock=lambda: now
        )
        auth = verifier.issue_test_only(
            authorization_id="a1",
            execution_id="e1",
            project_id="p",
            task_id="t",
            workspace_id="ws",
            agent_id="cursor",
            image_digest="sha256:" + ("a" * 64),
            cpu_limit="1.0",
            memory_limit="512m",
            pids_limit=128,
            network_mode="none",
            network_policy_id="uds-broker-network-none",
            credential_provider_id="cursor-api-key-fixture",
            acp_command_profile="agent acp",
            expires_at_unix=now + 60,
            nonce="n1",
        )
        verifier.verify(
            auth,
            execution_id="e1",
            project_id="p",
            workspace_id="ws",
            agent_id="cursor",
            image_digest=auth.image_digest,
            network_mode="none",
            cpu_limit="1.0",
            memory_limit="512m",
            pids_limit=128,
            task_id="t",
            credential_provider_id="cursor-api-key-fixture",
            acp_command_profile="agent acp",
            network_policy_id="uds-broker-network-none",
        )
        with self.assertRaises(AuthorizationError):
            verifier.verify(
                auth,
                execution_id="e1",
                project_id="p",
                workspace_id="ws",
                agent_id="cursor",
                image_digest=auth.image_digest,
                network_mode="none",
                cpu_limit="1.0",
                memory_limit="512m",
                pids_limit=128,
                task_id="t",
                credential_provider_id="cursor-api-key-fixture",
                acp_command_profile="agent acp",
                network_policy_id="uds-broker-network-none",
            )


if __name__ == "__main__":
    unittest.main()
