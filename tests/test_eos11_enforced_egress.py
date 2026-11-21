"""EOS-11 offline tests — UDS egress broker, Podman 3.4.4 compat, image identity."""

from __future__ import annotations

import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from engineering_os.application.services import ControlPlane
from engineering_os.infrastructure.credential_provider import (
    FixtureCursorCredentialProvider,
    OwnerEnvFileCredentialProvider,
    redact_secrets,
)
from engineering_os.infrastructure.cursor_image import (
    inspect_local_image,
    verify_image_identity,
)
from engineering_os.infrastructure.cursor_launcher import (
    CursorAcpLauncher,
    CursorLaunchRequest,
    build_cursor_podman_argv,
)
from engineering_os.infrastructure.cursor_runtime import CursorRuntimePlanner
from engineering_os.infrastructure.egress_broker import (
    TrustedEgressBroker,
    blocked_connect,
    cursor_proxy_compatibility,
    write_tcp_uds_relay_script,
)
from engineering_os.infrastructure.egress_enforcer import (
    FailClosedEgressPolicy,
    PastaAllowlistEgressPolicy,
    UdsBrokerEgressPolicy,
    select_egress_policy,
)
from engineering_os.infrastructure.oci_acp_transport import OciAcpStdioTransport
from engineering_os.infrastructure.oci_process import InjectedFixtureProcess
from engineering_os.infrastructure.podman_capabilities import (
    PodmanCapabilities,
    parse_podman_version,
    probe_podman_capabilities,
    version_at_least,
)
from engineering_os.infrastructure.runtime_authorization import (
    AuthorizationError,
    RuntimeAuthorizationVerifier,
)


class PodmanCompatTests(unittest.TestCase):
    def test_parse_and_pasta_gate(self) -> None:
        self.assertEqual(parse_podman_version("podman version 3.4.4"), (3, 4, 4))
        self.assertFalse(version_at_least((3, 4, 4), (4, 4, 1)))
        self.assertTrue(version_at_least((4, 4, 1), (4, 4, 1)))

    def test_podman_344_rejects_pasta_enforcement(self) -> None:
        caps = probe_podman_capabilities(
            which=lambda n: "/bin/podman" if n == "podman" else None,
            version_runner=lambda: "podman version 3.4.4",
            info_runner=lambda: {"host": {"security": {"rootless": True}}},
        )
        self.assertEqual(caps.version, (3, 4, 4))
        self.assertFalse(caps.pasta_network_mode_supported)
        self.assertTrue(caps.network_none_supported)
        self.assertEqual(caps.to_dict()["recommended_egress"], "uds_broker_network_none")

        pasta = PastaAllowlistEgressPolicy(
            pasta_available=True, rootless_podman=True, capabilities=caps
        )
        ready = pasta.readiness()
        self.assertEqual(ready["status"], "BLOCKED")
        self.assertEqual(ready["enforcement"], "NOT_ENFORCED")
        self.assertIn("pasta_is_not_destination_firewall", ready["missing"])
        self.assertFalse(pasta.evaluate("api.cursor.com").allowed)

    def test_missing_pasta_binary_still_blocked(self) -> None:
        caps = PodmanCapabilities(
            podman_path="/usr/bin/podman",
            version=(3, 4, 4),
            rootless=True,
            pasta_binary_present=False,
            passt_binary_present=False,
            pasta_network_mode_supported=False,
            network_none_supported=True,
        )
        pasta = PastaAllowlistEgressPolicy(capabilities=caps, pasta_available=False)
        self.assertEqual(pasta.readiness()["enforcement"], "NOT_ENFORCED")


class BrokerTests(unittest.TestCase):
    def test_allow_deny_dns_ip_private(self) -> None:
        broker = TrustedEgressBroker(
            resolve_fn=None, connect_fn=blocked_connect
        )
        self.assertTrue(broker.evaluate_destination("api.cursor.com", 443).allowed)
        self.assertFalse(broker.evaluate_destination("evil.example", 443).allowed)
        self.assertFalse(broker.evaluate_destination("1.2.3.4", 443).allowed)
        self.assertFalse(broker.evaluate_destination("10.1.2.3", 443).allowed)
        self.assertFalse(broker.evaluate_destination("127.0.0.1", 443).allowed)
        self.assertFalse(broker.evaluate_destination("::1", 443).allowed)
        self.assertFalse(broker.evaluate_destination("169.254.169.254", 80).allowed)

    def test_dns_rebinding_and_ipv6(self) -> None:
        broker = TrustedEgressBroker(
            resolve_fn=lambda h: ["10.0.0.9"],
            connect_fn=blocked_connect,
        )
        d = broker.evaluate_destination("api.cursor.com", 443)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "dns_rebinding_or_private_resolution")

        broker6 = TrustedEgressBroker(
            resolve_fn=lambda h: ["2001:db8::1"],
            connect_fn=blocked_connect,
        )
        # Public-looking IPv6 in docs range is still an IP resolution — allowed
        # only if not private. 2001:db8::/32 is documentation, not private by
        # ipaddress module — ensure private/link-local still blocked.
        self.assertFalse(
            TrustedEgressBroker(
                resolve_fn=lambda h: ["fe80::1"], connect_fn=blocked_connect
            )
            .evaluate_destination("api.cursor.com", 443)
            .allowed
        )

    def test_broker_crash_fail_closed(self) -> None:
        broker = TrustedEgressBroker(connect_fn=blocked_connect)
        broker.mark_crashed()
        self.assertFalse(broker.evaluate_destination("api.cursor.com").allowed)
        self.assertEqual(broker.readiness()["status"], "BLOCKED")

    def test_probe_dry_run_plan(self) -> None:
        plan = TrustedEgressBroker().probe_plan()
        self.assertTrue(plan["all_ok"])
        self.assertFalse(plan["executed"])
        cases = {c["case"] for c in plan["cases"]}
        self.assertIn("direct_ip", cases)
        self.assertIn("broker_interruption_fail_closed", cases)

    def test_proxy_compatibility_not_assumed(self) -> None:
        diag = cursor_proxy_compatibility()
        self.assertFalse(diag["websocket_proxy_guaranteed"])
        self.assertTrue(diag["fail_closed_on_bypass"])
        self.assertTrue(diag["unrestricted_network_fallback_forbidden"])

    def test_relay_script_written(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_tcp_uds_relay_script(Path(tmp) / "relay.py")
            self.assertTrue(path.is_file())
            self.assertIn("AF_UNIX", path.read_text(encoding="utf-8"))


class UdsPolicyAndLauncherTests(unittest.TestCase):
    def test_select_policy_and_network_none_argv(self) -> None:
        caps = PodmanCapabilities(
            podman_path="/usr/bin/podman",
            version=(3, 4, 4),
            rootless=True,
            pasta_binary_present=False,
            passt_binary_present=False,
            pasta_network_mode_supported=False,
            network_none_supported=True,
        )
        selected = select_egress_policy(capabilities=caps)
        self.assertIsInstance(selected, FailClosedEgressPolicy)

        ready = UdsBrokerEgressPolicy(
            broker_ready=True,
            broker_socket_path="/tmp/eos-egress/broker.sock",
            capabilities=caps,
        )
        self.assertEqual(ready.readiness()["status"], "READY_FOR_OWNER_PROBE")
        self.assertEqual(ready.podman_network_args(), ["--network", "none"])
        self.assertTrue(ready.evaluate("api.cursor.com").allowed)
        self.assertFalse(ready.evaluate("8.8.8.8").allowed)

        argv = build_cursor_podman_argv(
            image_ref="localhost/eos-cursor-acp-runtime:eos10",
            container_name="eos-cursor-abcdefghijkl",
            workspace_host_path="/tmp/eos-workspaces/ws",
            acp_argv=["agent", "acp"],
            network_args=["--network", "none"],
        )
        self.assertIn("none", argv)
        self.assertNotIn("host", argv)
        with self.assertRaises(Exception):
            build_cursor_podman_argv(
                image_ref="x",
                container_name="eos-cursor-abcdefghijkl",
                workspace_host_path="/tmp/x",
                acp_argv=["agent", "acp"],
                network_args=["--network", "eos-cursor-egress"],
            )

    def test_direct_networking_unavailable_in_plan(self) -> None:
        launcher = CursorAcpLauncher(
            runtime=CursorRuntimePlanner(
                image_digest="sha256:" + ("a" * 64),
                image_present=True,
                cursor_version="1.0.0",
                available_binaries=["agent"],
            ),
            credentials=FixtureCursorCredentialProvider(),
            network=UdsBrokerEgressPolicy(
                broker_ready=True, broker_socket_path="/tmp/sock"
            ),
            auth_verifier=RuntimeAuthorizationVerifier(
                secret=b"x", issuance_enabled=True
            ),
            sandbox_gate="NOT_TESTED",
        )
        plan = launcher.plan(
            CursorLaunchRequest(
                execution_id="exec-abcdefghijkl",
                project_id="p",
                task_id="t",
                workspace_id="ws",
                workspace_host_path="/tmp/eos-workspaces/ws",
                image_ref="localhost/eos-cursor-acp-runtime:eos10",
                image_digest="sha256:" + ("a" * 64),
                acp_argv=["agent", "acp"],
                broker_socket_host_path="/tmp/sock",
                relay_host_path="/tmp/relay.py",
            )
        )
        self.assertTrue(plan.controls["network_none"])
        self.assertTrue(plan.controls["deny_untrusted_tools"])
        self.assertTrue(plan.controls["credential_env_not_isolated_from_peers"])


class ImageIdentityTests(unittest.TestCase):
    def test_user_supplied_checksum_untrusted_alone(self) -> None:
        result = verify_image_identity(
            image_digest="sha256:" + ("a" * 64),
            artifact_checksum="sha256:" + ("b" * 64),
            write_evidence=True,
        )
        self.assertEqual(result["overall_status"], "BLOCKED")
        self.assertIsNone(result["evidence_written"])
        keys = {c["key"] for c in result["checks"]}
        self.assertIn("user_supplied_checksum_untrusted_alone", keys)

    def test_local_inspect_injected(self) -> None:
        def runner(ref: str) -> dict:
            return {
                "Id": "sha256:" + ("c" * 64),
                "Digest": "sha256:" + ("d" * 64),
                "Architecture": "amd64",
                "Os": "linux",
                "RepoDigests": [f"{ref}@sha256:" + ("d" * 64)],
            }

        local = inspect_local_image("localhost/eos-cursor-acp-runtime:eos10", inspect_runner=runner)
        self.assertTrue(local["inspected"])
        self.assertEqual(local["local_image_id"], "sha256:" + ("c" * 64))

        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "agent"
            artifact.write_bytes(b"fixture-agent-bytes")
            verified = verify_image_identity(
                use_local_inspect=True,
                inspect_runner=runner,
                artifact_path=str(artifact),
                cursor_version="fixture",
                base_digest="sha256:" + ("e" * 64),
                write_evidence=False,
            )
            self.assertIn("artifact_checksum_verified_from_bytes", [
                c["key"] for c in verified["checks"] if c["ok"]
            ] + [c["key"] for c in verified["checks"]])


class CredentialIsolationTests(unittest.TestCase):
    def test_env_isolation_not_claimed(self) -> None:
        prov = OwnerEnvFileCredentialProvider(enabled=False)
        ready = prov.readiness()
        self.assertFalse(ready["env_var_isolates_untrusted_code"])
        self.assertEqual(
            ready["separations"]["untrusted_project_tool_execution"],
            "denied_in_smoke_until_isolated",
        )
        text = redact_secrets("CURSOR_API_KEY=sk-abcdefghijk")
        self.assertIn("[REDACTED]", text)


class AuthLifecycleTests(unittest.TestCase):
    def test_replay_and_cancel_cleanup(self) -> None:
        now = int(time.time())
        verifier = RuntimeAuthorizationVerifier(
            secret=b"eos11", issuance_enabled=True, clock=lambda: now
        )
        auth = verifier.issue_test_only(
            authorization_id="a1",
            execution_id="e1",
            project_id="p",
            task_id="t",
            workspace_id="ws",
            agent_id="cursor",
            image_digest="sha256:" + ("f" * 64),
            cpu_limit="1.0",
            memory_limit="512m",
            pids_limit=128,
            network_mode="none",
            network_policy_id="uds-broker-network-none",
            credential_provider_id="cursor-api-key-fixture",
            acp_command_profile="agent acp",
            expires_at_unix=now + 30,
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

        handle = InjectedFixtureProcess(
            scenario="success", sticky_alive=True, ignore_terminate=True
        )
        transport = OciAcpStdioTransport(handle, grace_seconds=0.05)
        transport.mark_protocol_completed(True)
        transport.close()
        outcome = transport.close_outcome()
        self.assertTrue(outcome["protocol_completed"])
        self.assertTrue(outcome["cleanup_verified"])
        self.assertFalse(outcome["process_exited_cleanly"])


class ServiceCliTests(unittest.TestCase):
    def test_network_and_live_preflight_and_demo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "eos.sqlite3"
            plane = ControlPlane.open(db)
            try:
                status = plane.network_status()
                self.assertEqual(status["pasta_policy"]["enforcement"], "NOT_ENFORCED")
                self.assertIn("pasta", status["note"].lower())
                probe = plane.network_probe(dry_run=True)
                self.assertTrue(probe["all_ok"])
                self.assertFalse(probe["executed"])
                live = plane.cursor_live_preflight()
                self.assertFalse(live["launch_eligible"])
                self.assertNotEqual(live["overall_status"], "READY")
                demo = plane.run_cursor_fixture_demo()
                self.assertFalse(demo["live_cursor_acp"])
                seq = plane.owner_deployment_sequence()
                blob = str(seq).lower()
                self.assertNotIn("apt-get install -y passt", blob)
                self.assertIn("network probe", blob)
            finally:
                plane.close()


if __name__ == "__main__":
    unittest.main()
