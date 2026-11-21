"""EOS-12.1 regression tests — CONNECT tunnel, evidence gates, false positives."""

from __future__ import annotations

import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from engineering_os.application.services import ControlPlane
from engineering_os.infrastructure.network.broker.broker_runtime import BrokerRuntime
from engineering_os.infrastructure.network.broker.egress_broker import (
    TrustedEgressBroker,
    blocked_connect,
    forward_bidirectional,
    live_open_upstream,
)
from engineering_os.infrastructure.network.probe.network_probe_executor import (
    NetworkProbeExecutor,
    NetworkProbeRequest,
    build_probe_podman_argv,
    default_injected_probe_factory,
    evaluate_container_observations,
    legacy_false_positive_would_pass,
    parse_probe_output,
    write_probe_workload_script,
)


class ConnectTunnelTests(unittest.TestCase):
    def test_forward_bidirectional_echo(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def echo() -> None:
            conn, _ = server.accept()
            data = conn.recv(1024)
            conn.sendall(b"ECHO:" + data)
            conn.close()
            server.close()

        threading.Thread(target=echo, daemon=True).start()
        upstream = socket.create_connection(("127.0.0.1", port), timeout=2)
        left, right = socket.socketpair()
        # Send payload on left; forward_bidirectional will move it to upstream
        # and back — drive via thread writing after tunnel starts is awkward;
        # instead exercise pipe between two ends with a local echo peer.
        upstream.close()
        left.close()
        right.close()

        a, b = socket.socketpair()
        c, d = socket.socketpair()

        def pump() -> None:
            forward_bidirectional(b, c, deadline_seconds=2.0, max_bytes=4096)

        t = threading.Thread(target=pump, daemon=True)
        t.start()
        a.sendall(b"ping")
        got = d.recv(1024)
        self.assertEqual(got, b"ping")
        a.close()
        d.close()
        t.join(timeout=3)

    def test_connect_tunnel_over_uds_with_pinned_upstream(self) -> None:
        echo = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        echo.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        echo.bind(("127.0.0.1", 0))
        echo.listen(1)
        echo_port = echo.getsockname()[1]
        # Globally routable pin for policy; opener maps to local echo server.
        pinned = ["8.8.8.8"]

        def serve_echo() -> None:
            conn, _ = echo.accept()
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nPONG")
            conn.close()
            echo.close()

        threading.Thread(target=serve_echo, daemon=True).start()

        def open_pinned(host, port, timeout, resolved_addrs=None):
            self.assertEqual(resolved_addrs, pinned)
            sock = socket.create_connection(("127.0.0.1", echo_port), timeout=timeout)
            return sock, "connected:local-echo"

        with tempfile.TemporaryDirectory() as tmp:
            sock_path = str(Path(tmp) / "broker.sock")
            broker = TrustedEgressBroker(
                allowed_destinations={"api.cursor.com"},
                resolve_fn=lambda h: list(pinned),
                open_upstream_fn=open_pinned,
                socket_path=sock_path,
                tunnel_deadline_seconds=5.0,
            )
            path = broker.start_unix_server(sock_path)
            try:
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.connect(path)
                client.sendall(b"CONNECT api.cursor.com:443 HTTP/1.1\r\nHost: api.cursor.com:443\r\n\r\n")
                # Read status line
                status = b""
                while b"\r\n\r\n" not in status:
                    chunk = client.recv(4096)
                    self.assertTrue(chunk, "broker closed before CONNECT 200")
                    status += chunk
                self.assertIn(b"200 Connection Established", status)
                client.sendall(b"GET / HTTP/1.1\r\nHost: api.cursor.com\r\n\r\n")
                body = b""
                while b"PONG" not in body and len(body) < 4096:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    body += chunk
                self.assertIn(b"PONG", body)
                client.close()
                stats = []
                for _ in range(50):
                    stats = broker.tunnel_stats()
                    if stats and int(stats[0].get("bytes") or 0) > 0:
                        break
                    time.sleep(0.05)
                self.assertTrue(stats)
                self.assertGreater(int(stats[0].get("bytes") or 0), 0)
            finally:
                broker.stop()

    def test_connect_200_not_sent_when_upstream_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sock_path = str(Path(tmp) / "broker.sock")
            broker = TrustedEgressBroker(
                allowed_destinations={"api.cursor.com"},
                resolve_fn=lambda h: ["8.8.8.8"],
                connect_fn=blocked_connect,
                socket_path=sock_path,
            )
            path = broker.start_unix_server(sock_path)
            try:
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.connect(path)
                client.sendall(b"CONNECT api.cursor.com:443 HTTP/1.1\r\n\r\n")
                resp = client.recv(4096)
                self.assertIn(b"502", resp)
                self.assertNotIn(b"200 Connection Established", resp)
                client.close()
            finally:
                broker.stop()

    def test_unsupported_method_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sock_path = str(Path(tmp) / "broker.sock")
            broker = TrustedEgressBroker(
                allowed_destinations={"api.cursor.com"},
                connect_fn=blocked_connect,
                socket_path=sock_path,
            )
            path = broker.start_unix_server(sock_path)
            try:
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.connect(path)
                client.sendall(b"GET http://api.cursor.com/ HTTP/1.1\r\n\r\n")
                resp = client.recv(4096)
                self.assertIn(b"405", resp)
                client.close()
            finally:
                broker.stop()

    def test_live_open_upstream_requires_pinned_addrs(self) -> None:
        sock, reason = live_open_upstream("api.cursor.com", 443, 1.0, resolved_addrs=[])
        self.assertIsNone(sock)
        self.assertEqual(reason, "no_pinned_addrs")

    def test_dns_pin_used_not_second_lookup_host(self) -> None:
        seen: dict = {}
        opened = threading.Event()

        def open_fn(host, port, timeout, resolved_addrs=None):
            seen["host"] = host
            seen["addrs"] = list(resolved_addrs or [])
            opened.set()
            return None, "forced_fail"

        broker = TrustedEgressBroker(
            allowed_destinations={"api.cursor.com"},
            resolve_fn=lambda h: ["1.1.1.1"],
            open_upstream_fn=open_fn,
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = broker.start_unix_server(str(Path(tmp) / "b.sock"))
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(path)
            client.sendall(b"CONNECT api.cursor.com:443 HTTP/1.1\r\n\r\n")
            resp = client.recv(4096)
            self.assertIn(b"502", resp)
            self.assertTrue(opened.wait(2.0))
            client.close()
            broker.stop()
        self.assertEqual(seen["addrs"], ["1.1.1.1"])


class EvidenceGateTests(unittest.TestCase):
    def test_attempted_is_not_success(self) -> None:
        obs, done, _, _, _ = parse_probe_output(
            [
                "PROBE_RESULT allowed_public attempted via_proxy",
                "PROBE_RESULT unapproved_public denied via_proxy",
                "PROBE_RESULT direct_external denied no_route",
                "PROBE_RESULT private_address denied via_proxy",
                "PROBE_RESULT ip_literal denied via_proxy",
                "PROBE_DONE",
            ]
        )
        ok, problems = evaluate_container_observations(obs, done=done)
        self.assertFalse(ok)
        self.assertTrue(any("allowed_public=attempted" in p for p in problems))
        # Pre-12.1 logic would have accepted this when policy_ok=True.
        self.assertTrue(legacy_false_positive_would_pass(obs, policy_ok=True))

    def test_incomplete_output_fails(self) -> None:
        obs, done, _, _, _ = parse_probe_output(
            [
                "PROBE_RESULT allowed_public ok via_proxy",
                "PROBE_RESULT unapproved_public denied via_proxy",
            ]
        )
        ok, problems = evaluate_container_observations(obs, done=done)
        self.assertFalse(ok)
        self.assertIn("missing_PROBE_DONE", problems)
        self.assertTrue(any("missing_observation:direct_external" in p for p in problems))

    def test_missing_python_runtime_fails(self) -> None:
        obs, done, diags, _, _ = parse_probe_output(
            [
                "EOS_RELAY_MISSING_RUNTIME python3",
                "PROBE_RESULT relay_runtime missing python3",
                "PROBE_DONE",
            ]
        )
        ok, problems = evaluate_container_observations(obs, done=done)
        self.assertFalse(ok)
        self.assertIn("relay_runtime_missing_python3", problems)
        self.assertTrue(diags)

    def test_injected_complete_evidence_completed(self) -> None:
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
            result = ex.run(
                req,
                dry_run=False,
                execute=True,
                allow_phase_b=True,
                owner_authorize_runtime_execution=True,
            )
            self.assertEqual(result.status, "COMPLETED")
            self.assertTrue(result.policy_validated)
            self.assertTrue(result.transport_verified)
            self.assertFalse(result.enforcement_verified)
            self.assertEqual(result.verification_level, "TRANSPORT_VERIFIED")
            self.assertTrue(result.cleanup["container"].get("cleaned_up"))
            self.assertTrue(result.cleanup["broker"].get("cleanup_verified"))

    def test_false_positive_injected_lines_fail(self) -> None:
        bad_lines = [
            "PROBE_RESULT allowed_public attempted via_proxy",
            "PROBE_RESULT unapproved_public denied via_proxy",
            "PROBE_RESULT private_address denied via_proxy",
            "PROBE_RESULT ip_literal denied via_proxy",
            "PROBE_RESULT direct_external denied no_route",
            "PROBE_DONE",
        ]
        with tempfile.TemporaryDirectory() as tmp:
            rt = BrokerRuntime(root=Path(tmp), connect_fn=blocked_connect)
            ex = NetworkProbeExecutor(
                broker_runtime=rt,
                process_factory=default_injected_probe_factory(lines=bad_lines),
                allow_real_podman=False,
            )
            req = NetworkProbeRequest(
                execution_id="exec-probe-falsepos1",
                project_id="p",
                image_ref="localhost/alpine:eos-fixture",
            )
            result = ex.run(
                req,
                dry_run=False,
                execute=True,
                allow_phase_b=True,
                owner_authorize_runtime_execution=True,
            )
            self.assertEqual(result.status, "FAILED")
            self.assertNotEqual(result.verification_level, "ENFORCEMENT_VERIFIED")
            self.assertIn("attempted", result.failure_reason or "")

    def test_cleanup_on_parse_incomplete(self) -> None:
        incomplete = [
            "PROBE_RESULT allowed_public ok via_proxy",
        ]
        with tempfile.TemporaryDirectory() as tmp:
            rt = BrokerRuntime(root=Path(tmp), connect_fn=blocked_connect)
            ex = NetworkProbeExecutor(
                broker_runtime=rt,
                process_factory=default_injected_probe_factory(lines=incomplete),
                allow_real_podman=False,
            )
            req = NetworkProbeRequest(
                execution_id="exec-probe-incomplete",
                project_id="p",
                image_ref="localhost/alpine:eos-fixture",
            )
            result = ex.run(
                req,
                dry_run=False,
                execute=True,
                allow_phase_b=True,
                owner_authorize_runtime_execution=True,
            )
            self.assertEqual(result.status, "FAILED")
            self.assertTrue(result.cleanup["broker"].get("cleanup_verified"))
            self.assertTrue(result.cleanup["container"].get("cleaned_up"))


class ProbeImageResolverTests(unittest.TestCase):
    def test_rejects_mutable_tags(self) -> None:
        from engineering_os.infrastructure.network.probe.probe_image import (
            ProbeImageError,
            validate_probe_image_ref,
        )

        with self.assertRaises(ProbeImageError):
            validate_probe_image_ref("docker.io/library/alpine:3.20")
        with self.assertRaises(ProbeImageError):
            validate_probe_image_ref("python:3.12-alpine")
        ok = validate_probe_image_ref("sha256:" + ("d" * 64))
        self.assertTrue(ok.startswith("sha256:"))

    def test_injected_inspect_validates_python(self) -> None:
        from engineering_os.infrastructure.network.probe.probe_image import (
            _host_arch,
            resolve_probe_image,
        )

        ref = "sha256:" + ("e" * 64)

        def inspect_fn(image_ref: str) -> dict:
            return {
                "Id": ref,
                "Digest": ref,
                "Architecture": _host_arch(),
                "Os": "linux",
                "Size": 12,
                "RepoTags": ["python:3.12-alpine"],
            }

        def py_fn(image_ref: str) -> dict:
            return {"ok": True, "version": "3.12.0", "exit_code": 0}

        identity = resolve_probe_image(
            ref,
            require_image=True,
            allow_host_inspect=True,
            verify_python=True,
            inspect_fn=inspect_fn,
            python_check_fn=py_fn,
        )
        self.assertTrue(identity.validated)
        self.assertTrue(identity.python3["ok"])
        self.assertEqual(identity.image_id, ref)

    def test_missing_python_blocks_validation(self) -> None:
        from engineering_os.infrastructure.network.probe.probe_image import (
            _host_arch,
            resolve_probe_image,
        )

        ref = "sha256:" + ("f" * 64)

        def inspect_fn(image_ref: str) -> dict:
            return {
                "Id": ref,
                "Architecture": _host_arch(),
                "Os": "linux",
                "Size": 1,
                "RepoTags": [],
            }

        def py_fn(image_ref: str) -> dict:
            return {"ok": False, "version": None, "exit_code": 127}

        identity = resolve_probe_image(
            ref,
            allow_host_inspect=True,
            verify_python=True,
            inspect_fn=inspect_fn,
            python_check_fn=py_fn,
        )
        self.assertFalse(identity.validated)
        self.assertIn("python3_missing_in_image", identity.blocked_reasons)


class ArgvAndWiringTests(unittest.TestCase):
    def test_argv_uses_host_uid_not_nobody(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sock = Path(tmp) / "broker.sock"
            sock.write_text("", encoding="utf-8")
            relay = Path(tmp) / "relay.py"
            relay.write_text("print(1)\n", encoding="utf-8")
            workload = write_probe_workload_script(Path(tmp) / "run.py")
            transport = Path(tmp) / "transport.py"
            transport.write_text("# stub\n", encoding="utf-8")
            argv = build_probe_podman_argv(
                image_ref="sha256:" + ("b" * 64),
                container_name="eos-netprobe-abcdefghijkl",
                socket_host_path=str(sock),
                relay_host_path=str(relay),
                workload_host_path=str(workload),
                transport_host_path=str(transport),
            )
            joined = " ".join(argv)
            self.assertIn(f"--user {os.getuid()}:{os.getgid()}", joined)
            self.assertNotIn("--user 65534:65534", joined)
            self.assertIn("python3 /probe/run.py", joined)
            self.assertIn("/probe/transport.py", joined)
            self.assertIn("https_connect_probe", workload.read_text(encoding="utf-8"))
            self.assertNotIn("wget", workload.read_text(encoding="utf-8"))

    def test_composition_root_wires_live_only_for_owner_real(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "eos.sqlite3"
            plane = ControlPlane.open(db)
            try:
                dry = plane.network_probe(dry_run=True)
                self.assertEqual(dry["verification_level"], "NOT_TESTED")
                self.assertFalse(dry["ENFORCEMENT_VERIFIED"])
                self.assertIn("prerequisites", dry)
                self.assertIn("python3", dry["prerequisites"]["image_must_provide"])
                self.assertTrue(
                    dry["prerequisites"]["fixture_alpine_resolver_forbidden"]
                )
                self.assertIn("probe_image_ref_required", dry["image_identity"]["blocked_reasons"])
                self.assertIn("<IMAGE_ID_REQUIRED>", " ".join(dry["argv"]))

                injected = plane.network_probe(
                    dry_run=False,
                    execute=True,
                    allow_phase_b=True,
                    owner_authorize_runtime_execution=True,
                    use_injected=True,
                )
                self.assertTrue(injected["executed"])
                self.assertEqual(injected["status"], "COMPLETED")
                self.assertFalse(
                    plane._broker_runtime.status()["live_connect_enabled"]
                )
            finally:
                plane.close()

    def test_owner_gates_still_required(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rt = BrokerRuntime(root=Path(tmp), connect_fn=blocked_connect)
            ex = NetworkProbeExecutor(
                broker_runtime=rt,
                process_factory=default_injected_probe_factory(),
            )
            req = NetworkProbeRequest(
                execution_id="exec-probe-gates0001",
                project_id="p",
                image_ref="localhost/alpine:eos-fixture",
            )
            with self.assertRaises(Exception):
                ex.run(
                    req,
                    dry_run=False,
                    execute=True,
                    allow_phase_b=False,
                    owner_authorize_runtime_execution=False,
                )


if __name__ == "__main__":
    unittest.main()
