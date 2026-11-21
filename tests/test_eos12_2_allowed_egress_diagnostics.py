"""EOS-12.2 offline tests — staged CONNECT/TLS diagnostics and broker events."""

from __future__ import annotations

import socket
import ssl
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from engineering_os.infrastructure.network.broker.egress_broker import (
    EVT_DESTINATION_DENIED,
    EVT_TUNNEL_ESTABLISHED,
    TrustedEgressBroker,
    blocked_connect,
    forward_bidirectional,
)
from engineering_os.infrastructure.network.broker.broker_runtime import BrokerRuntime
from engineering_os.infrastructure.network.probe.network_probe_executor import (
    NetworkProbeExecutor,
    NetworkProbeRequest,
    correlate_denied_with_broker,
    default_injected_probe_factory,
    evaluate_container_observations,
    parse_probe_output,
)
from engineering_os.infrastructure.network.probe.probe_transport import (
    FAILURE_CONNECT_DENIED,
    classify_os_error,
    https_connect_probe,
    wait_tcp_ready,
)


class TransportProbeUnitTests(unittest.TestCase):
    def test_wait_tcp_ready_timeout(self) -> None:
        ok, detail = wait_tcp_ready("127.0.0.1", 1, deadline_seconds=0.2)
        self.assertFalse(ok)
        self.assertIn("not_ready", detail)

    def test_connect_403_records_denied_stage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sock_path = str(Path(tmp) / "b.sock")
            broker = TrustedEgressBroker(
                allowed_destinations={"api.cursor.com"},
                connect_fn=blocked_connect,
                socket_path=sock_path,
            )
            path = broker.start_unix_server(sock_path)

            # Local TCP→UDS shim so https_connect_probe can use 127.0.0.1.
            def shim() -> None:
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind(("127.0.0.1", 0))
                srv.listen(1)
                port_holder.append(srv.getsockname()[1])
                ready.set()
                client, _ = srv.accept()
                upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                upstream.connect(path)
                forward_bidirectional(
                    client, upstream, deadline_seconds=5.0, max_bytes=65536
                )
                srv.close()

            port_holder: list = []
            ready = threading.Event()
            threading.Thread(target=shim, daemon=True).start()
            self.assertTrue(ready.wait(2.0))
            result = https_connect_probe(
                proxy_host="127.0.0.1",
                proxy_port=port_holder[0],
                target_host="evil.example",
                target_port=443,
                request_id="req-deny-unit",
                timeout=3.0,
                expect_allow=False,
            )
            broker.stop()
            self.assertEqual(result.connect_status, 403)
            self.assertFalse(result.transport_verified)
            self.assertEqual(result.failure_code, FAILURE_CONNECT_DENIED)
            events = broker.tunnel_events()
            self.assertTrue(any(e["code"] == EVT_DESTINATION_DENIED for e in events))

    def test_connect_200_then_tls_http_status(self) -> None:
        # Local TLS server behind CONNECT broker with pinned open_upstream.
        tls_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tls_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tls_srv.bind(("127.0.0.1", 0))
        tls_srv.listen(1)
        tls_port = tls_srv.getsockname()[1]

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # Self-signed will fail default verification — exercise TLS failure path.
        def serve() -> None:
            conn, _ = tls_srv.accept()
            try:
                # Plain HTTP response without TLS to force SSL error after CONNECT.
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            finally:
                conn.close()
                tls_srv.close()

        threading.Thread(target=serve, daemon=True).start()

        def open_pinned(host, port, timeout, resolved_addrs=None):
            sock = socket.create_connection(("127.0.0.1", tls_port), timeout=timeout)
            return sock, "connected:local"

        with tempfile.TemporaryDirectory() as tmp:
            sock_path = str(Path(tmp) / "b.sock")
            broker = TrustedEgressBroker(
                allowed_destinations={"api.cursor.com"},
                resolve_fn=lambda h: ["8.8.8.8"],
                open_upstream_fn=open_pinned,
                socket_path=sock_path,
            )
            path = broker.start_unix_server(sock_path)

            port_holder: list = []
            ready = threading.Event()

            def shim() -> None:
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind(("127.0.0.1", 0))
                srv.listen(1)
                port_holder.append(srv.getsockname()[1])
                ready.set()
                client, _ = srv.accept()
                upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                upstream.connect(path)
                forward_bidirectional(
                    client, upstream, deadline_seconds=5.0, max_bytes=65536
                )
                srv.close()

            threading.Thread(target=shim, daemon=True).start()
            self.assertTrue(ready.wait(2.0))
            result = https_connect_probe(
                proxy_host="127.0.0.1",
                proxy_port=port_holder[0],
                target_host="api.cursor.com",
                target_port=443,
                request_id="req-tls-fail",
                timeout=3.0,
                expect_allow=True,
            )
            broker.stop()
            self.assertEqual(result.connect_status, 200)
            self.assertFalse(result.transport_verified)
            self.assertTrue(any(e.code == "TLS_STARTED" for e in result.events))
            self.assertIsNotNone(result.failure_code)
            self.assertTrue(
                any(e["code"] == EVT_TUNNEL_ESTABLISHED for e in broker.tunnel_events())
            )

    def test_http_403_after_verified_tls_counts_as_transport(self) -> None:
        # Build a mini CONNECT proxy that wraps a real ssl server with a cert
        # matching hostname via temporary cert is heavy; instead unit-test the
        # acceptance rule in evaluate_container_observations / parse.
        obs, done, _, _, allowed = parse_probe_output(
            [
                "PROBE_ALLOWED_PATH transport_verified=true tls_ok=true cert_ok=true http_status=403 connect_status=200",
                "PROBE_RESULT allowed_public ok http_403 req1",
                "PROBE_RESULT unapproved_public denied destination_not_allowlisted req2",
                "PROBE_RESULT private_address denied ip_literal_bypass_denied req3",
                "PROBE_RESULT ip_literal denied ip_literal_bypass_denied req4",
                "PROBE_RESULT direct_external denied no_proxy:network_unreachable",
                "PROBE_DONE",
            ]
        )
        ok, problems = evaluate_container_observations(
            obs, done=done, allowed_path=allowed
        )
        self.assertTrue(ok, problems)
        self.assertEqual(allowed["http_status"], "403")


class BrokerEventTests(unittest.TestCase):
    def test_failed_upstream_emits_events_without_200(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sock_path = str(Path(tmp) / "b.sock")
            broker = TrustedEgressBroker(
                allowed_destinations={"api.cursor.com"},
                resolve_fn=lambda h: ["8.8.8.8"],
                connect_fn=blocked_connect,
                socket_path=sock_path,
            )
            path = broker.start_unix_server(sock_path)
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(path)
            client.sendall(b"CONNECT api.cursor.com:443 HTTP/1.1\r\n\r\n")
            resp = client.recv(4096)
            client.close()
            broker.stop()
            self.assertIn(b"502", resp)
            codes = [e["code"] for e in broker.tunnel_events()]
            self.assertIn("CONNECT_RECEIVED", codes)
            self.assertIn("DESTINATION_ALLOWED", codes)
            self.assertIn("UPSTREAM_CONNECT_FAILED", codes)
            self.assertNotIn(EVT_TUNNEL_ESTABLISHED, codes)

    def test_correlation_requires_broker_denials(self) -> None:
        obs = {
            "unapproved_public": "denied",
            "private_address": "denied",
            "ip_literal": "denied",
        }
        paths, problems = correlate_denied_with_broker(obs, [])
        self.assertTrue(problems)
        self.assertFalse(all(p["ok"] for p in paths))
        events = [
            {
                "code": EVT_DESTINATION_DENIED,
                "host": "evil.example",
                "ok": False,
                "detail": "destination_not_allowlisted",
            },
            {
                "code": EVT_DESTINATION_DENIED,
                "host": "10.0.0.1",
                "ok": False,
                "detail": "ip_literal_bypass_denied",
            },
            {
                "code": EVT_DESTINATION_DENIED,
                "host": "1.2.3.4",
                "ok": False,
                "detail": "ip_literal_bypass_denied",
            },
        ]
        paths, problems = correlate_denied_with_broker(obs, events)
        self.assertFalse(problems)
        self.assertTrue(all(p["ok"] for p in paths))

    def test_ipv6_loopback_not_mutilated(self) -> None:
        broker = TrustedEgressBroker(connect_fn=blocked_connect)
        d = broker.evaluate_destination("::1", 443)
        self.assertEqual(d.host, "::1")
        self.assertFalse(d.allowed)


class InjectedExecutorDiagnosticsTests(unittest.TestCase):
    def test_injected_emits_allowed_path_and_transport_verified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rt = BrokerRuntime(root=Path(tmp), connect_fn=blocked_connect)
            ex = NetworkProbeExecutor(
                broker_runtime=rt,
                process_factory=default_injected_probe_factory(),
            )
            req = NetworkProbeRequest(
                execution_id="exec-probe-diag0001",
                project_id="p",
                image_ref="sha256:" + ("a" * 64),
            )
            result = ex.run(
                req,
                dry_run=False,
                execute=True,
                allow_phase_b=True,
                owner_authorize_runtime_execution=True,
            )
            self.assertEqual(result.status, "COMPLETED")
            self.assertEqual(result.verification_level, "TRANSPORT_VERIFIED")
            self.assertFalse(result.enforcement_verified)
            self.assertTrue(result.allowed_path.get("transport_verified"))
            self.assertEqual(result.allowed_path.get("http_status"), 403)
            self.assertTrue(result.tunnel_events)
            self.assertTrue(
                any(e.get("code") == EVT_DESTINATION_DENIED for e in result.tunnel_events)
            )

    def test_opaque_failed_allowed_still_fails(self) -> None:
        bad = [
            "PROBE_RESULT allowed_public failed via_proxy",
            "PROBE_RESULT unapproved_public denied destination_not_allowlisted r1",
            "PROBE_RESULT private_address denied ip_literal_bypass_denied r2",
            "PROBE_RESULT ip_literal denied ip_literal_bypass_denied r3",
            "PROBE_RESULT direct_external denied no_proxy:network_unreachable",
            "PROBE_DONE",
        ]
        with tempfile.TemporaryDirectory() as tmp:
            rt = BrokerRuntime(root=Path(tmp), connect_fn=blocked_connect)
            ex = NetworkProbeExecutor(
                broker_runtime=rt,
                process_factory=default_injected_probe_factory(lines=bad),
            )
            req = NetworkProbeRequest(
                execution_id="exec-probe-diagfail1",
                project_id="p",
                image_ref="sha256:" + ("a" * 64),
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
            self.assertFalse(result.allowed_path.get("transport_verified"))


class ClassifyErrorTests(unittest.TestCase):
    def test_classify_connection_refused(self) -> None:
        import errno

        exc = OSError(errno.ECONNREFUSED, "refused")
        self.assertEqual(classify_os_error(exc), "connection_refused")


if __name__ == "__main__":
    unittest.main()
