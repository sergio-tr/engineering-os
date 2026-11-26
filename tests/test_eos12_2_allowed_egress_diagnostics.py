"""EOS-12.2 offline tests — staged CONNECT/TLS diagnostics and broker events."""

from __future__ import annotations

import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import Mock, create_autospec, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from engineering_os.infrastructure.network.broker.egress_broker import (
    EVT_DESTINATION_DENIED,
    EVT_TUNNEL_BYTES_TRANSFERRED,
    EVT_TUNNEL_ESTABLISHED,
    TrustedEgressBroker,
    blocked_connect,
    forward_bidirectional,
)
from engineering_os.infrastructure.network.broker.broker_runtime import (
    BrokerInstance,
    BrokerRuntime,
)
from engineering_os.infrastructure.network.probe.network_probe_executor import (
    InjectedNetworkProbeProcess,
    NetworkProbeExecutor,
    NetworkProbeRequest,
    correlate_allowed_with_broker,
    correlate_denied_with_broker,
    default_injected_probe_factory,
)
from engineering_os.infrastructure.network.probe.probe_image import synthetic_probe_image
from engineering_os.infrastructure.network.probe.probe_transport import (
    FAILURE_BROKER_REQUEST_ID,
    FAILURE_CONNECT_DENIED,
    FAILURE_HTTP,
    classify_os_error,
    https_connect_probe,
    wait_tcp_ready,
)

BROKER_ID = "breq-0123456789ab"
OTHER_BROKER_ID = "breq-0123456789cd"
CLIENT_ID = "req-allow-inj"
CONTAINER_ID = "a" * 64
OPENSSL = shutil.which("openssl")


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

    def test_connect_200_without_tls_fails(self) -> None:
        # Local plaintext server behind CONNECT broker with pinned open_upstream.
        tls_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tls_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tls_srv.bind(("127.0.0.1", 0))
        tls_srv.listen(1)
        tls_port = tls_srv.getsockname()[1]

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
            established = [
                e for e in broker.tunnel_events() if e["code"] == EVT_TUNNEL_ESTABLISHED
            ]
            self.assertEqual(len(established), 1)
            self.assertEqual(result.broker_request_id, established[0]["request_id"])
            self.assertNotEqual(result.broker_request_id, result.request_id)

    def probe_response(self, connect_headers: bytes, http_response: bytes = b""):
        raw = Mock(spec=socket.socket)
        raw.recv.side_effect = [connect_headers, b""]
        tls = Mock(spec=ssl.SSLSocket)
        tls.recv.side_effect = [http_response, b""]
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        with (
            patch.object(socket, "create_connection", return_value=raw),
            patch.object(ssl, "create_default_context", return_value=context),
            patch.object(context, "wrap_socket", return_value=tls) as wrap,
        ):
            result = https_connect_probe(request_id=CLIENT_ID)
        return result, context, wrap

    def test_connect_rejects_missing_unissued_or_ambiguous_broker_id(self) -> None:
        header = b"X-EOS-Request-Id: " + BROKER_ID.encode() + b"\r\n"
        for fields, expected_status in (
            (b"", 200),
            (b"X-EOS-Request-Id: req-allow-inj\r\n", 200),
            (b"X-EOS-Request-Id: breq-invalid\r\n", 200),
            (header + header, None),
            (header[:-2], None),
        ):
            with self.subTest(fields=fields, expected_status=expected_status):
                ending = b"" if fields == header[:-2] else b"\r\n"
                result, _, wrap = self.probe_response(
                    b"HTTP/1.1 200 Connection Established\r\n" + fields + ending
                )
                self.assertEqual(result.connect_status, expected_status)
                self.assertIsNone(result.broker_request_id)
                self.assertFalse(result.transport_verified)
                if expected_status == 200:
                    self.assertEqual(result.failure_code, FAILURE_BROKER_REQUEST_ID)
                wrap.assert_not_called()

    def test_verified_tls_context_and_http_error_statuses(self) -> None:
        connect = (
            b"HTTP/1.1 200 Connection Established\r\n"
            b"x-eos-request-id: " + BROKER_ID.encode() + b"\r\n\r\n"
        )
        for status in (401, 403, 404):
            with self.subTest(status=status):
                result, context, wrap = self.probe_response(
                    connect, f"HTTP/1.1 {status} Application Error\r\n\r\n".encode()
                )
                self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
                self.assertTrue(context.check_hostname)
                self.assertEqual(wrap.call_args.kwargs["server_hostname"], "api.cursor.com")
                self.assertEqual(result.request_id, CLIENT_ID)
                self.assertEqual(result.broker_request_id, BROKER_ID)
                self.assertEqual(result.http_status, status)
                self.assertTrue(result.tls_ok and result.cert_ok and result.transport_verified)

    def test_tls_alone_cannot_verify_malformed_or_interim_http(self) -> None:
        connect = (
            b"HTTP/1.1 200 Connection Established\r\n"
            b"X-EOS-Request-Id: " + BROKER_ID.encode() + b"\r\n\r\n"
        )
        for response in (
            b"NOT-HTTP 403 Forbidden\r\n\r\n",
            b"HTTP/1.1 403 Forbidden\r\n",
            b"HTTP/1.1 403 Forbidden\r\nBroken header\r\n\r\n",
            b"HTTP/1.1 103 Early Hints\r\n\r\n",
        ):
            with self.subTest(response=response):
                result, _, _ = self.probe_response(connect, response)
                self.assertTrue(result.tls_ok and result.cert_ok)
                self.assertFalse(result.transport_verified)
                self.assertEqual(result.failure_code, FAILURE_HTTP)

    @unittest.skipUnless(OPENSSL, "openssl CLI required for a disposable TLS certificate")
    def test_http_403_after_verified_tls_counts_as_transport(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cert = Path(tmp) / "cert.pem"
            key = Path(tmp) / "key.pem"
            subprocess.run(
                [
                    OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=api.cursor.com", "-addext", "subjectAltName=DNS:api.cursor.com",
                    "-keyout", str(key), "-out", str(cert),
                ],
                capture_output=True,
                check=True,
                timeout=10,
            )
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(cert, key)
            # Trust only this test certificate while retaining hostname verification.
            client_context = ssl.create_default_context(cafile=str(cert))

        client, broker_client = socket.socketpair()
        origin, broker_upstream = socket.socketpair()
        broker = TrustedEgressBroker(
            resolve_fn=lambda _: ["8.8.8.8"],
            open_upstream_fn=lambda *_: (broker_upstream, "connected:socketpair"),
            tunnel_deadline_seconds=4,
        )

        def serve() -> bytes:
            with server_context.wrap_socket(origin, server_side=True) as tls:
                with tls.makefile("rb") as stream:
                    request = stream.readline()
                    while stream.readline() not in (b"\r\n", b""):
                        pass
                tls.sendall(
                    b"HTTP/1.1 103 Early Hints\r\n\r\n"
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
                )
                return request

        with broker_client, broker_upstream, ThreadPoolExecutor(max_workers=2) as threads:
            with client, origin:
                client.settimeout(3)
                origin.settimeout(3)
                worker = threads.submit(broker._handle_client, broker_client)
                server = threads.submit(serve)
                with (
                    patch.object(socket, "create_connection", return_value=client),
                    patch.object(ssl, "create_default_context", return_value=client_context),
                ):
                    result = https_connect_probe(request_id=CLIENT_ID, timeout=3)
                self.assertEqual(server.result(timeout=4), b"GET / HTTP/1.1\r\n")
            worker.result(timeout=4)
        self.assertEqual(result.http_status, 403)
        self.assertTrue(result.tls_ok and result.cert_ok and result.transport_verified)
        evidence = correlate_allowed_with_broker(result.to_dict(), broker.tunnel_events())
        self.assertTrue(evidence.verified, broker.tunnel_events())


class BrokerEventTests(unittest.TestCase):
    def test_broker_records_both_forwarding_directions_for_its_connect_id(self) -> None:
        client, broker_client = socket.socketpair()
        origin, broker_upstream = socket.socketpair()
        broker = TrustedEgressBroker(
            resolve_fn=lambda _: ["8.8.8.8"],
            open_upstream_fn=lambda *_: (broker_upstream, "connected:socketpair"),
        )
        with broker_client, broker_upstream, ThreadPoolExecutor(max_workers=1) as threads:
            with client, origin:
                client.settimeout(2)
                origin.settimeout(2)
                worker = threads.submit(broker._handle_client, broker_client)
                client.sendall(
                    b"CONNECT api.cursor.com:443 HTTP/1.1\r\n"
                    b"X-EOS-Request-Id: " + CLIENT_ID.encode() + b"\r\n\r\n"
                )
                with client.makefile("rb") as response:
                    self.assertIn(b"200 Connection Established", response.readline())
                    name, value = response.readline().split(b":", maxsplit=1)
                    self.assertEqual(name, b"X-EOS-Request-Id")
                    self.assertEqual(response.readline(), b"\r\n")
                client.sendall(b"ping")
                self.assertEqual(origin.recv(4, socket.MSG_WAITALL), b"ping")
                origin.sendall(b"pong!")
                self.assertEqual(client.recv(5, socket.MSG_WAITALL), b"pong!")
            worker.result(timeout=2)
        broker_id = value.strip().decode()
        self.assertNotEqual(broker_id, CLIENT_ID)
        evidence = correlate_allowed_with_broker(
            {"request_id": CLIENT_ID, "broker_request_id": broker_id}, broker.tunnel_events()
        )
        self.assertTrue(evidence.verified, broker.tunnel_events())
        stats = broker.tunnel_stats()[0]
        self.assertEqual(stats["request_id"], broker_id)
        self.assertEqual(stats["bytes"], 9)
        self.assertEqual(stats["client_to_upstream"], 4)
        self.assertEqual(stats["upstream_to_client"], 5)

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


class EnforcementEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.lines = [
            f"PROBE_EVENT allowed_public CONNECT_200 ok connection_established {CLIENT_ID}",
            f"PROBE_EVENT allowed_public TLS_COMPLETED ok handshake_ok {CLIENT_ID}",
            f"PROBE_EVENT allowed_public CERT_VALIDATED ok hostname=api.cursor.com {CLIENT_ID}",
            f"PROBE_EVENT allowed_public HTTP_SENT ok GET_/ {CLIENT_ID}",
            f"PROBE_EVENT allowed_public HTTP_RESPONSE ok status=403 {CLIENT_ID}",
            "PROBE_ALLOWED_PATH relay_ready=true connect_status=200 tls_ok=true cert_ok=true "
            "http_status=403 transport_verified=true failure_stage=- failure_code=- "
            f"request_id={CLIENT_ID} broker_request_id={BROKER_ID}",
            f"PROBE_RESULT allowed_public ok http_403 {CLIENT_ID}",
            f"PROBE_HTTP allowed_public 403 {CLIENT_ID}",
            "PROBE_RESULT unapproved_public denied destination_not_allowlisted req-deny-1",
            "PROBE_RESULT private_address denied ip_literal_bypass_denied req-deny-2",
            "PROBE_RESULT ip_literal denied ip_literal_bypass_denied req-deny-3",
            "PROBE_RESULT direct_external denied no_proxy:network_unreachable",
            "PROBE_DONE",
        ]
        self.allowed_events = [
            {
                "code": code,
                "request_id": BROKER_ID,
                "host": "api.cursor.com",
                "port": 443,
                "ok": True,
                "detail": detail,
            }
            for code, detail in (
                ("CONNECT_RECEIVED", f"client_req_id={CLIENT_ID}"),
                ("DESTINATION_ALLOWED", "allowlisted_via_broker"),
                ("DNS_RESOLVED", "addrs=1"),
                ("UPSTREAM_CONNECT_STARTED", "pinned=1"),
                ("UPSTREAM_CONNECTED", "connected:synthetic"),
                (EVT_TUNNEL_ESTABLISHED, ""),
                (EVT_TUNNEL_BYTES_TRANSFERRED, "bytes=9 client_to_upstream=4 upstream_to_client=5"),
                ("TUNNEL_CLOSED", "peer_closed"),
            )
        ]
        self.denied_events = [
            {
                "code": EVT_DESTINATION_DENIED,
                "request_id": f"breq-00000000000{i}",
                "host": host,
                "port": 443,
                "ok": False,
            }
            for i, host in enumerate(("evil.example", "10.0.0.1", "1.2.3.4"))
        ]

    def run_fixture(
        self, *, events=None, lines=None, container_cleanup=True, broker_cleanup=True,
        injected=False, cleanup_overrides=None
    ):
        work_dir = Path(self.temp.name)
        runtime = create_autospec(BrokerRuntime, instance=True)
        runtime.get.return_value = TrustedEgressBroker(connect_fn=blocked_connect)
        (work_dir / "broker.sock").touch()
        (work_dir / "relay.py").touch()
        runtime.start.return_value = BrokerInstance(
            "broker-fixture", "exec-fixture", str(work_dir / "broker.sock"),
            str(work_dir / "relay.py"), str(work_dir), "fixture",
        )
        runtime.interrupt.return_value = {"evaluate_api_cursor": {"allowed": False}}
        runtime.stop.return_value = {
            "cleanup_verified": broker_cleanup,
            "tunnel_events": self.allowed_events + self.denied_events if events is None else events,
        }
        handle = InjectedNetworkProbeProcess(
            container_id=CONTAINER_ID, lines=self.lines if lines is None else lines
        )
        cleanup = {
            "container_id": CONTAINER_ID,
            "cleaned_up": container_cleanup,
            "cleanup_requested": True,
            "cleanup_verified": container_cleanup,
            "cleanup_returncode": 0 if container_cleanup else 125,
            "removal_succeeded": container_cleanup,
            "container_presence": {
                "container_id": CONTAINER_ID,
                "state": "absent" if container_cleanup else "unknown",
                "returncode": 1 if container_cleanup else None,
            },
            **(cleanup_overrides or {}),
        }
        executor = NetworkProbeExecutor(
            broker_runtime=runtime,
            allow_real_podman=True,
            process_factory=(lambda _: handle) if injected else None,
        )
        digest = "sha256:" + "a" * 64
        module = "engineering_os.infrastructure.network.probe.network_probe_executor"

        def start(argv, *, container_name):
            return handle, argv

        with (
            patch.object(executor, "resolve_image", return_value=synthetic_probe_image(digest)),
            patch.object(handle, "cleanup", return_value=cleanup),
            patch(f"{module}.SubprocessOciHandle.start_podman", side_effect=start) as spawn,
            patch(f"{module}._seed_broker_policy_denials"),
        ):
            result = executor.run(
                NetworkProbeRequest("exec-fixture", "project", digest),
                dry_run=False,
                execute=True,
                allow_phase_b=True,
                owner_authorize_runtime_execution=True,
            )
        self.assertEqual(spawn.call_count, 0 if injected else 1, result.failure_reason)
        return result

    def test_complete_correlation_is_required_by_the_podman_branch(self) -> None:
        # Evaluate the real-mode decision with mocked process and broker I/O.
        unrelated = [
            {**event, "request_id": OTHER_BROKER_ID, "ok": False}
            for event in self.allowed_events
        ]
        lines = ["PROBE_HTTP unrelated_case 200 req-other", *self.lines]
        result = self.run_fixture(
            events=unrelated + self.allowed_events + self.denied_events, lines=lines
        )
        self.assertTrue(result.enforcement_verified, result.failure_reason)
        self.assertEqual(result.verification_level, "ENFORCEMENT_VERIFIED")
        self.assertEqual(result.allowed_path["request_id"], CLIENT_ID)
        self.assertEqual(result.allowed_path["broker_request_id"], BROKER_ID)
        self.assertEqual(result.allowed_path["http_status"], 403)
        self.assertEqual(result.allowed_path["raw"]["http_statuses"], {"allowed_public": "403"})
        self.assertTrue(result.allowed_path["broker_correlation_verified"])
        self.assertTrue(result.allowed_path["bidirectional_traffic"])
        self.assertTrue(all(path["ok"] for path in result.denied_paths))

    def test_broker_evidence_cannot_be_borrowed_from_other_requests(self) -> None:
        for missing, field in (
            ("UPSTREAM_CONNECTED", "upstream_connected"),
            (EVT_TUNNEL_ESTABLISHED, "tunnel_established"),
            (EVT_TUNNEL_BYTES_TRANSFERRED, "bidirectional_traffic"),
        ):
            for unrelated in (False, True):
                with self.subTest(missing=missing, unrelated=unrelated):
                    events = [e for e in self.allowed_events if e["code"] != missing]
                    if unrelated:
                        events += [
                            {**e, "request_id": OTHER_BROKER_ID} for e in self.allowed_events
                        ]
                    result = self.run_fixture(events=events + self.denied_events)
                    self.assertFalse(result.enforcement_verified)
                    self.assertFalse(result.allowed_path[field])
                    self.assertTrue(result.transport_verified)
                    self.assertEqual(result.failure_reason, "broker_allowed_correlation_incomplete")

    def test_no_or_contradictory_broker_evidence_fails_closed(self) -> None:
        for name, events in (
            ("missing_broker_chain", []),
            ("wrong_broker_id", [{**e, "request_id": OTHER_BROKER_ID} for e in self.allowed_events]),
            ("wrong_client_id", [
                {**self.allowed_events[0], "detail": "client_req_id=req-other"},
                *self.allowed_events[1:],
            ]),
            ("wrong_host", [*self.allowed_events[:-1], {**self.allowed_events[-1], "host": "other.example"}]),
            ("wrong_port", [*self.allowed_events[:-1], {**self.allowed_events[-1], "port": 8443}]),
            ("wrong_order", [self.allowed_events[1], self.allowed_events[0], *self.allowed_events[2:]]),
            ("duplicate_stage", [*self.allowed_events[:3], *self.allowed_events[2:]]),
            ("tunnel_error", [*self.allowed_events[:-1], {**self.allowed_events[-1], "code": "TUNNEL_ERROR", "ok": False}]),
        ):
            with self.subTest(name=name):
                result = self.run_fixture(events=events + self.denied_events)
                self.assertFalse(result.enforcement_verified)
                self.assertFalse(result.allowed_path["broker_correlation_verified"])
                self.assertTrue(result.transport_verified)
                if name in {"missing_broker_chain", "wrong_broker_id", "wrong_client_id", "wrong_host", "wrong_port"}:
                    self.assertFalse(result.allowed_path["broker_connected"])
                    self.assertFalse(result.allowed_path["destination_allowed"])

    def test_byte_evidence_requires_positive_counts_in_both_directions(self) -> None:
        for detail in (
            "bytes=0 client_to_upstream=0 upstream_to_client=0",
            "bytes=9",
            "bytes=9 client_to_upstream=0 upstream_to_client=9",
            "bytes=9 client_to_upstream=9 upstream_to_client=0",
            "bytes=99 client_to_upstream=4 upstream_to_client=5",
        ):
            with self.subTest(detail=detail):
                events = [
                    {**e, "detail": detail} if e["code"] == EVT_TUNNEL_BYTES_TRANSFERRED else e
                    for e in self.allowed_events
                ]
                result = self.run_fixture(events=events + self.denied_events)
                self.assertFalse(result.enforcement_verified)
                self.assertFalse(result.allowed_path["bidirectional_traffic"])

    def test_missing_broker_id_fails_correlation_even_with_a_complete_chain(self) -> None:
        lines = [line.replace(f" broker_request_id={BROKER_ID}", "") for line in self.lines]
        result = self.run_fixture(lines=lines)
        self.assertIsNone(result.allowed_path["broker_request_id"])
        self.assertFalse(result.allowed_path["broker_connected"])
        self.assertFalse(result.enforcement_verified)

    def test_container_records_must_agree_on_the_request_tls_and_http(self) -> None:
        for search, replacement in (
            ("TLS_COMPLETED ok", "TLS_COMPLETED fail"),
            ("tls_ok=true", "tls_ok=false"),
            ("CERT_VALIDATED ok hostname=api.cursor.com", "CERT_VALIDATED ok hostname=other.example"),
            (f"TLS_COMPLETED ok handshake_ok {CLIENT_ID}", "TLS_COMPLETED ok handshake_ok other"),
            (f"ok http_403 {CLIENT_ID}", "ok http_403 other"),
            ("HTTP_RESPONSE ok status=403", "HTTP_RESPONSE ok status=404"),
            ("PROBE_HTTP allowed_public 403", "PROBE_HTTP allowed_public 404"),
            ("PROBE_EVENT allowed_public HTTP_SENT", "PROBE_EVENT_EXTRA allowed_public HTTP_SENT"),
            ("connect_status=200", "connect_status=200 connect_status=403"),
        ):
            with self.subTest(search=search):
                result = self.run_fixture(lines=[line.replace(search, replacement) for line in self.lines])
                self.assertFalse(result.transport_verified)
                self.assertFalse(result.enforcement_verified)

    def test_denial_confirmation_and_container_observation_are_independent(self) -> None:
        result = self.run_fixture(events=self.allowed_events + self.denied_events[1:])
        self.assertTrue(result.allowed_path["broker_correlation_verified"])
        self.assertFalse(result.enforcement_verified)
        self.assertIn("missing_broker_deny:unapproved_public", result.failure_reason)
        lines = [line.replace("private_address denied", "private_address LEAK") for line in self.lines]
        result = self.run_fixture(lines=lines)
        self.assertFalse(result.enforcement_verified)
        self.assertIn("denied_case_not_ok:private_address=LEAK", result.failure_reason)

    def test_cleanup_failure_cannot_verify_enforcement(self) -> None:
        for container, broker in ((False, True), (True, False)):
            with self.subTest(container=container, broker=broker):
                result = self.run_fixture(container_cleanup=container, broker_cleanup=broker)
                self.assertTrue(result.allowed_path["broker_correlation_verified"])
                self.assertEqual(result.status, "FAILED")
                self.assertEqual(result.failure_reason, "probe_cleanup_incomplete")
                self.assertFalse(result.enforcement_verified)

    def test_complete_network_evidence_cannot_override_invalid_cleanup(self) -> None:
        for overrides in (
            {"cleaned_up": True, "cleanup_verified": False},
            {"cleaned_up": False, "cleanup_verified": True},
            {"cleanup_returncode": None},
            {"cleanup_returncode": 125},
            {"container_id": "b" * 64},
            {"container_presence": None},
            {"container_presence": {"container_id": "b" * 64, "state": "absent", "returncode": 1}},
            {"container_presence": {"container_id": CONTAINER_ID, "state": "present", "returncode": 0}},
            {"container_presence": {"container_id": CONTAINER_ID, "state": "unknown", "returncode": None}},
            {"container_presence": {"container_id": CONTAINER_ID, "state": "absent", "returncode": 125}},
        ):
            with self.subTest(overrides=overrides):
                result = self.run_fixture(cleanup_overrides=overrides)
                self.assertTrue(result.cleanup["broker"]["cleanup_verified"])
                self.assertTrue(result.transport_verified)
                self.assertTrue(result.allowed_path["broker_correlation_verified"])
                self.assertTrue(all(path["ok"] for path in result.denied_paths))
                self.assertFalse(result.enforcement_verified)
                self.assertEqual(result.status, "FAILED")
                self.assertEqual(result.failure_reason, "probe_cleanup_incomplete")

    def test_injected_run_with_complete_evidence_cannot_verify_enforcement(self) -> None:
        result = self.run_fixture(injected=True)
        self.assertEqual(result.verification_level, "TRANSPORT_VERIFIED")
        self.assertTrue(result.allowed_path["broker_correlation_verified"])
        self.assertFalse(result.enforcement_verified)


class ClassifyErrorTests(unittest.TestCase):
    def test_classify_connection_refused(self) -> None:
        import errno

        exc = OSError(errno.ECONNREFUSED, "refused")
        self.assertEqual(classify_os_error(exc), "connection_refused")


if __name__ == "__main__":
    unittest.main()
