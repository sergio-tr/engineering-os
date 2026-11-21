"""EOS-08 OCI ACP fixture executor and stdio transport tests (no real containers)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from engineering_os.application.services import ControlPlane
from engineering_os.infrastructure.acp.acp_fixture import AcpFixturePeer
from engineering_os.infrastructure.acp.sessions.acp_session import AcpSessionManager
from engineering_os.infrastructure.runtime.oci.oci_acp_transport import OciAcpStdioTransport
from engineering_os.infrastructure.runtime.oci.oci_process import InjectedFixtureProcess
from engineering_os.infrastructure.runtime.oci.podman_executor import (
    FixtureLaunchRequest,
    OwnerGateError,
    PodmanSandboxExecutor,
    build_fixture_podman_argv,
    default_injected_factory,
    require_owner_execution_gates,
)
from engineering_os.infrastructure.persistence.sqlite import Repository
from engineering_os.infrastructure.evidence import SYNTHETIC_IN_MEMORY, CURSOR_ACP_LIVE


def _tmp() -> Path:
    return Path(tempfile.mkdtemp(prefix="eos08-")) / "t.sqlite3"


class OwnerGateTests(unittest.TestCase):
    def test_incomplete_and_complete_gates(self) -> None:
        with self.assertRaises(OwnerGateError):
            require_owner_execution_gates(
                execute=True, allow_phase_b=False, owner_authorize_runtime_execution=False
            )
        with self.assertRaises(OwnerGateError):
            require_owner_execution_gates(
                execute=False, allow_phase_b=False, owner_authorize_runtime_execution=False
            )
        require_owner_execution_gates(
            execute=True, allow_phase_b=True, owner_authorize_runtime_execution=True
        )


class ArgvPolicyTests(unittest.TestCase):
    def test_fixture_argv_fail_closed(self) -> None:
        script = Path(__file__).resolve().parents[1] / (
            "src/engineering_os/infrastructure/fixtures/acp_fixture.sh"
        )
        argv = build_fixture_podman_argv(
            image_ref="localhost/alpine:3.20",
            fixture_host_path=str(script),
            container_name="eos-acp-fix-abc12345",
        )
        self.assertIn("--network", argv)
        self.assertIn("none", argv)
        self.assertIn("--cap-drop", argv)
        self.assertNotIn("--privileged", argv)
        joined = " ".join(argv)
        self.assertNotIn("docker.sock", joined)
        self.assertNotIn(".ssh", joined)
        self.assertIn("HOME=/tmp", joined)
        # Fixture bind may live under a developer path; host HOME must not be mounted as workspace.
        self.assertNotIn("dst=/home", joined)
        self.assertIn("dst=/fixture/acp_fixture.sh", joined)


class FixturePeerTransportTests(unittest.TestCase):
    def test_ndjson_lifecycle(self) -> None:
        peer = AcpFixturePeer()
        init = json.loads(
            peer.handle_line(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {"protocolVersion": 1},
                    }
                )
            )[0]
        )
        self.assertEqual(init["result"]["protocolVersion"], 1)
        handle = InjectedFixtureProcess(scenario="success")
        transport = OciAcpStdioTransport(handle, evidence_class=SYNTHETIC_IN_MEMORY)
        repo = Repository(_tmp())
        manager = AcpSessionManager(repo, transport)
        session = manager.create_session_record(
            execution_id="e1", project_id="p", task_id="t"
        )
        out = manager.run_to_completion(session, prompt_text="hi")
        self.assertEqual(out["status"], "COMPLETED")
        self.assertTrue(out["evidence_refs"])
        self.assertNotEqual(transport.summary().get("evidence_class"), CURSOR_ACP_LIVE)

    def test_timeout_and_bad_json(self) -> None:
        handle = InjectedFixtureProcess(scenario="timeout")
        transport = OciAcpStdioTransport(handle, read_timeout=0.05)
        # initialize still works
        from engineering_os.infrastructure.acp.protocol.acp_protocol import make_request, initialize_params

        resp = transport.send(make_request("initialize", initialize_params()))
        self.assertIsNotNone(resp)
        # prompt holds — send returns None after timeout reads
        created = transport.send(
            make_request("session/new", {"cwd": "/tmp", "mcpServers": []})
        )
        self.assertIsNotNone(created)
        sid = created["result"]["sessionId"]
        prompt = transport.send(
            make_request(
                "session/prompt",
                {"sessionId": sid, "prompt": [{"type": "text", "text": "x"}]},
            )
        )
        self.assertIsNone(prompt)

        bad = InjectedFixtureProcess(scenario="bad_json_response")
        t2 = OciAcpStdioTransport(bad, read_timeout=0.05)
        with self.assertRaises(Exception):
            t2.send(make_request("initialize", initialize_params()))


class ExecutorServiceTests(unittest.TestCase):
    def test_dry_run_and_demo(self) -> None:
        plane = ControlPlane.open(_tmp())
        try:
            dry = plane.run_oci_acp_fixture(dry_run=True, execute=False)
            self.assertEqual(dry["action"], "dry_run")
            demo = plane.run_sandbox_fixture_demo()
            self.assertEqual(demo["mode"], "SANDBOX_FIXTURE_OFFLINE")
            self.assertTrue(demo["gate_incomplete_rejected"]["rejected"])
            self.assertEqual(demo["result"]["run"]["status"], "COMPLETED")
            self.assertEqual(demo["result"]["provenance"], SYNTHETIC_IN_MEMORY)
            self.assertFalse(demo["live_cursor_acp"])
            hist = plane.sandbox_fixture_history(demo["result"]["project_id"])
            self.assertEqual(len(hist), 1)
            # Restart: completed run visible
            path = Path(plane.repo.db_path)
        finally:
            plane.close()
        plane2 = ControlPlane.open(path)
        try:
            hist2 = plane2.sandbox_fixture_history()
            self.assertEqual(hist2[0]["status"], "COMPLETED")
            active = [
                r for r in hist2 if r["status"] in {"RUNNING", "STARTING"}
            ]
            self.assertEqual(active, [])
        finally:
            plane2.close()

    def test_http_rejects_real_run_endpoint(self) -> None:
        import json
        import threading
        import urllib.request
        from http.cookiejar import CookieJar
        from http.server import ThreadingHTTPServer
        from engineering_os.interfaces.http_server import AppState, make_handler

        db = _tmp()
        plane = ControlPlane.open(db)
        state = AppState(plane)
        handler = make_handler(state)
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        server.quiet = True  # type: ignore[attr-defined]
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        jar = CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        try:
            base = f"http://127.0.0.1:{port}"
            csrf = json.loads(opener.open(base + "/api/csrf").read())["csrf_token"]
            req = urllib.request.Request(
                base + "/api/sandbox/run-acp-fixture",
                data=b"{}",
                headers={"Content-Type": "application/json", "X-CSRF-Token": csrf},
                method="POST",
            )
            try:
                opener.open(req)
                self.fail("expected 403")
            except Exception as exc:  # urllib.error.HTTPError
                self.assertEqual(getattr(exc, "code", None), 403)
            readiness = json.loads(
                opener.open(base + "/api/sandbox/fixture-readiness").read()
            )
            self.assertIn("status", readiness)
        finally:
            server.shutdown()
            server.server_close()
            plane.close()

    def test_executor_refuses_without_factory_when_blocked(self) -> None:
        ex = PodmanSandboxExecutor(
            process_factory=None,
            allow_real_podman=False,
            which=lambda _: None,
        )
        ready = ex.readiness()
        self.assertEqual(ready["status"], "BLOCKED")
        self.assertIn("podman_missing", ready["blocked_reasons"])


if __name__ == "__main__":
    unittest.main()
