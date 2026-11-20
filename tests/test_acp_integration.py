"""EOS-06 ACP protocol, sessions, orchestrator and gate tests."""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.cookiejar import CookieJar
from http.server import ThreadingHTTPServer
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from engineering_os.application.orchestrator import SequentialOrchestrator
from engineering_os.application.services import ControlPlane
from engineering_os.domain.states import IllegalTransitionError
from engineering_os.infrastructure.acp_protocol import (
    AcpProtocolError,
    make_request,
    parse_message,
)
from engineering_os.infrastructure.acp_session import AcpSessionManager
from engineering_os.infrastructure.acp_states import assert_acp_transition
from engineering_os.infrastructure.acp_transport import (
    AcpTransportError,
    CursorAcpAdapter,
    DisabledLiveAcpTransport,
    InMemoryAcpTransport,
    OpenClawAcpxExecutionTransport,
)
from engineering_os.infrastructure.sqlite_repo import Repository
from engineering_os.interfaces.http_server import AppState, make_handler


def _tmp() -> Path:
    return Path(tempfile.mkdtemp(prefix="eos-acp-")) / "t.sqlite3"


class ProtocolTests(unittest.TestCase):
    def test_envelope_and_malformed(self) -> None:
        ok = parse_message(make_request("initialize", {"protocolVersion": 1}))
        self.assertTrue(ok.is_request)
        with self.assertRaises(AcpProtocolError):
            parse_message({"id": 1, "result": {}})  # missing jsonrpc
        with self.assertRaises(AcpProtocolError):
            parse_message({"jsonrpc": "2.0", "method": "x", "result": {}})


class LifecycleTests(unittest.TestCase):
    def test_illegal_transition(self) -> None:
        with self.assertRaises(IllegalTransitionError):
            assert_acp_transition("COMPLETED", "RUNNING")


class TransportTests(unittest.TestCase):
    def test_permission_denied_by_default(self) -> None:
        transport = InMemoryAcpTransport(scenario="permission_denied")
        manager = AcpSessionManager(Repository(_tmp()), transport)
        session = manager.create_session_record(
            execution_id="e1",
            project_id="p1",
            task_id="t1",
        )
        # Need fake project/task FKs? acp_sessions has no FK to projects — OK
        out = manager.run_to_completion(session, prompt_text="hi")
        self.assertEqual(out["status"], "FAILED")
        self.assertIn("permission", out.get("failure_reason") or "")

    def test_success_and_duplicate_completion(self) -> None:
        repo = Repository(_tmp())
        transport = InMemoryAcpTransport(scenario="success")
        manager = AcpSessionManager(repo, CursorAcpAdapter(transport))
        session = manager.create_session_record(
            execution_id="e2", project_id="p", task_id="t"
        )
        out = manager.run_to_completion(session, prompt_text="hello")
        self.assertEqual(out["status"], "COMPLETED")
        self.assertTrue(out["evidence_refs"])
        events = repo.list_acp_events(out["session_id"])
        completed = [e for e in events if e["event_type"] == "acp.completed"]
        self.assertEqual(len(completed), 1)

    def test_timeout_and_interrupt(self) -> None:
        repo = Repository(_tmp())
        timed = AcpSessionManager(
            repo, CursorAcpAdapter(InMemoryAcpTransport(scenario="timeout"))
        )
        s1 = timed.create_session_record(execution_id="e3", project_id="p", task_id="t")
        self.assertEqual(
            timed.run_to_completion(s1, prompt_text="x")["status"], "TIMED_OUT"
        )
        repo2 = Repository(_tmp())
        interrupted = AcpSessionManager(
            repo2, CursorAcpAdapter(InMemoryAcpTransport(scenario="interrupt"))
        )
        s2 = interrupted.create_session_record(
            execution_id="e4", project_id="p", task_id="t"
        )
        self.assertEqual(
            interrupted.run_to_completion(s2, prompt_text="x")["status"], "FAILED"
        )

    def test_live_and_direct_bypass_rejected(self) -> None:
        disabled = DisabledLiveAcpTransport()
        with self.assertRaises(AcpTransportError):
            disabled.send(make_request("initialize", {}))
        with self.assertRaises(AcpTransportError):
            CursorAcpAdapter(
                InMemoryAcpTransport(),
                allow_direct_process=True,
                sandbox_authorized=False,
            )
        openclaw = OpenClawAcpxExecutionTransport(enabled=False)
        self.assertFalse(openclaw.availability().available)


class ServiceOrchestratorTests(unittest.TestCase):
    def test_demo_restart_and_live_reject(self) -> None:
        path = _tmp()
        plane = ControlPlane.open(path)
        result = plane.run_acp_fixture_demo()
        self.assertEqual(result["mode"], "ACP_FIXTURE_OFFLINE")
        self.assertTrue(result["live_acp_rejected"]["rejected"])
        self.assertEqual(result["ready_after"], [result["task2_id"]])
        execution_id = result["simulated"]["execution"]["execution_id"]
        plane.close()
        plane2 = ControlPlane.open(path)
        sessions = plane2.list_acp_sessions(result["project_id"])
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0]["status"], "COMPLETED")
        detail = plane2.get_acp_session_for_execution(execution_id)
        self.assertGreaterEqual(len(detail["events"]), 3)
        # No duplicate active sessions
        active = [
            s
            for s in sessions
            if s["status"] not in {"COMPLETED", "FAILED", "CANCELLED", "TIMED_OUT"}
        ]
        self.assertEqual(active, [])
        plane2.close()

    def test_duplicate_dispatch_suppressed(self) -> None:
        plane = ControlPlane.open(_tmp())
        try:
            project = plane.create_project("P", "r/p")
            goal = plane.create_goal(project.project_id, "g")
            task = plane.create_task(goal.goal_id, "t")
            plane.approve_goal(goal.goal_id)
            orch = SequentialOrchestrator(plane)
            first = orch.simulate_acp(project.project_id)
            self.assertEqual(first["action"], "acp_dispatched")
            second = orch.simulate_acp(project.project_id)
            self.assertEqual(second["action"], "claim_held")
        finally:
            plane.close()

    def test_gate_blocks_live_request(self) -> None:
        plane = ControlPlane.open(_tmp())
        try:
            out = plane.request_live_acp_transport()
            self.assertTrue(out["rejected"])
            self.assertEqual(plane.sandbox_gate, "NOT_TESTED")
            caps = plane.acp_capabilities()
            self.assertEqual(
                caps["live_transport"]["details"].get("reason"),
                "live_acp_disabled_sandbox_not_pass",
            )
        finally:
            plane.close()

    def test_idempotent_session_create(self) -> None:
        repo = Repository(_tmp())
        manager = AcpSessionManager(repo, InMemoryAcpTransport())
        a = manager.create_session_record(
            execution_id="same", project_id="p", task_id="t"
        )
        b = manager.create_session_record(
            execution_id="same", project_id="p", task_id="t"
        )
        self.assertEqual(a["session_id"], b["session_id"])


class AcpHttpApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = _tmp()
        self.plane = ControlPlane.open(self.db)
        self.state = AppState(self.plane)
        handler = make_handler(self.state)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.server.quiet = True  # type: ignore[attr-defined]
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.port}"
        self.jar = CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar)
        )

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.plane.close()

    def _get(self, path: str):
        req = urllib.request.Request(self.base + path)
        with self.opener.open(req) as resp:
            return resp.status, json.loads(resp.read().decode())

    def _csrf(self) -> str:
        status, data = self._get("/api/csrf")
        self.assertEqual(status, 200)
        return data["csrf_token"]

    def _post(self, path: str, payload: dict):
        body = json.dumps(payload).encode()
        headers = {
            "Content-Type": "application/json",
            "X-CSRF-Token": self._csrf(),
        }
        req = urllib.request.Request(
            self.base + path, data=body, headers=headers, method="POST"
        )
        try:
            with self.opener.open(req) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def test_acp_status_capabilities_and_demo(self) -> None:
        status, caps = self._get("/api/acp/capabilities")
        self.assertEqual(status, 200)
        self.assertEqual(caps["permission_policy"], "deny_by_default")
        status, runtime = self._get("/api/acp/status")
        self.assertEqual(status, 200)
        self.assertFalse(runtime.get("live_acp_enabled", True))
        status, demo = self._post("/api/acp/demo", {})
        self.assertEqual(status, 200)
        self.assertEqual(demo["mode"], "ACP_FIXTURE_OFFLINE")
        self.assertTrue(demo["live_acp_rejected"]["rejected"])
        status, sessions = self._get("/api/acp/sessions")
        self.assertEqual(status, 200)
        self.assertEqual(len(sessions), 1)
        exec_id = demo["simulated"]["execution"]["execution_id"]
        status, detail = self._get(f"/api/acp/sessions/{exec_id}")
        self.assertEqual(status, 200)
        self.assertEqual(detail["mode"], "SYNTHETIC")
        self.assertGreaterEqual(len(detail["events"]), 3)
        status, blocked = self._post(
            "/api/acp/simulate", {"project_id": demo["project_id"], "live": True}
        )
        self.assertEqual(status, 403)
        self.assertEqual(blocked["error"], "live_acp_disabled")

    def test_dashboard_mentions_acp_panel(self) -> None:
        req = urllib.request.Request(self.base + "/")
        with self.opener.open(req) as resp:
            html = resp.read().decode()
        self.assertIn("ACP runtime", html)
        self.assertIn("btn-acp-demo", html)
        self.assertNotIn("Start live ACP", html)


if __name__ == "__main__":
    unittest.main()
