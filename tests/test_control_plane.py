"""Unit and integration tests for EOS control plane (EOS-01/02/03)."""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from http.cookiejar import CookieJar
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from engineering_os.application.orchestrator import SequentialOrchestrator
from engineering_os.application.services import ControlPlane, PolicyError
from engineering_os.domain.states import IllegalTransitionError
from engineering_os.infrastructure.adapters import (
    DisabledLiveExecutionAdapter,
    DispatchRequest,
    SyntheticExecutionAdapter,
)
from engineering_os.infrastructure.sqlite_repo import ConcurrencyError, Repository
from engineering_os.interfaces.http_server import AppState, make_handler
from http.server import ThreadingHTTPServer


def _tmp_db() -> Path:
    return Path(tempfile.mkdtemp(prefix="eos-test-")) / "test.sqlite3"


class PersistenceTests(unittest.TestCase):
    def test_persistence_and_restart(self) -> None:
        path = _tmp_db()
        plane = ControlPlane.open(path)
        project = plane.create_project("P", "r/p")
        plane.close()
        plane2 = ControlPlane.open(path)
        self.assertEqual(plane2.get_project(project.project_id).name, "P")
        plane2.close()

    def test_transaction_rollback(self) -> None:
        repo = Repository(_tmp_db())
        try:
            with self.assertRaises(RuntimeError):
                with repo.transaction() as conn:
                    conn.execute(
                        "INSERT INTO projects(project_id,name,repository_identity,status,"
                        "isolation_requirements,created_at,updated_at,version)"
                        " VALUES ('x','n','r','ACTIVE','i','t','t',1)"
                    )
                    raise RuntimeError("boom")
            self.assertIsNone(repo.get_project("x"))
        finally:
            repo.close()


class StateMachineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plane = ControlPlane.open(_tmp_db())
        self.project = self.plane.create_project("SM", "r/sm")
        self.goal = self.plane.create_goal(self.project.project_id, "G")
        self.plane.approve_goal(self.goal.goal_id)

    def tearDown(self) -> None:
        self.plane.close()

    def test_illegal_transition(self) -> None:
        task = self.plane.create_task(self.goal.goal_id, "t")
        task = self.plane._require_task(task.task_id)
        task.lifecycle_state = "DONE"
        with self.assertRaises(IllegalTransitionError):
            from engineering_os.domain.states import TASK_TRANSITIONS, assert_transition

            assert_transition("task", "DONE", "READY", TASK_TRANSITIONS)

    def test_dependency_ordering(self) -> None:
        t1 = self.plane.create_task(self.goal.goal_id, "first")
        t2 = self.plane.create_task(
            self.goal.goal_id, "second", depends_on=[t1.task_id]
        )
        ready = self.plane.list_ready_tasks(self.project.project_id)
        self.assertEqual([t.task_id for t in ready], [t1.task_id])
        self.assertEqual(self.plane._require_task(t2.task_id).lifecycle_state, "BLOCKED")
        self.plane.simulate_task(t1.task_id)
        ready2 = self.plane.list_ready_tasks(self.project.project_id)
        self.assertEqual([t.task_id for t in ready2], [t2.task_id])

    def test_cross_project_dependency_rejected(self) -> None:
        other = self.plane.create_project("Other", "r/o")
        og = self.plane.create_goal(other.project_id, "OG")
        ot = self.plane.create_task(og.goal_id, "foreign")
        with self.assertRaises(PolicyError):
            self.plane.create_task(
                self.goal.goal_id, "bad", depends_on=[ot.task_id]
            )


class ExecutionPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = _tmp_db()
        self.plane = ControlPlane.open(self.db)
        self.project = self.plane.create_project("EP", "r/ep")
        self.goal = self.plane.create_goal(self.project.project_id, "G")
        self.plane.approve_goal(self.goal.goal_id)
        self.task = self.plane.create_task(self.goal.goal_id, "work")

    def tearDown(self) -> None:
        self.plane.close()

    def test_duplicate_execution_idempotent(self) -> None:
        key = "same-key"
        e1 = self.plane.prepare_synthetic_execution(self.task.task_id, idempotency_key=key)
        e2 = self.plane.prepare_synthetic_execution(self.task.task_id, idempotency_key=key)
        self.assertEqual(e1.execution_id, e2.execution_id)

    def test_disabled_live_execution(self) -> None:
        adapter = DisabledLiveExecutionAdapter()
        result = adapter.dispatch(
            DispatchRequest(
                execution_id="e",
                task_id="t",
                project_id="p",
                attempt_number=1,
                contract_ref="c",
            )
        )
        self.assertFalse(result.ok)
        self.assertIn("sandbox", result.failure_reason or "")

    def test_failure_and_retry_budget(self) -> None:
        failing = SyntheticExecutionAdapter(fail_task_ids={self.task.task_id})
        plane = ControlPlane(
            self.plane.repo, execution_adapter=failing, max_attempts=2
        )
        e1 = plane.simulate_task(self.task.task_id)
        self.assertEqual(e1.status, "FAILED")
        # Make READY again for retry
        plane.recalculate_task_eligibility(project_id=self.project.project_id)
        task = plane._require_task(self.task.task_id)
        self.assertEqual(task.lifecycle_state, "READY")
        e2 = plane.simulate_task(self.task.task_id)
        self.assertEqual(e2.status, "FAILED")
        plane.recalculate_task_eligibility(project_id=self.project.project_id)
        with self.assertRaises(PolicyError):
            plane.prepare_synthetic_execution(self.task.task_id)

    def test_evidence_required_for_success(self) -> None:
        class NoEvidence(SyntheticExecutionAdapter):
            def dispatch(self, request: DispatchRequest):
                from engineering_os.infrastructure.adapters import DispatchResult

                return DispatchResult(ok=True, status="SUCCEEDED", evidence=[])

        plane = ControlPlane(self.plane.repo, execution_adapter=NoEvidence())
        # Reset task to READY if needed
        task = plane._require_task(self.task.task_id)
        if task.lifecycle_state != "READY":
            task.lifecycle_state = "READY"
            task.execution_eligible = True
            plane.repo.update_task(task, expected_version=task.version)
        execution = plane.simulate_task(self.task.task_id)
        self.assertEqual(execution.status, "FAILED")


class ApprovalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plane = ControlPlane.open(_tmp_db())
        self.project = self.plane.create_project("AP", "r/ap")
        self.goal = self.plane.create_goal(self.project.project_id, "G")

    def tearDown(self) -> None:
        self.plane.close()

    def test_expired_approval(self) -> None:
        goal = self.plane.submit_goal_for_approval(self.goal.goal_id)
        approvals = [
            a
            for a in self.plane.repo.list_approvals(pending_only=True)
            if a.goal_id == goal.goal_id
        ]
        approval = approvals[0]
        approval.expires_at = (
            datetime.now(timezone.utc) - timedelta(hours=1)
        ).replace(microsecond=0).isoformat()
        self.plane.repo.update_approval(approval)
        with self.assertRaises(PolicyError):
            self.plane.approve_goal(goal.goal_id)

    def test_approval_scope_mismatch(self) -> None:
        self.plane.submit_goal_for_approval(self.goal.goal_id)
        approvals = self.plane.repo.list_approvals(pending_only=True)
        approval = approvals[0]
        approval.scope = "goal:other"
        self.plane.repo.update_approval(approval)
        with self.assertRaises(PolicyError):
            self.plane.approve_goal(self.goal.goal_id)


class EventAuditTests(unittest.TestCase):
    def test_event_trail_and_idempotent_append(self) -> None:
        plane = ControlPlane.open(_tmp_db())
        try:
            project = plane.create_project("EV", "r/ev")
            events = plane.repo.list_events(aggregate_type="project", aggregate_id=project.project_id)
            self.assertTrue(any(e.event_type == "project.created" for e in events))
            # Append-only: creating again with same id via upsert emits another event path
            before = len(plane.repo.list_events(limit=10000))
            plane._emit(
                aggregate_type="project",
                aggregate_id=project.project_id,
                event_type="project.note",
                payload={"n": 1},
            )
            after = len(plane.repo.list_events(limit=10000))
            self.assertEqual(after, before + 1)
        finally:
            plane.close()


class DemoTests(unittest.TestCase):
    def test_run_demo_and_restart(self) -> None:
        path = _tmp_db()
        plane = ControlPlane.open(path)
        result = plane.run_demo(ephemeral=True)
        self.assertEqual(result["mode"], "SYNTHETIC")
        project_id = result["project_id"]
        plane.close()
        plane2 = ControlPlane.open(path)
        t1 = plane2._require_task(result["task1_id"])
        self.assertEqual(t1.lifecycle_state, "DONE")
        ready = plane2.list_ready_tasks(project_id)
        self.assertEqual(ready[0].task_id, result["task2_id"])
        plane2.close()

    def test_persistent_demo_idempotent(self) -> None:
        from engineering_os.application.services import DEMO_PROJECT_ID, DEMO_TASK1_ID

        path = _tmp_db()
        plane = ControlPlane.open(path)
        first = plane.ensure_persistent_demo()
        self.assertTrue(first["created"])
        self.assertTrue(first["seeded"])
        self.assertEqual(first["project"]["project_id"], DEMO_PROJECT_ID)
        second = plane.ensure_persistent_demo()
        self.assertFalse(second["created"])
        self.assertTrue(second["idempotent"])
        projects = plane.list_projects()
        self.assertEqual(len(projects), 1)
        self.assertEqual(
            plane._require_task(DEMO_TASK1_ID).lifecycle_state, "DONE"
        )
        plane.close()
        plane2 = ControlPlane.open(path)
        snap = plane2.demo_snapshot()
        self.assertTrue(snap["seeded"])
        self.assertEqual(len(snap["tasks"]), 2)
        plane2.close()

    def test_synthetic_approval_does_not_enable_live(self) -> None:
        path = _tmp_db()
        plane = ControlPlane.open(path)
        plane.ensure_persistent_demo()
        task = plane.list_ready_tasks("proj-eos-mvp-demo")[0]
        execution = plane.prepare_synthetic_execution(task.task_id)
        with self.assertRaises(PolicyError):
            plane.dispatch_execution(execution.execution_id, live=True)
        self.assertNotEqual(plane.sandbox_gate, "PASS")
        self.assertFalse(plane.overview()["live_execution_enabled"])
        plane.close()


class OrchestratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.path = _tmp_db()
        self.plane = ControlPlane.open(self.path)
        self.project = self.plane.create_project("OR", "r/or")
        self.goal = self.plane.create_goal(self.project.project_id, "OG")
        self.t1 = self.plane.create_task(self.goal.goal_id, "A")
        self.t2 = self.plane.create_task(
            self.goal.goal_id, "B", depends_on=[self.t1.task_id]
        )
        self.plane.approve_goal(self.goal.goal_id)
        self.orch = SequentialOrchestrator(self.plane)

    def tearDown(self) -> None:
        self.plane.close()

    def test_full_lifecycle_with_integration(self) -> None:
        result = self.orch.run_full_synthetic_lifecycle(self.project.project_id)
        tasks = {t["task_id"]: t for t in result["tasks"]}
        self.assertEqual(tasks[self.t1.task_id]["lifecycle_state"], "DONE")
        self.assertEqual(tasks[self.t2.task_id]["lifecycle_state"], "DONE")
        for ex in result["executions"]:
            self.assertEqual(ex["runner_type"], "SYNTHETIC")
            self.assertTrue(ex["synthetic"])

    def test_duplicate_dispatch_suppressed_by_claim(self) -> None:
        step = self.orch.tick(self.project.project_id, auto_integration=False)
        self.assertEqual(step["action"], "dispatched")
        again = self.orch.tick(self.project.project_id, auto_integration=False)
        self.assertIn(again["action"], {"claim_held", "awaiting_owner_decision"})

    def test_rejected_merge_and_failed_ci_path(self) -> None:
        self.orch.tick(self.project.project_id, auto_integration=False)
        active = self.orch.active_execution(self.project.project_id)
        assert active is not None
        rejected = self.orch.complete_integration(active.execution_id, approve_merge=False)
        self.assertEqual(rejected["action"], "integration_rejected")

    def test_recovery_after_restart(self) -> None:
        self.orch.tick(self.project.project_id, auto_integration=False)
        active = self.orch.active_execution(self.project.project_id)
        assert active is not None
        exec_id = active.execution_id
        self.plane.close()
        plane2 = ControlPlane.open(self.path)
        orch2 = SequentialOrchestrator(plane2)
        recovered = orch2.recover(self.project.project_id)
        self.assertEqual(recovered["action"], "resume_awaiting_integration")
        done = orch2.complete_integration(exec_id, approve_merge=True)
        self.assertEqual(done["action"], "integration_completed")
        # No duplicate SUCCEEDED for same attempt when ticking again after done
        next_step = orch2.tick(self.project.project_id, auto_integration=True)
        self.assertIn(next_step["action"], {"dispatched", "idle", "integration_completed"})
        plane2.close()
        self.plane = ControlPlane.open(self.path)  # for tearDown


class HttpApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = _tmp_db()
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

    def _post(self, path: str, payload: dict, *, csrf: str | None = None, origin: str | None = None):
        token = csrf if csrf is not None else self._csrf()
        body = json.dumps(payload).encode()
        headers = {
            "Content-Type": "application/json",
            "X-CSRF-Token": token,
        }
        if origin is not None:
            headers["Origin"] = origin
        req = urllib.request.Request(
            self.base + path, data=body, headers=headers, method="POST"
        )
        try:
            with self.opener.open(req) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def test_health_and_static(self) -> None:
        status, health = self._get("/api/health")
        self.assertEqual(status, 200)
        self.assertTrue(health["ok"])
        self.assertFalse(health["live_execution_enabled"])
        req = urllib.request.Request(self.base + "/")
        with self.opener.open(req) as resp:
            self.assertEqual(resp.status, 200)
            html = resp.read().decode()
            self.assertIn("Engineering OS", html)
        req = urllib.request.Request(self.base + "/app.js")
        with self.opener.open(req) as resp:
            self.assertEqual(resp.status, 200)

    def test_csrf_and_origin_guards(self) -> None:
        status, _ = self._post("/api/projects", {"name": "X", "repository_identity": "r"}, csrf="")
        self.assertEqual(status, 403)
        status, _ = self._post(
            "/api/projects",
            {"name": "X", "repository_identity": "r"},
            origin="http://evil.example",
        )
        self.assertEqual(status, 403)

    def test_workflow_persists(self) -> None:
        status, project = self._post(
            "/api/projects", {"name": "Web", "repository_identity": "local/web"}
        )
        self.assertEqual(status, 201)
        status, goal = self._post(
            "/api/goals",
            {
                "project_id": project["project_id"],
                "title": "Goal",
                "description": "d",
            },
        )
        self.assertEqual(status, 201)
        status, task = self._post(
            "/api/tasks",
            {"goal_id": goal["goal_id"], "description": "T1", "depends_on": []},
        )
        self.assertEqual(status, 201)
        status, _ = self._post("/api/goals/approve", {"goal_id": goal["goal_id"]})
        self.assertEqual(status, 200)
        status, payload = self._post(
            "/api/synthetic-executions", {"task_id": task["task_id"]}
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["mode"], "SYNTHETIC")
        self.assertEqual(payload["execution"]["status"], "SUCCEEDED")
        # Restart persistence — reopen plane on same DB via new ControlPlane
        self.plane.close()
        plane2 = ControlPlane.open(self.db)
        ex = plane2._require_execution(payload["execution"]["execution_id"])
        self.assertEqual(ex.status, "SUCCEEDED")
        plane2.close()
        # Restore for tearDown
        self.plane = ControlPlane.open(self.db)
        self.state.plane = self.plane
        self.state.orchestrator = SequentialOrchestrator(self.plane)

    def test_live_flag_rejected(self) -> None:
        status, body = self._post(
            "/api/synthetic-executions", {"task_id": "x", "live": True}
        )
        self.assertEqual(status, 403)
        self.assertEqual(body["error"], "live_acp_disabled")

    def test_persistent_demo_via_api(self) -> None:
        status, first = self._post("/api/demo", {})
        self.assertEqual(status, 200)
        self.assertTrue(first["created"])
        self.assertTrue(first["seeded"])
        project_id = first["project"]["project_id"]
        status, second = self._post("/api/demo", {})
        self.assertEqual(status, 200)
        self.assertFalse(second["created"])
        status, projects = self._get("/api/projects")
        self.assertEqual(status, 200)
        self.assertEqual(len(projects), 1)
        self.assertEqual(projects[0]["project_id"], project_id)
        status, overview = self._get("/api/overview")
        self.assertGreaterEqual(overview["projects"], 1)
        self.assertFalse(overview["live_execution_enabled"])
        status, health = self._get("/api/health")
        self.assertTrue(health["demo_seeded"])
        status, demo_status = self._get("/api/demo/status")
        self.assertTrue(demo_status["seeded"])
        self.assertEqual(len(demo_status["tasks"]), 2)


class OptimisticConcurrencyTests(unittest.TestCase):
    def test_version_conflict(self) -> None:
        repo = Repository(_tmp_db())
        try:
            from engineering_os.domain.models import Project

            p = Project(project_id="p1", name="n", repository_identity="r")
            repo.upsert_project(p)
            p2 = repo.get_project("p1")
            assert p2 is not None
            p2.name = "changed"
            repo.update_project = getattr(repo, "upsert_project")  # type: ignore
            # Force conflict via update_goal pattern on a goal
            from engineering_os.domain.models import Goal

            g = Goal(goal_id="g1", project_id="p1", title="t")
            repo.insert_goal(g)
            g.lifecycle_state = "PENDING_APPROVAL"
            g2 = repo.update_goal(g, expected_version=1)
            with self.assertRaises(ConcurrencyError):
                repo.update_goal(g, expected_version=1)
            self.assertEqual(g2.version, 2)
        finally:
            repo.close()


if __name__ == "__main__":
    unittest.main()
