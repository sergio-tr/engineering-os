"""EOS-05 Paperclip + OpenClaw integration tests (fixtures only, no network)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from engineering_os.application.services import ControlPlane, PolicyError
from engineering_os.infrastructure.eos05_fixtures import (
    COMPANY_ID,
    PROJECT_EXT,
    build_paperclip_fixture_transport,
    openclaw_absent_which,
    openclaw_fixture_runner,
)
from engineering_os.infrastructure.github_client import FixtureTransport, HttpResponse
from engineering_os.infrastructure.openclaw_client import OpenClawCliClient
from engineering_os.infrastructure.paperclip_client import (
    PaperclipClient,
    PaperclipClientError,
)
from engineering_os.infrastructure.sqlite_repo import Repository


def _tmp() -> Path:
    return Path(tempfile.mkdtemp(prefix="eos05-")) / "t.sqlite3"


def _plane(**kwargs) -> ControlPlane:
    defaults = dict(
        paperclip_transport=build_paperclip_fixture_transport(),
        openclaw_client=OpenClawCliClient(
            runner=openclaw_fixture_runner, which=lambda _: "/bin/openclaw"
        ),
    )
    defaults.update(kwargs)
    return ControlPlane(Repository(_tmp()), **defaults)


class PaperclipClientTests(unittest.TestCase):
    def test_auth_and_schema_errors(self) -> None:
        transport = FixtureTransport()
        transport.routes["GET /api/companies"] = HttpResponse(
            401, {}, b'{"message":"no"}', "x"
        )
        client = PaperclipClient(transport=transport)
        with self.assertRaises(PaperclipClientError) as ctx:
            client.list_companies()
        self.assertEqual(ctx.exception.code, "auth_error")

        transport2 = FixtureTransport()
        transport2.add("GET /api/companies", "not-a-list")
        client2 = PaperclipClient(transport=transport2)
        with self.assertRaises(PaperclipClientError):
            client2.list_companies()

    def test_non_local_http_rejected(self) -> None:
        with self.assertRaises(PaperclipClientError):
            PaperclipClient(base_url="http://evil.example:3100")

    def test_write_rejected_without_apply_path(self) -> None:
        client = PaperclipClient(transport=build_paperclip_fixture_transport())
        with self.assertRaises(PaperclipClientError):
            client._request("POST", "/api/companies/x/issues", body={}, allow_write=False)

    def test_create_issue_dry_run_and_apply(self) -> None:
        client = PaperclipClient(transport=build_paperclip_fixture_transport())
        dry = client.create_issue(COMPANY_ID, {"title": "T"}, apply=False)
        self.assertTrue(dry["dry_run"])
        applied = client.create_issue(COMPANY_ID, {"title": "T"}, apply=True)
        self.assertFalse(applied["dry_run"])
        self.assertIn("issue", applied)

    def test_token_redaction(self) -> None:
        client = PaperclipClient(
            transport=build_paperclip_fixture_transport(), token="secret-pc-token"
        )
        blob = json.dumps(client.redact())
        self.assertNotIn("secret-pc-token", blob)


class OpenClawClientTests(unittest.TestCase):
    def test_absent_binary(self) -> None:
        client = OpenClawCliClient(which=openclaw_absent_which)
        status = client.status_json()
        self.assertEqual(status["evidence_class"], "UNAVAILABLE")

    def test_invalid_json(self) -> None:
        def runner(argv, timeout, env):
            from engineering_os.infrastructure.openclaw_client import CommandResult

            return CommandResult(0, "not-json", "", list(argv))

        client = OpenClawCliClient(runner=runner, which=lambda _: "/bin/openclaw")
        status = client.status_json()
        self.assertEqual(status["error"]["code"], "invalid_status_json")

    def test_timeout(self) -> None:
        import subprocess

        def runner(argv, timeout, env):
            raise subprocess.TimeoutExpired(cmd=list(argv), timeout=timeout)

        client = OpenClawCliClient(runner=runner, which=lambda _: "/bin/openclaw")
        with self.assertRaises(Exception):
            client.status_json()

    def test_fixed_argv_no_injection(self) -> None:
        seen = []

        def runner(argv, timeout, env):
            from engineering_os.infrastructure.openclaw_client import CommandResult

            seen.append(list(argv))
            return CommandResult(0, '{"gateway":{}}', "", list(argv))

        client = OpenClawCliClient(runner=runner, which=lambda _: "/bin/openclaw")
        client.status_json()
        self.assertEqual(seen[0], ["/bin/openclaw", "status", "--json"])
        # Ensure no shell metacharacters path
        self.assertTrue(all(isinstance(a, str) for a in seen[0]))


class IntegrationServiceTests(unittest.TestCase):
    def test_sync_mappings_plan_and_restart(self) -> None:
        path = _tmp()
        plane = ControlPlane(
            Repository(path),
            paperclip_transport=build_paperclip_fixture_transport(),
            openclaw_client=OpenClawCliClient(
                runner=openclaw_fixture_runner, which=lambda _: "/bin/openclaw"
            ),
        )
        project = plane.create_project("P", "local/p")
        plane.paperclip_link_project(project.project_id, PROJECT_EXT, company_id=COMPANY_ID)
        sync = plane.paperclip_sync(COMPANY_ID, project_id=project.project_id)
        self.assertEqual(sync["snapshot"]["evidence_class"], "LIVE_READ_ONLY")
        self.assertGreaterEqual(sync["snapshot"]["counts"]["issues"], 2)
        oc = plane.openclaw_refresh()
        self.assertTrue(oc["status"]["installation_available"])
        plan = plane.orchestration_plan(project.project_id)
        self.assertFalse(plan["live_acp_enabled"])
        self.assertTrue(plan["synthetic_execution_permitted"])
        self.assertEqual(plan["sandbox_gate"], "NOT_TESTED")
        plane.close()
        plane2 = ControlPlane(
            Repository(path),
            paperclip_transport=build_paperclip_fixture_transport(),
            openclaw_client=OpenClawCliClient(
                runner=openclaw_fixture_runner, which=lambda _: "/bin/openclaw"
            ),
        )
        maps = plane2.repo.list_external_mappings(system_name="paperclip")
        self.assertGreaterEqual(len(maps), 1)
        cached = plane2.repo.latest_integration_observation(
            system_name="paperclip", project_id=project.project_id, include_stale=True
        )
        self.assertIsNotNone(cached)
        plane2.close()

    def test_duplicate_sync_and_create_suppression(self) -> None:
        plane = _plane()
        try:
            project = plane.create_project("P", "local/p")
            plane.paperclip_sync(COMPANY_ID, project_id=project.project_id)
            second = plane.paperclip_sync(COMPANY_ID, project_id=project.project_id)
            first_id = plane.repo.latest_integration_observation(
                system_name="paperclip", project_id=project.project_id
            )
            self.assertIsNotNone(first_id)
            created = plane.paperclip_create_issue(
                COMPANY_ID, {"title": "X"}, apply=True, idempotency_key="idem-1"
            )
            again = plane.paperclip_create_issue(
                COMPANY_ID, {"title": "X"}, apply=True, idempotency_key="idem-1"
            )
            self.assertTrue(again.get("suppressed_duplicate"))
            self.assertFalse(created.get("agent_work_triggered"))
            dry = plane.paperclip_create_issue(COMPANY_ID, {"title": "Y"}, apply=False)
            self.assertTrue(dry["dry_run"])
        finally:
            plane.close()

    def test_cross_company_conflict(self) -> None:
        plane = _plane()
        try:
            project = plane.create_project("P", "local/p")
            plane.paperclip_link_project(
                project.project_id, PROJECT_EXT, company_id=COMPANY_ID
            )
            with self.assertRaises(PolicyError):
                plane.paperclip_link_project(
                    project.project_id,
                    "99999999-9999-9999-9999-999999999999",
                    company_id=COMPANY_ID,
                )
        finally:
            plane.close()

    def test_fixture_demo(self) -> None:
        plane = _plane()
        try:
            result = plane.run_eos05_fixture_demo()
            self.assertEqual(result["mode"], "FIXTURE_OFFLINE")
            self.assertFalse(result["live_acp_enabled"])
            self.assertIn("plan", result)
        finally:
            plane.close()

    def test_synthetic_still_works(self) -> None:
        from engineering_os.application.orchestrator import SequentialOrchestrator

        plane = ControlPlane.open(_tmp())
        try:
            project = plane.create_project("S", "local/s")
            goal = plane.create_goal(project.project_id, "g")
            t1 = plane.create_task(goal.goal_id, "a")
            plane.create_task(goal.goal_id, "b", depends_on=[t1.task_id])
            plane.approve_goal(goal.goal_id)
            orch = SequentialOrchestrator(plane)
            out = orch.run_full_synthetic_lifecycle(project.project_id)
            self.assertTrue(any(t["lifecycle_state"] == "DONE" for t in out["tasks"]))
        finally:
            plane.close()


if __name__ == "__main__":
    unittest.main()
