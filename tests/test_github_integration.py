"""EOS-04 GitHub read-only integration tests (fixture-driven, no network)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from engineering_os.application.services import ControlPlane, PolicyError
from engineering_os.infrastructure.adapters import UnsupportedIntegrationOperation
from engineering_os.infrastructure.evidence import (
    CACHED,
    EXTERNALLY_VERIFIED,
    LIVE_READ_ONLY,
)
from engineering_os.infrastructure.github_adapter import GitHubReadOnlyRepositoryAdapter
from engineering_os.infrastructure.github_client import (
    FixtureTransport,
    GitHubClientError,
    GitHubReadOnlyClient,
    HttpResponse,
    parse_repository,
)
from engineering_os.infrastructure.github_fixtures import (
    build_demo_fixture_transport,
    build_open_pr_transport,
)
from engineering_os.infrastructure.sqlite_repo import Repository


def _tmp() -> Path:
    return Path(tempfile.mkdtemp(prefix="eos-gh-")) / "t.sqlite3"


class ClientUnitTests(unittest.TestCase):
    def test_invalid_repository_identifiers(self) -> None:
        with self.assertRaises(GitHubClientError):
            parse_repository("../evil/repo")
        with self.assertRaises(GitHubClientError):
            parse_repository("bad repo/name")
        with self.assertRaises(GitHubClientError):
            parse_repository("onlyowner")

    def test_write_methods_rejected(self) -> None:
        client = GitHubReadOnlyClient(transport=FixtureTransport())
        with self.assertRaises(GitHubClientError):
            client._request("POST", "/repos/a/b")

    def test_host_and_redirect_restrictions(self) -> None:
        with self.assertRaises(GitHubClientError):
            GitHubReadOnlyClient(api_base="http://api.github.com")
        client = GitHubReadOnlyClient(transport=FixtureTransport())
        with self.assertRaises(GitHubClientError):
            client._validate_url("https://evil.example/repos/a/b")

    def test_auth_header_when_token_present(self) -> None:
        transport = FixtureTransport()
        transport.add(
            "GET /repos/acme/demo",
            {"full_name": "acme/demo", "default_branch": "main", "private": True},
        )
        client = GitHubReadOnlyClient(token="secret-token", transport=transport)
        client.get_repository("acme", "demo")
        # Token must not appear in redact()
        redacted = client.redact()
        self.assertTrue(redacted["token_configured"])
        blob = json.dumps(redacted)
        self.assertNotIn("secret-token", blob)

    def test_auth_errors_and_rate_limit(self) -> None:
        transport = FixtureTransport()
        transport.routes["GET /repos/acme/demo"] = HttpResponse(
            status=401,
            headers={},
            body=b'{"message":"bad creds"}',
            url="x",
        )
        client = GitHubReadOnlyClient(transport=transport)
        with self.assertRaises(GitHubClientError) as ctx:
            client.get_repository("acme", "demo")
        self.assertEqual(ctx.exception.code, "auth_error")

        transport2 = FixtureTransport()
        transport2.routes["GET /repos/acme/demo"] = HttpResponse(
            status=403,
            headers={"x-ratelimit-remaining": "0"},
            body=b'{"message":"API rate limit exceeded"}',
            url="x",
        )
        client2 = GitHubReadOnlyClient(transport=transport2, max_retries=0)
        with self.assertRaises(GitHubClientError) as ctx2:
            client2.get_repository("acme", "demo")
        self.assertEqual(ctx2.exception.code, "rate_limited")

    def test_timeout_mapped(self) -> None:
        class Boom(FixtureTransport):
            def request(self, method, url, headers, *, timeout):
                raise GitHubClientError("network_error:timed out", code="network_timeout")

        client = GitHubReadOnlyClient(transport=Boom(), max_retries=0)
        with self.assertRaises(GitHubClientError) as ctx:
            client.get_repository("acme", "demo")
        self.assertEqual(ctx.exception.code, "network_timeout")

    def test_pagination(self) -> None:
        transport = FixtureTransport()
        page1 = [{"number": 1, "state": "open", "merged": False, "title": "a",
                  "head": {"sha": "h1", "ref": "a"}, "base": {"sha": "b1", "ref": "main"}}]
        page2 = [{"number": 2, "state": "open", "merged": False, "title": "b",
                  "head": {"sha": "h2", "ref": "b"}, "base": {"sha": "b2", "ref": "main"}}]
        transport.routes["GET /repos/acme/demo/pulls?state=open&sort=updated&direction=desc&per_page=30&page=1"] = HttpResponse(
            status=200,
            headers={
                "content-type": "application/json",
                "link": '<https://api.github.com/repos/acme/demo/pulls?page=2>; rel="next"',
            },
            body=json.dumps(page1).encode(),
            url="p1",
        )
        # Force full page to continue — use 30 items would be heavy; client breaks on len < per_page.
        # So path-only second page via exact query:
        transport.routes["GET /repos/acme/demo/pulls?state=open&sort=updated&direction=desc&per_page=30&page=2"] = HttpResponse(
            status=200,
            headers={"content-type": "application/json"},
            body=json.dumps(page2).encode(),
            url="p2",
        )
        # Override per_page behavior by making page1 length == 30
        page1_full = page1 * 30
        transport.routes["GET /repos/acme/demo/pulls?state=open&sort=updated&direction=desc&per_page=30&page=1"] = HttpResponse(
            status=200,
            headers={
                "content-type": "application/json",
                "link": '<https://api.github.com/repos/acme/demo/pulls?page=2>; rel="next"',
            },
            body=json.dumps(page1_full).encode(),
            url="p1",
        )
        client = GitHubReadOnlyClient(transport=transport)
        items = client.list_pull_requests("acme", "demo", state="open", max_pages=2)
        self.assertGreaterEqual(len(items), 31)

    def test_schema_change_rejected(self) -> None:
        transport = FixtureTransport()
        transport.add("GET /repos/acme/demo", ["not", "an", "object"])
        client = GitHubReadOnlyClient(transport=transport)
        with self.assertRaises(GitHubClientError) as ctx:
            client.get_repository("acme", "demo")
        self.assertEqual(ctx.exception.code, "schema_error")


class AdapterTests(unittest.TestCase):
    def test_fail_closed_synthetic_commands(self) -> None:
        adapter = GitHubReadOnlyRepositoryAdapter(
            GitHubReadOnlyClient(transport=build_open_pr_transport()),
            owner="acme",
            repo="demo",
        )
        with self.assertRaises(UnsupportedIntegrationOperation):
            adapter.simulate_pr("p", "e")
        with self.assertRaises(UnsupportedIntegrationOperation):
            adapter.record_owner_merge_decision("e", approved=True)

    def test_open_merged_and_missing_checks(self) -> None:
        adapter = GitHubReadOnlyRepositoryAdapter(
            GitHubReadOnlyClient(transport=build_open_pr_transport()),
            owner="acme",
            repo="demo",
        )
        obs = adapter.observe_pull_request(7)
        self.assertEqual(obs["pr_state"], "open")
        self.assertEqual(obs["evidence_class"], LIVE_READ_ONLY)
        self.assertIn(obs["ci_status"], {"pending", "unknown"})

        demo = GitHubReadOnlyRepositoryAdapter(
            GitHubReadOnlyClient(transport=build_demo_fixture_transport()),
            owner="sergio-tr",
            repo="engineering-os",
        )
        merged = demo.observe_pull_request(42)
        self.assertEqual(merged["pr_state"], "merged")
        self.assertEqual(merged["merge_commit_sha"], "mergecafe42deadbeef")
        self.assertEqual(merged["ci_status"], "success")
        self.assertEqual(merged["review_status"], "approved")


class ServiceIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.path = _tmp()
        self.plane = ControlPlane(
            Repository(self.path),
            github_transport=build_demo_fixture_transport(),
            github_token_provider=lambda: "fixture-token-should-not-leak",
        )
        self.project = self.plane.create_project("GH", "local/gh")
        self.goal = self.plane.create_goal(self.project.project_id, "g")
        self.task = self.plane.create_task(self.goal.goal_id, "t")
        self.plane.approve_goal(self.goal.goal_id)
        self.execution = self.plane.simulate_task(self.task.task_id)

    def tearDown(self) -> None:
        self.plane.close()

    def test_connect_sync_link_reconcile_and_restart(self) -> None:
        conn = self.plane.configure_github_connection(
            self.project.project_id, "sergio-tr/engineering-os"
        )
        self.assertNotIn("fixture-token-should-not-leak", json.dumps(conn))
        sync = self.plane.sync_github_repository(self.project.project_id)
        self.assertEqual(sync["observation"]["evidence_class"], LIVE_READ_ONLY)
        prs = self.plane.list_github_pull_requests(self.project.project_id)
        self.assertGreaterEqual(len(prs["pull_requests"]), 1)
        link = self.plane.link_execution_to_pr(self.execution.execution_id, 42)
        self.assertEqual(link["pr_number"], 42)
        synced = self.plane.sync_linked_pull_request(self.execution.execution_id)
        self.assertEqual(synced["live"]["pr_state"], "merged")
        reconciled = self.plane.reconcile_github_merge(self.execution.execution_id)
        self.assertEqual(reconciled["evidence_class"], EXTERNALLY_VERIFIED)
        self.assertFalse(reconciled["synthetic_path_used"])
        self.plane.close()
        plane2 = ControlPlane(
            Repository(self.path), github_transport=build_demo_fixture_transport()
        )
        cached = plane2.cached_github_observation(
            self.project.project_id, execution_id=self.execution.execution_id
        )
        self.assertIsNotNone(cached)
        # After restart, latest non-stale may be the verified observation.
        self.assertIn(
            cached["evidence_class"],
            {EXTERNALLY_VERIFIED, LIVE_READ_ONLY, CACHED},
        )
        plane2.close()
        self.plane = ControlPlane(
            Repository(self.path), github_transport=build_demo_fixture_transport()
        )

    def test_mismatched_association_and_repo(self) -> None:
        self.plane.configure_github_connection(
            self.project.project_id, "sergio-tr/engineering-os"
        )
        self.plane.link_execution_to_pr(
            self.execution.execution_id,
            42,
            expected_base_ref="develop",
        )
        synced = self.plane.sync_linked_pull_request(self.execution.execution_id)
        self.assertEqual(synced["live"]["evidence_class"], "ERROR")
        self.assertIn("base_ref", synced["live"]["details"]["association_mismatch"])

    def test_synthetic_cannot_authorize_real_reconcile_without_link(self) -> None:
        with self.assertRaises(PolicyError):
            self.plane.reconcile_github_merge(self.execution.execution_id)

    def test_sqlite_migration_additive(self) -> None:
        # Re-open existing DB; schema init is idempotent.
        plane2 = ControlPlane(
            Repository(self.path), github_transport=build_demo_fixture_transport()
        )
        self.assertIsNone(plane2.repo.get_github_connection("missing"))
        plane2.configure_github_connection(self.project.project_id, "sergio-tr/engineering-os")
        self.assertIsNotNone(plane2.repo.get_github_connection(self.project.project_id))
        plane2.close()

    def test_duplicate_sync_marks_stale(self) -> None:
        self.plane.configure_github_connection(
            self.project.project_id, "sergio-tr/engineering-os"
        )
        first = self.plane.sync_github_repository(self.project.project_id)
        second = self.plane.sync_github_repository(self.project.project_id)
        old = self.plane.repo.get_github_observation(first["observation"]["observation_id"])
        self.assertTrue(old["stale"])
        self.assertFalse(second["observation"]["stale"])

    def test_offline_fixture_demo(self) -> None:
        result = self.plane.run_github_fixture_demo()
        self.assertEqual(result["mode"], "FIXTURE_OFFLINE")
        self.assertEqual(result["sync"]["evidence_class"], LIVE_READ_ONLY)


class SyntheticStillWorksTests(unittest.TestCase):
    def test_existing_synthetic_orchestrator(self) -> None:
        from engineering_os.application.orchestrator import SequentialOrchestrator

        plane = ControlPlane.open(_tmp())
        try:
            project = plane.create_project("S", "local/s")
            goal = plane.create_goal(project.project_id, "g")
            t1 = plane.create_task(goal.goal_id, "a")
            t2 = plane.create_task(goal.goal_id, "b", depends_on=[t1.task_id])
            plane.approve_goal(goal.goal_id)
            orch = SequentialOrchestrator(plane)
            result = orch.run_full_synthetic_lifecycle(project.project_id)
            states = {t["task_id"]: t["lifecycle_state"] for t in result["tasks"]}
            self.assertEqual(states[t1.task_id], "DONE")
            self.assertEqual(states[t2.task_id], "DONE")
            for ex in result["executions"]:
                self.assertTrue(ex["synthetic"])
        finally:
            plane.close()


if __name__ == "__main__":
    unittest.main()
