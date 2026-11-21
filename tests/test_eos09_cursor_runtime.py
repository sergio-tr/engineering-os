"""EOS-09 Cursor runtime integration tests (no live Cursor/containers/network)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from engineering_os.application.orchestrator import SequentialOrchestrator
from engineering_os.application.services import ControlPlane
from engineering_os.infrastructure.acpx_cursor_config import (
    propose_acpx_cursor_agent_config,
    validate_acpx_cursor_command,
)
from engineering_os.infrastructure.credential_provider import (
    FixtureCursorCredentialProvider,
    UnavailableCursorCredentialProvider,
    redact_secrets,
)
from engineering_os.infrastructure.cursor_runtime import CursorRuntimePlanner
from engineering_os.infrastructure.network_policy import (
    DenyAllNetworkPolicy,
    FixtureAllowlistNetworkPolicy,
    UnenforcedNetworkPolicy,
)
from engineering_os.infrastructure.sqlite_repo import Repository
from engineering_os.infrastructure.workspace_prep import (
    WorkspacePreparer,
    validate_workspace_path,
)


def _tmp() -> Path:
    return Path(tempfile.mkdtemp(prefix="eos09-")) / "t.sqlite3"


class CredentialNetworkTests(unittest.TestCase):
    def test_redaction_and_unavailable(self) -> None:
        text = redact_secrets("Authorization: Bearer sk-abcdefghijk CURSOR_API_KEY=x")
        self.assertIn("[REDACTED]", text)
        prov = UnavailableCursorCredentialProvider()
        self.assertFalse(prov.readiness()["available"])
        with self.assertRaises(Exception):
            prov.lease(execution_id="e1")

    def test_network_allow_deny(self) -> None:
        deny = DenyAllNetworkPolicy()
        self.assertFalse(deny.evaluate("api.cursor.com").allowed)
        unenf = UnenforcedNetworkPolicy()
        self.assertEqual(unenf.readiness()["status"], "BLOCKED")
        allow = FixtureAllowlistNetworkPolicy()
        self.assertTrue(allow.evaluate("api.cursor.com").allowed)
        self.assertFalse(allow.evaluate("evil.example").allowed)


class RuntimeConfigTests(unittest.TestCase):
    def test_image_plan_and_command(self) -> None:
        planner = CursorRuntimePlanner(
            image_digest="sha256:" + ("a" * 64),
            image_present=True,
            cursor_version="1.2.3",
            available_binaries=["agent"],
        )
        plan = planner.image_plan()
        self.assertFalse(plan["build_authorized_in_eos09"])
        self.assertFalse(plan["alpine_fixture_suitable"])
        cmd = planner.command()
        self.assertEqual(cmd.argv[0], "agent")
        ready = planner.readiness()
        self.assertEqual(ready.overall_status, "READY_FOR_AUTHORIZATION")

    def test_digest_mismatch_and_missing_image(self) -> None:
        planner = CursorRuntimePlanner(
            image_digest="sha256:dead",
            image_present=False,
        )
        # Force expected digest via mutating copy
        planner.profile = dict(planner.profile)
        planner.profile["expected_image_digest"] = "sha256:" + ("b" * 64)
        ready = planner.readiness().to_dict()
        self.assertIn("image_present", ready["missing"])

    def test_acpx_validator_rejects_host_cursor(self) -> None:
        bad = validate_acpx_cursor_command(["cursor-agent", "acp"])
        self.assertFalse(bad["ok"])
        proposal = propose_acpx_cursor_agent_config()
        good = validate_acpx_cursor_command(proposal["proposed_command"])
        self.assertTrue(good["ok"])


class WorkspaceTests(unittest.TestCase):
    def test_prepare_cleanup_and_escape(self) -> None:
        prep = WorkspacePreparer()
        spec = prep.prepare(execution_id="exec-abcdefghijkl", project_id="proj-1")
        self.assertTrue(Path(spec.host_path).exists())
        errors = validate_workspace_path("/home/sergio/secret")
        self.assertIn("workspace_outside_allowlist", errors)
        self.assertTrue(any("forbidden_marker" in e for e in errors))
        cleaned = prep.cleanup(spec)
        self.assertTrue(cleaned["cleaned"])


class BridgeServiceTests(unittest.TestCase):
    def test_demo_and_live_blocked(self) -> None:
        path = _tmp()
        plane = ControlPlane.open(path)
        result = plane.run_cursor_fixture_demo()
        self.assertEqual(result["mode"], "CURSOR_FIXTURE_OFFLINE")
        self.assertFalse(result["live_cursor_acp"])
        self.assertFalse(result["unauthorized_egress_denied"]["allowed"])
        self.assertEqual(result["demo"]["preparation"]["status"], "COMPLETED")
        self.assertTrue(
            result["integration_check"]["direct_host_rejected"]["errors"]
        )
        plane.close()
        plane2 = ControlPlane.open(path)
        preps = plane2.repo.list_cursor_preparations(project_id=result["project_id"])
        self.assertEqual(len(preps), 1)
        self.assertEqual(preps[0]["status"], "COMPLETED")
        plane2.close()

    def test_orchestrator_prepare_cursor_claim(self) -> None:
        plane = ControlPlane(
            Repository(_tmp()),
            cursor_bridge=None,
        )
        # Replace cursor bridge with fixture-ready one via demo wiring pattern
        from engineering_os.infrastructure.cursor_bridge import CursorBridge

        plane.cursor = CursorBridge(
            plane.repo,
            credentials=FixtureCursorCredentialProvider(),
            network=FixtureAllowlistNetworkPolicy(),
            runtime=CursorRuntimePlanner(
                image_digest="sha256:" + ("c" * 64),
                image_present=True,
                cursor_version="fix",
                available_binaries=["agent"],
            ),
        )
        try:
            project = plane.create_project("P", "r/p")
            goal = plane.create_goal(project.project_id, "g")
            plane.create_task(goal.goal_id, "t")
            plane.approve_goal(goal.goal_id)
            orch = SequentialOrchestrator(plane)
            first = orch.prepare_cursor(project.project_id)
            self.assertEqual(first["action"], "cursor_prepared")
            second = orch.prepare_cursor(project.project_id)
            self.assertEqual(second["action"], "claim_held")
            reqs = plane.runtime_requirements()
            self.assertTrue(reqs["live_blocked"])
        finally:
            plane.close()


if __name__ == "__main__":
    unittest.main()
