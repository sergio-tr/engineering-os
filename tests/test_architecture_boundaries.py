"""Architecture regression tests — anti-shim, anti-wildcard, dependency direction."""

from __future__ import annotations

import ast
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "engineering_os"
INFRA = SRC / "infrastructure"

LEGACY_TOP_LEVEL = {
    "acp_adapter",
    "acp_fixture",
    "acp_protocol",
    "acp_states",
    "acp_transport",
    "acp_session",
    "acpx_bridge",
    "acpx_cursor_config",
    "acpx_readiness",
    "broker_runtime",
    "egress_broker",
    "egress_enforcer",
    "network_policy",
    "network_probe_executor",
    "credential_provider",
    "runtime_authorization",
    "oci_process",
    "oci_acp_transport",
    "podman_executor",
    "podman_capabilities",
    "sandbox_launcher",
    "sandbox_spec",
    "cursor_bridge",
    "cursor_launcher",
    "cursor_image",
    "cursor_runtime",
    "cursor_smoke_workflow",
    "deployment_stages",
    "live_preflight",
    "runtime_preflight",
    "workspace_prep",
    "github_client",
    "github_adapter",
    "github_fixtures",
    "paperclip_client",
    "paperclip_adapter",
    "openclaw_client",
    "openclaw_adapter",
    "gateway_client",
    "gateway_transport",
    "sqlite_repo",
}


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
    return found


def _has_wildcard_import(path: Path) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    return True
    return False


class ArchitectureBoundaryTests(unittest.TestCase):
    def test_legacy_shim_modules_are_gone(self) -> None:
        for name in sorted(LEGACY_TOP_LEVEL):
            path = INFRA / f"{name}.py"
            self.assertFalse(path.exists(), msg=f"legacy shim still present: {path}")

    def test_no_production_imports_of_legacy_paths(self) -> None:
        legacy_prefixes = tuple(
            f"engineering_os.infrastructure.{name}" for name in LEGACY_TOP_LEVEL
        )
        offenders: list[str] = []
        for path in SRC.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            for prefix in legacy_prefixes:
                if prefix in text:
                    offenders.append(f"{path}:{prefix}")
        self.assertEqual(offenders, [])

    def test_no_wildcard_imports_in_production(self) -> None:
        offenders = [
            str(p.relative_to(ROOT))
            for p in SRC.rglob("*.py")
            if _has_wildcard_import(p)
        ]
        self.assertEqual(offenders, [])

    def test_domain_and_ports_avoid_infrastructure(self) -> None:
        for package in ("domain", "ports"):
            for path in (SRC / package).rglob("*.py"):
                imports = _imports(path)
                bad = [
                    i
                    for i in imports
                    if i == "engineering_os.infrastructure"
                    or i.startswith("engineering_os.infrastructure.")
                    or i in {"sqlite3", "http.server"}
                ]
                self.assertEqual(bad, [], msg=f"{path} imports {bad}")

    def test_use_cases_avoid_concrete_infrastructure(self) -> None:
        for path in (SRC / "application" / "use_cases").rglob("*.py"):
            imports = _imports(path)
            bad = [
                i
                for i in imports
                if i.startswith("engineering_os.infrastructure")
            ]
            self.assertEqual(bad, [], msg=f"{path} imports {bad}")

    def test_deps_bundle_avoids_infrastructure_imports(self) -> None:
        imports = _imports(SRC / "application" / "deps.py")
        bad = [i for i in imports if i.startswith("engineering_os.infrastructure")]
        self.assertEqual(bad, [])

    def test_composition_root_and_store_port(self) -> None:
        from engineering_os.bootstrap import open_control_plane
        from engineering_os.ports.persistence import ControlPlaneStorePort

        with tempfile.TemporaryDirectory() as tmp:
            plane = open_control_plane(Path(tmp) / "eos.sqlite3")
            try:
                self.assertIsInstance(plane.repo, ControlPlaneStorePort)
                self.assertTrue(hasattr(plane, "_projects"))
                self.assertTrue(hasattr(plane, "_goals"))
            finally:
                plane.close()

    def test_cli_and_http_entrypoints_importable(self) -> None:
        from engineering_os.interfaces.cli import build_parser, main
        from engineering_os.interfaces.http.routes import dispatch_get

        self.assertTrue(callable(main))
        self.assertTrue(callable(build_parser))
        self.assertTrue(callable(dispatch_get))
        parser = build_parser()
        self.assertIsNotNone(parser.parse_args(["network", "broker", "status"]))


if __name__ == "__main__":
    unittest.main()
