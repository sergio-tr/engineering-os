"""Architecture regression tests for EOS-13 dependency direction."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "src" / "engineering_os"


FORBIDDEN_IN_DOMAIN = {
    "engineering_os.infrastructure",
    "engineering_os.interfaces",
    "sqlite3",
    "http.server",
    "urllib.request",
}

FORBIDDEN_IN_PORTS = {
    "engineering_os.infrastructure",
    "engineering_os.interfaces",
    "sqlite3",
}


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name.split(".")[0] if alias.name.startswith("sqlite") else alias.name)
                found.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
    return found


class ArchitectureBoundaryTests(unittest.TestCase):
    def test_domain_avoids_infrastructure(self) -> None:
        for path in (ROOT / "domain").rglob("*.py"):
            imports = _imports(path)
            for forbidden in FORBIDDEN_IN_DOMAIN:
                self.assertFalse(
                    any(imp == forbidden or imp.startswith(forbidden + ".") for imp in imports),
                    msg=f"{path} imports {forbidden}",
                )

    def test_ports_avoid_infrastructure(self) -> None:
        ports = ROOT / "ports"
        self.assertTrue(ports.is_dir())
        for path in ports.rglob("*.py"):
            imports = _imports(path)
            for forbidden in FORBIDDEN_IN_PORTS:
                bad = [
                    imp
                    for imp in imports
                    if imp == forbidden or imp.startswith(forbidden + ".")
                ]
                # ports.persistence imports domain.models only — allow that.
                self.assertEqual(bad, [], msg=f"{path} imports {bad}")

    def test_composition_root_exists(self) -> None:
        bootstrap = ROOT / "bootstrap.py"
        self.assertTrue(bootstrap.is_file())
        text = bootstrap.read_text(encoding="utf-8")
        self.assertIn("build_dependencies", text)
        self.assertIn("ControlPlaneDependencies", text)

    def test_controlplane_accepts_dependency_bundle(self) -> None:
        import tempfile

        from engineering_os.application.services import ControlPlane
        from engineering_os.bootstrap import build_dependencies, open_control_plane

        with tempfile.TemporaryDirectory() as tmp:
            plane = open_control_plane(Path(tmp) / "eos.sqlite3")
            try:
                self.assertTrue(hasattr(plane, "_deps"))
                self.assertTrue(hasattr(plane, "_projects"))
                self.assertTrue(hasattr(ControlPlane, "from_dependencies"))
                deps = build_dependencies(plane.repo)
                plane2 = ControlPlane.from_dependencies(deps)
                self.assertIs(plane2.repo, deps.repo)
                plane2.close()
            finally:
                plane.close()

    def test_persistence_package_exports_repository(self) -> None:
        from engineering_os.infrastructure.persistence.sqlite import Repository
        from engineering_os.infrastructure.sqlite_repo import Repository as Shim

        self.assertIs(Repository, Shim)

    def test_no_new_god_module_without_shim(self) -> None:
        # sqlite_repo must remain a thin shim after the split.
        text = (ROOT / "infrastructure" / "sqlite_repo.py").read_text(encoding="utf-8")
        self.assertLess(len(text.splitlines()), 40)


if __name__ == "__main__":
    unittest.main()
