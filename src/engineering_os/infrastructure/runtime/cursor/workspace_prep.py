"""Trusted disposable workspace preparation for sandboxed executions."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import os
import shutil
import tempfile

from engineering_os.domain.models import new_id, utc_now
from engineering_os.infrastructure.evidence import ERROR, SYNTHETIC


FORBIDDEN_WORKSPACE_MARKERS = (
    "/home/",
    "/root/",
    ".ssh",
    ".cursor",
    "docker.sock",
    "podman.sock",
    ".git-credentials",
    "EOS_GITHUB_TOKEN",
)


@dataclass
class WorkspaceSpec:
    workspace_id: str
    execution_id: str
    project_id: str
    host_path: str
    container_path: str = "/workspace"
    size_limit_bytes: int = 64 * 1024 * 1024
    read_only_project_snapshot: bool = True
    allow_git_push: bool = False
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "workspace_id": self.workspace_id,
            "execution_id": self.execution_id,
            "project_id": self.project_id,
            "host_path": self.host_path,
            "container_path": self.container_path,
            "size_limit_bytes": self.size_limit_bytes,
            "read_only_project_snapshot": self.read_only_project_snapshot,
            "allow_git_push": self.allow_git_push,
            "created_at": self.created_at,
        }


class WorkspacePrepError(RuntimeError):
    def __init__(self, message: str, *, code: str = "workspace_error") -> None:
        super().__init__(message)
        self.code = code


def validate_workspace_path(path: str) -> List[str]:
    errors: List[str] = []
    resolved = str(Path(path).resolve()) if path else ""
    if not resolved.startswith(str(Path(tempfile.gettempdir()).resolve())):
        # Only disposable dirs under system temp (or explicit eos workspaces root).
        eos_root = Path(tempfile.gettempdir()).resolve() / "eos-workspaces"
        if not resolved.startswith(str(eos_root)):
            errors.append("workspace_outside_allowlist")
    for marker in FORBIDDEN_WORKSPACE_MARKERS:
        if marker in resolved:
            errors.append(f"forbidden_marker:{marker}")
    if ".." in path:
        errors.append("path_escape")
    return sorted(set(errors))


class WorkspacePreparer:
    def __init__(self, *, root: Optional[Path] = None) -> None:
        base = root or (Path(tempfile.gettempdir()) / "eos-workspaces")
        self.root = Path(base)
        self.root.mkdir(parents=True, exist_ok=True)

    def readiness(self) -> Dict[str, Any]:
        return {
            "status": "READY",
            "ok": True,
            "root": str(self.root),
            "size_limit_bytes": 64 * 1024 * 1024,
            "cross_project_mounts": False,
            "host_home_access": False,
            "github_credential_mounts": False,
            "podman_socket_access": False,
            "git_push_from_sandbox": False,
            "evidence_class": SYNTHETIC,
        }

    def prepare(
        self,
        *,
        execution_id: str,
        project_id: str,
        size_limit_bytes: int = 64 * 1024 * 1024,
    ) -> WorkspaceSpec:
        workspace_id = f"ws-{execution_id[-12:]}"
        host_path = self.root / workspace_id
        if host_path.exists():
            # Idempotent reuse for same execution workspace id.
            spec = WorkspaceSpec(
                workspace_id=workspace_id,
                execution_id=execution_id,
                project_id=project_id,
                host_path=str(host_path),
                size_limit_bytes=size_limit_bytes,
            )
        else:
            host_path.mkdir(parents=True, exist_ok=False)
            (host_path / ".eos-workspace").write_text(
                f"execution_id={execution_id}\nproject_id={project_id}\n",
                encoding="utf-8",
            )
            spec = WorkspaceSpec(
                workspace_id=workspace_id,
                execution_id=execution_id,
                project_id=project_id,
                host_path=str(host_path),
                size_limit_bytes=size_limit_bytes,
            )
        errors = validate_workspace_path(spec.host_path)
        if errors:
            raise WorkspacePrepError(",".join(errors), code="invalid_workspace")
        return spec

    def cleanup(self, spec: WorkspaceSpec) -> Dict[str, Any]:
        path = Path(spec.host_path)
        if path.exists() and str(path.resolve()).startswith(str(self.root.resolve())):
            shutil.rmtree(path, ignore_errors=False)
            return {"cleaned": True, "workspace_id": spec.workspace_id}
        return {"cleaned": False, "reason": "path_not_under_root", "evidence_class": ERROR}
