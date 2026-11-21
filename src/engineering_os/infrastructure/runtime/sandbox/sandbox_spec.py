"""Typed sandbox execution specification for ACP launches."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from engineering_os.domain.models import new_id, utc_now


ALLOWED_NETWORK_MODES = frozenset({"none"})
FORBIDDEN_MOUNT_MARKERS = (
    "/home/",
    "/root/",
    ".ssh",
    "docker.sock",
    "podman.sock",
    "/var/run/",
    "credentials",
    ".cursor",
)


@dataclass
class SandboxExecutionSpec:
    execution_id: str
    project_id: str
    task_id: str
    agent_id: str
    approved_runtime_identity: str
    image_digest: str
    image_ref: str
    workspace_id: str
    allowed_mounts: Tuple[str, ...]
    network_mode: str
    cpu_limit: str
    memory_limit: str
    pids_limit: int
    disk_limit_policy: str
    wall_clock_seconds: int
    acp_command: Tuple[str, ...]
    expected_evidence_outputs: Tuple[str, ...]
    correlation_id: str
    idempotency_key: str
    rootless_required: bool = True
    read_only_rootfs: bool = True
    no_new_privileges: bool = True
    cap_drop_all: bool = True
    privileged: bool = False
    share_host_pid: bool = False
    share_host_ipc: bool = False
    created_at: str = field(default_factory=utc_now)
    spec_id: str = field(default_factory=lambda: new_id("sbspec"))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "spec_id": self.spec_id,
            "execution_id": self.execution_id,
            "project_id": self.project_id,
            "task_id": self.task_id,
            "agent_id": self.agent_id,
            "approved_runtime_identity": self.approved_runtime_identity,
            "image_digest": self.image_digest,
            "image_ref": self.image_ref,
            "workspace_id": self.workspace_id,
            "allowed_mounts": list(self.allowed_mounts),
            "network_mode": self.network_mode,
            "cpu_limit": self.cpu_limit,
            "memory_limit": self.memory_limit,
            "pids_limit": self.pids_limit,
            "disk_limit_policy": self.disk_limit_policy,
            "wall_clock_seconds": self.wall_clock_seconds,
            "acp_command": list(self.acp_command),
            "expected_evidence_outputs": list(self.expected_evidence_outputs),
            "correlation_id": self.correlation_id,
            "idempotency_key": self.idempotency_key,
            "rootless_required": self.rootless_required,
            "read_only_rootfs": self.read_only_rootfs,
            "no_new_privileges": self.no_new_privileges,
            "cap_drop_all": self.cap_drop_all,
            "privileged": self.privileged,
            "share_host_pid": self.share_host_pid,
            "share_host_ipc": self.share_host_ipc,
            "created_at": self.created_at,
        }


class SandboxSpecValidationError(ValueError):
    def __init__(self, message: str, *, code: str = "sandbox_spec_invalid") -> None:
        super().__init__(message)
        self.code = code


def validate_sandbox_spec(spec: SandboxExecutionSpec) -> List[str]:
    """Fail-closed policy validation. Returns empty list when valid."""
    errors: List[str] = []
    if not spec.image_digest or not spec.image_digest.startswith("sha256:"):
        errors.append("missing_or_mutable_image_identity")
    if ":" in spec.image_ref and "@sha256:" not in spec.image_ref:
        # Tag-only refs are rejected; require digest pinning in image_ref or digest field.
        if not spec.image_digest.startswith("sha256:"):
            errors.append("unpinned_image_ref")
    if spec.network_mode not in ALLOWED_NETWORK_MODES:
        errors.append("unapproved_network_access")
    if spec.privileged:
        errors.append("privileged_mode_forbidden")
    if not spec.rootless_required:
        errors.append("rootful_execution_forbidden")
    if spec.share_host_pid or spec.share_host_ipc:
        errors.append("host_namespace_sharing_forbidden")
    if not spec.read_only_rootfs:
        errors.append("writable_rootfs_forbidden")
    if not spec.no_new_privileges or not spec.cap_drop_all:
        errors.append("permission_escalation_risk")
    if spec.pids_limit <= 0 or spec.pids_limit > 512:
        errors.append("resource_limit_violation_pids")
    if not spec.memory_limit or spec.memory_limit.endswith("G") and int(spec.memory_limit[:-1]) > 4:
        errors.append("resource_limit_violation_memory")
    if spec.wall_clock_seconds <= 0 or spec.wall_clock_seconds > 3600:
        errors.append("resource_limit_violation_wall_clock")
    if spec.disk_limit_policy in {"", "none", "tmpfs_size_only"}:
        # tmpfs size alone is not a workspace disk quota — report unsupported.
        errors.append("disk_limit_unsupported")
    if not spec.acp_command or any(
        tok in {"sh", "bash", "-c", "/bin/sh", "/bin/bash"} for tok in spec.acp_command
    ):
        errors.append("arbitrary_shell_command_rejected")
    for mount in spec.allowed_mounts:
        lower = mount.lower()
        if ".." in mount or mount.startswith("/") is False:
            # Only absolute disposable workspace mounts under /tmp/eos-workspaces/
            if not mount.startswith("/tmp/eos-workspaces/"):
                errors.append("invalid_workspace_path")
        for marker in FORBIDDEN_MOUNT_MARKERS:
            if marker in lower:
                errors.append("forbidden_mount")
                break
        if mount.endswith(":rw") or ":rw," in mount:
            # Broad writable mounts rejected unless exact workspace bind.
            if "/tmp/eos-workspaces/" not in mount:
                errors.append("broad_writable_mount")
    if not spec.workspace_id.startswith("ws-"):
        errors.append("invalid_workspace_identity")
    if not spec.approved_runtime_identity:
        errors.append("missing_runtime_authorization_identity")
    return sorted(set(errors))


def build_default_spec(
    *,
    execution_id: str,
    project_id: str,
    task_id: str,
    correlation_id: str,
    idempotency_key: str,
    image_digest: str = "sha256:" + ("a" * 64),
    image_ref: str = "localhost/eos-acp-runtime@sha256:" + ("a" * 64),
    disk_limit_policy: str = "unsupported_pending_enforcement",
    network_mode: str = "none",
    agent_id: str = "cursor",
) -> SandboxExecutionSpec:
    workspace_id = f"ws-{execution_id[-12:]}"
    return SandboxExecutionSpec(
        execution_id=execution_id,
        project_id=project_id,
        task_id=task_id,
        agent_id=agent_id,
        approved_runtime_identity="eos-runtime-auth-v1",
        image_digest=image_digest,
        image_ref=image_ref,
        workspace_id=workspace_id,
        allowed_mounts=(f"/tmp/eos-workspaces/{workspace_id}:rw",),
        network_mode=network_mode,
        cpu_limit="1.0",
        memory_limit="512m",
        pids_limit=128,
        disk_limit_policy=disk_limit_policy,
        wall_clock_seconds=300,
        acp_command=("cursor-agent", "acp"),
        expected_evidence_outputs=("acp-transcript", "sandbox-inspect"),
        correlation_id=correlation_id,
        idempotency_key=idempotency_key,
    )
