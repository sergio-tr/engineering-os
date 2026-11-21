"""Sandbox-enforced Cursor ACP launcher — policy validation and argv construction.

Does not execute containers in EOS-07. Real launch remains blocked without trusted
authorization and verified enforcement capabilities.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from engineering_os.domain.models import new_id, utc_now
from engineering_os.infrastructure.evidence import ERROR, SYNTHETIC, UNAVAILABLE
from engineering_os.infrastructure.security.authorization.runtime_authorization import (
    AuthorizationError,
    RuntimeAuthorization,
    RuntimeAuthorizationVerifier,
)
from engineering_os.infrastructure.runtime.sandbox.sandbox_spec import (
    SandboxExecutionSpec,
    SandboxSpecValidationError,
    validate_sandbox_spec,
)


class SandboxLauncherError(RuntimeError):
    def __init__(self, message: str, *, code: str = "sandbox_launcher_error") -> None:
        super().__init__(message)
        self.code = code


@dataclass
class LaunchPlan:
    argv: List[str]
    env: Dict[str, str]
    spec: SandboxExecutionSpec
    validation_errors: List[str]
    mode: str
    blocked_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "argv": list(self.argv),
            "env_keys": sorted(self.env.keys()),
            "spec_id": self.spec.spec_id,
            "validation_errors": list(self.validation_errors),
            "mode": self.mode,
            "blocked_reason": self.blocked_reason,
        }


@dataclass
class LaunchResult:
    ok: bool
    status: str
    evidence_class: str
    evidence_refs: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    failure_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "status": self.status,
            "evidence_class": self.evidence_class,
            "evidence_refs": list(self.evidence_refs),
            "details": dict(self.details),
            "failure_reason": self.failure_reason,
        }


class SandboxLauncher(ABC):
    name: str

    @abstractmethod
    def readiness(self) -> Dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def plan(self, spec: SandboxExecutionSpec) -> LaunchPlan:
        raise NotImplementedError

    @abstractmethod
    def launch(
        self,
        spec: SandboxExecutionSpec,
        *,
        authorization: Optional[RuntimeAuthorization] = None,
        mode: str = "REAL",
    ) -> LaunchResult:
        raise NotImplementedError


def build_podman_argv(spec: SandboxExecutionSpec) -> List[str]:
    """Fixed-policy rootless Podman argv. Never interpolates untrusted shell."""
    argv = [
        "podman",
        "run",
        "--rm",
        "--rootless",
        "--read-only",
        "--network",
        spec.network_mode,
        "--user",
        "65534:65534",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--memory",
        spec.memory_limit,
        "--cpus",
        spec.cpu_limit,
        "--pids-limit",
        str(spec.pids_limit),
        "--userns",
        "keep-id",
        "--name",
        f"eos-acp-{spec.execution_id[-12:]}",
    ]
    for mount in spec.allowed_mounts:
        # Convert "path:rw" to --mount type=bind
        path, _, mode = mount.partition(":")
        rw = mode == "rw"
        argv.extend(
            [
                "--mount",
                f"type=bind,src={path},dst=/workspace,{'rw' if rw else 'ro'}",
            ]
        )
    argv.extend(["--workdir", "/workspace", spec.image_ref, *spec.acp_command])
    return argv


class PodmanAcpSandboxLauncher(SandboxLauncher):
    """Validates and plans sandbox ACP launches. Real execution disabled in EOS-07."""

    name = "podman-acp-sandbox"

    def __init__(
        self,
        *,
        auth_verifier: Optional[RuntimeAuthorizationVerifier] = None,
        allow_real_launch: bool = False,
        cursor_in_image: bool = False,
        disk_enforcement_available: bool = False,
    ) -> None:
        self.auth_verifier = auth_verifier
        self.allow_real_launch = allow_real_launch
        self.cursor_in_image = cursor_in_image
        self.disk_enforcement_available = disk_enforcement_available

    def readiness(self) -> Dict[str, Any]:
        items = {
            "rootless_podman_policy": True,
            "cursor_in_pinned_image": self.cursor_in_image,
            "disk_limit_enforcement": self.disk_enforcement_available,
            "real_launch_enabled": self.allow_real_launch,
            "host_home_mounts": False,
            "credential_mounts": False,
            "runtime_socket_mounts": False,
        }
        blocked: List[str] = []
        if not self.cursor_in_image:
            blocked.append("cursor_image_unsuitable")
        if not self.disk_enforcement_available:
            blocked.append("disk_limit_unsupported")
        if not self.allow_real_launch:
            blocked.append("real_launch_disabled_eos07")
        status = "BLOCKED" if blocked else "READY_FOR_AUTHORIZATION"
        return {
            "backend": self.name,
            "status": status,
            "items": items,
            "blocked": blocked,
            "evidence_class": UNAVAILABLE if blocked else ERROR,
            "note": "OpenClaw sandbox=require is not ACP isolation evidence",
        }

    def plan(self, spec: SandboxExecutionSpec) -> LaunchPlan:
        errors = validate_sandbox_spec(spec)
        if not self.disk_enforcement_available and "disk_limit_unsupported" not in errors:
            if spec.disk_limit_policy != "enforced_quota":
                errors.append("disk_limit_unsupported")
                errors = sorted(set(errors))
        argv = build_podman_argv(spec)
        # Reject host HOME / credential / socket patterns in argv.
        joined = " ".join(argv)
        for bad in ("docker.sock", "podman.sock", "/home/", ".ssh", ".cursor"):
            if bad in joined:
                errors.append("sandbox_bypass_rejected")
        blocked = None
        mode = "PLANNED"
        if errors:
            blocked = ",".join(errors)
            mode = "BLOCKED"
        return LaunchPlan(
            argv=argv,
            env={"EOS_EXECUTION_ID": spec.execution_id, "HOME": "/nonexistent"},
            spec=spec,
            validation_errors=errors,
            mode=mode,
            blocked_reason=blocked,
        )

    def launch(
        self,
        spec: SandboxExecutionSpec,
        *,
        authorization: Optional[RuntimeAuthorization] = None,
        mode: str = "REAL",
    ) -> LaunchResult:
        plan = self.plan(spec)
        if mode == "REAL":
            if plan.validation_errors:
                return LaunchResult(
                    ok=False,
                    status="BLOCKED",
                    evidence_class=ERROR,
                    failure_reason=plan.blocked_reason,
                    details=plan.to_dict(),
                )
            if not self.allow_real_launch:
                return LaunchResult(
                    ok=False,
                    status="BLOCKED",
                    evidence_class=ERROR,
                    failure_reason="real_launch_disabled_eos07",
                    details=plan.to_dict(),
                )
            if authorization is None or self.auth_verifier is None:
                return LaunchResult(
                    ok=False,
                    status="BLOCKED",
                    evidence_class=ERROR,
                    failure_reason="missing_runtime_authorization",
                    details=plan.to_dict(),
                )
            try:
                self.auth_verifier.verify(
                    authorization,
                    execution_id=spec.execution_id,
                    project_id=spec.project_id,
                    workspace_id=spec.workspace_id,
                    agent_id=spec.agent_id,
                    image_digest=spec.image_digest,
                    network_mode=spec.network_mode,
                    cpu_limit=spec.cpu_limit,
                    memory_limit=spec.memory_limit,
                    pids_limit=spec.pids_limit,
                )
            except AuthorizationError as exc:
                return LaunchResult(
                    ok=False,
                    status="BLOCKED",
                    evidence_class=ERROR,
                    failure_reason=str(exc),
                    details={"code": exc.code, **plan.to_dict()},
                )
            # Even with auth, EOS-07 does not execute containers.
            raise SandboxLauncherError(
                "container_execution_not_authorized_in_eos07",
                code="not_executed",
            )
        # SYNTHETIC / MOCK path — no real process.
        if mode not in {"SYNTHETIC", "MOCK"}:
            raise SandboxLauncherError(f"unknown_launch_mode:{mode}", code="bad_mode")
        return LaunchResult(
            ok=True,
            status="MOCK_LAUNCHED",
            evidence_class=SYNTHETIC,
            evidence_refs=[f"mock-sandbox:{spec.spec_id}"],
            details={
                **plan.to_dict(),
                "note": "mock sandbox launch; no container started",
                "completed_at": utc_now(),
                "cleanup_status": "synthetic_cleanup_ok",
            },
        )


class RejectHostDirectLauncher(SandboxLauncher):
    """Rejects any attempt to spawn Cursor ACP directly on the host."""

    name = "reject-host-direct"

    def readiness(self) -> Dict[str, Any]:
        return {
            "backend": self.name,
            "status": "BLOCKED",
            "items": {"direct_host_cursor_acp": False},
            "blocked": ["direct_host_execution_rejected"],
            "evidence_class": ERROR,
        }

    def plan(self, spec: SandboxExecutionSpec) -> LaunchPlan:
        return LaunchPlan(
            argv=[],
            env={},
            spec=spec,
            validation_errors=["direct_host_execution_rejected"],
            mode="BLOCKED",
            blocked_reason="direct_host_execution_rejected",
        )

    def launch(
        self,
        spec: SandboxExecutionSpec,
        *,
        authorization: Optional[RuntimeAuthorization] = None,
        mode: str = "REAL",
    ) -> LaunchResult:
        return LaunchResult(
            ok=False,
            status="BLOCKED",
            evidence_class=ERROR,
            failure_reason="direct_host_execution_rejected",
            details={"note": "ACPX must route cursor through sandbox launcher"},
        )


def scan_argv_for_bypass(argv: Sequence[str]) -> List[str]:
    """Lightweight safety scan aligned with scripts/sandbox/assertions themes."""
    issues: List[str] = []
    text = " ".join(argv)
    for flag in ("--privileged", "--env-host", "--pid=host", "--ipc=host"):
        if flag in text:
            issues.append(f"forbidden_flag:{flag}")
    for marker in ("docker.sock", "podman.sock", ".ssh", "EOS_GITHUB_TOKEN"):
        if marker in text:
            issues.append(f"forbidden_marker:{marker}")
    return issues
