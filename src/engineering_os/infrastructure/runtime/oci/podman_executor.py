"""PodmanSandboxExecutor — real OCI process launcher for EOS-08 ACP fixtures.

Does not enable Cursor ACP live. Owner triple-gate required for real execution.
Tests and demos inject process factories and never start containers during CI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence
import hashlib
import os
import re
import shutil
import subprocess
import tempfile

from engineering_os.domain.models import new_id, utc_now
from engineering_os.infrastructure.acp.acp_fixture import FIXTURE_PROTOCOL_SUBSET, fixture_script_path
from engineering_os.infrastructure.evidence import (
    ERROR,
    SYNTHETIC_IN_MEMORY,
    SYNTHETIC_OCI_EXECUTED,
    UNAVAILABLE,
)
from engineering_os.infrastructure.runtime.oci.oci_process import (
    InjectedFixtureProcess,
    OciProcessError,
    OciProcessHandle,
    SubprocessOciHandle,
)
from engineering_os.infrastructure.runtime.sandbox.sandbox_launcher import scan_argv_for_bypass


ProcessFactory = Callable[["FixtureLaunchRequest"], OciProcessHandle]


class OwnerGateError(RuntimeError):
    def __init__(self, message: str, *, code: str = "owner_gate_error") -> None:
        super().__init__(message)
        self.code = code


def require_owner_execution_gates(
    *,
    execute: bool,
    allow_phase_b: bool,
    owner_authorize_runtime_execution: bool,
) -> None:
    flags = (execute, allow_phase_b, owner_authorize_runtime_execution)
    if any(flags) and not all(flags):
        raise OwnerGateError(
            "incomplete_owner_execution_gate: require --execute --allow-phase-b "
            "--owner-authorize-runtime-execution together",
            code="incomplete_gate",
        )
    if not all(flags):
        raise OwnerGateError(
            "owner_execution_gate_not_asserted",
            code="gate_required",
        )


@dataclass
class FixtureLaunchRequest:
    execution_id: str
    project_id: str
    task_id: str
    image_ref: str
    image_digest: Optional[str]
    memory_limit: str = "256m"
    cpu_limit: str = "0.50"
    pids_limit: int = 64
    wall_clock_seconds: int = 30
    tmpfs_size: str = "64m"
    network_mode: str = "none"
    correlation_id: str = ""
    evidence_dir: Optional[str] = None


@dataclass
class FixturePlan:
    argv: List[str]
    workload_profile: str
    image_ref: str
    controls: Dict[str, bool]
    fixture_script: str
    mode: str
    blocked_reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "argv": list(self.argv),
            "workload_profile": self.workload_profile,
            "image_ref": self.image_ref,
            "controls": dict(self.controls),
            "fixture_script": self.fixture_script,
            "mode": self.mode,
            "blocked_reasons": list(self.blocked_reasons),
        }


def build_fixture_podman_argv(
    *,
    image_ref: str,
    fixture_host_path: str,
    container_name: str,
    memory_limit: str = "256m",
    cpu_limit: str = "0.50",
    pids_limit: int = 64,
    tmpfs_size: str = "64m",
    network_mode: str = "none",
    rm: bool = False,
) -> List[str]:
    """Fixed-policy argv for the EOS-08 ACP fixture workload. No shell interpolation."""
    if network_mode != "none":
        raise OciProcessError("network_must_be_none", code="network")
    if not re.fullmatch(r"[0-9]+[kKmMgG]?", tmpfs_size):
        raise OciProcessError("invalid_tmpfs_size", code="tmpfs")
    if not re.fullmatch(r"eos-acp-fix-[A-Za-z0-9._-]{4,80}", container_name):
        raise OciProcessError("invalid_container_name", code="name")
    fixture = Path(fixture_host_path).resolve()
    if not fixture.is_file():
        raise OciProcessError("fixture_script_missing", code="fixture")
    argv = [
        "podman",
        "run",
        "-i",
        "--pull=never",
        "--read-only",
        "--network",
        "none",
        "--userns=keep-id",
        "--user",
        "65534:65534",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--memory",
        memory_limit,
        "--cpus",
        cpu_limit,
        "--pids-limit",
        str(pids_limit),
        "--tmpfs",
        f"/tmp:rw,noexec,nosuid,size={tmpfs_size}",
        "--mount",
        f"type=bind,src={fixture},dst=/fixture/acp_fixture.sh,ro",
        "--workdir",
        "/tmp",
        "--name",
        container_name,
        "-e",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "-e",
        "HOME=/tmp",
        "-e",
        "LANG=C.UTF-8",
    ]
    if rm:
        argv.append("--rm")
    argv.extend([image_ref, "sh", "/fixture/acp_fixture.sh"])
    bypass = scan_argv_for_bypass(argv)
    if bypass:
        raise OciProcessError(f"argv_bypass:{','.join(bypass)}", code="bypass")
    return argv


class PodmanSandboxExecutor:
    """Starts/controls ACP fixture containers. Real Podman only with Owner gates."""

    WORKLOAD_PROFILE = "m03_style_acp_fixture_ndjson_v1"

    def __init__(
        self,
        *,
        process_factory: Optional[ProcessFactory] = None,
        which: Optional[Callable[[str], Optional[str]]] = None,
        podman_info_runner: Optional[Callable[[], Dict[str, Any]]] = None,
        allow_real_podman: bool = False,
        expected_image_digest: Optional[str] = None,
        code_revision: str = "unknown",
    ) -> None:
        self.process_factory = process_factory
        self.which = which or shutil.which
        self.podman_info_runner = podman_info_runner
        self.allow_real_podman = allow_real_podman
        self.expected_image_digest = expected_image_digest
        self.code_revision = code_revision
        self.last_handle: Optional[OciProcessHandle] = None

    def readiness(self) -> Dict[str, Any]:
        podman_path = self.which("podman")
        info: Dict[str, Any] = {}
        rootless = False
        image_ok = False
        reasons: List[str] = []
        if self.process_factory is not None and not self.allow_real_podman:
            # Injected offline path — do not require host Podman for readiness.
            return {
                "status": "READY_INJECTED",
                "podman_path": podman_path,
                "rootless": True,
                "image_ok": True,
                "image_ref": None,
                "workload_profile": self.WORKLOAD_PROFILE,
                "protocol_subset": list(FIXTURE_PROTOCOL_SUBSET),
                "blocked_reasons": [],
                "allow_real_podman": False,
                "live_cursor_acp": False,
                "evidence_class": SYNTHETIC_IN_MEMORY,
                "note": "Injected process factory active; real Podman not selected",
            }
        if not podman_path:
            reasons.append("podman_missing")
        else:
            if self.podman_info_runner:
                info = self.podman_info_runner()
            else:
                info = probe_podman_runtime()
            rootless = bool(info.get("rootless"))
            if info.get("rootless") is False:
                reasons.append("podman_rootful_rejected")
            if info.get("rootless") is None:
                reasons.append("podman_rootless_unverified")
            if info.get("image_present"):
                image_ok = True
            else:
                reasons.append("required_image_absent")
            if self.expected_image_digest and info.get("image_digest"):
                if info["image_digest"] != self.expected_image_digest:
                    reasons.append("image_identity_mismatch")
                    image_ok = False
        if not Path(fixture_script_path()).is_file():
            reasons.append("fixture_script_missing")
        status = "READY" if not reasons else "BLOCKED"
        return {
            "status": status,
            "podman_path": podman_path,
            "rootless": rootless,
            "image_ok": image_ok,
            "image_ref": (info or {}).get("image_ref") if podman_path else None,
            "image_digest": (info or {}).get("image_digest") if podman_path else None,
            "workload_profile": self.WORKLOAD_PROFILE,
            "protocol_subset": list(FIXTURE_PROTOCOL_SUBSET),
            "blocked_reasons": reasons,
            "allow_real_podman": self.allow_real_podman,
            "live_cursor_acp": False,
            "evidence_class": (
                SYNTHETIC_OCI_EXECUTED
                if not reasons and self.allow_real_podman
                else (UNAVAILABLE if reasons else SYNTHETIC_IN_MEMORY)
            ),
            "note": "Owner triple-gate required for real Podman; Cursor ACP remains disabled",
        }

    def plan(self, request: FixtureLaunchRequest) -> FixturePlan:
        name = f"eos-acp-fix-{request.execution_id[-12:]}"
        fixture = fixture_script_path()
        blocked: List[str] = []
        if request.network_mode != "none":
            blocked.append("unapproved_network")
        try:
            argv = build_fixture_podman_argv(
                image_ref=request.image_ref,
                fixture_host_path=fixture,
                container_name=name,
                memory_limit=request.memory_limit,
                cpu_limit=request.cpu_limit,
                pids_limit=request.pids_limit,
                tmpfs_size=request.tmpfs_size,
                network_mode=request.network_mode,
                rm=False,
            )
        except OciProcessError as exc:
            blocked.append(str(exc))
            argv = []
        ready = self.readiness()
        blocked.extend(ready.get("blocked_reasons") or [])
        controls = {
            "read_only_root": True,
            "network_none": True,
            "cap_drop_all": True,
            "no_new_privileges": True,
            "userns_keep_id": True,
            "tmpfs_tmp": True,
            "no_host_home": True,
            "no_credentials": True,
            "no_runtime_socket": True,
            "pull_never": True,
        }
        mode = "BLOCKED" if blocked else "PLANNED"
        return FixturePlan(
            argv=argv,
            workload_profile=self.WORKLOAD_PROFILE,
            image_ref=request.image_ref,
            controls=controls,
            fixture_script=fixture,
            mode=mode,
            blocked_reasons=sorted(set(blocked)),
        )

    def start(
        self,
        request: FixtureLaunchRequest,
        *,
        execute: bool = False,
        allow_phase_b: bool = False,
        owner_authorize_runtime_execution: bool = False,
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        plan = self.plan(request)
        if dry_run or not execute:
            return {
                "action": "dry_run",
                "plan": plan.to_dict(),
                "started": False,
                "evidence_class": SYNTHETIC_IN_MEMORY,
            }
        require_owner_execution_gates(
            execute=execute,
            allow_phase_b=allow_phase_b,
            owner_authorize_runtime_execution=owner_authorize_runtime_execution,
        )
        if plan.blocked_reasons and not self.process_factory:
            return {
                "action": "refused",
                "plan": plan.to_dict(),
                "started": False,
                "failure_reason": ",".join(plan.blocked_reasons),
                "evidence_class": ERROR,
            }
        if self.process_factory:
            handle = self.process_factory(request)
            evidence_class = SYNTHETIC_IN_MEMORY
            mode = "INJECTED"
        else:
            if not self.allow_real_podman:
                raise OwnerGateError(
                    "real_podman_disabled_in_executor_config",
                    code="podman_disabled",
                )
            handle = self._spawn_podman(plan, request)
            evidence_class = SYNTHETIC_OCI_EXECUTED
            mode = "PODMAN"
        self.last_handle = handle
        return {
            "action": "started",
            "started": True,
            "mode": mode,
            "plan": plan.to_dict(),
            "container_id": handle.container_id,
            "evidence_class": evidence_class,
            "code_revision": self.code_revision,
            "started_at": utc_now(),
        }

    def _spawn_podman(
        self, plan: FixturePlan, request: FixtureLaunchRequest
    ) -> SubprocessOciHandle:
        # Real path — not invoked by automated tests in EOS-08.
        name = f"eos-acp-fix-{request.execution_id[-12:]}"
        handle, _ = SubprocessOciHandle.start_podman(plan.argv, container_name=name)
        return handle


def default_injected_factory(scenario: str = "success") -> ProcessFactory:
    def factory(request: FixtureLaunchRequest) -> OciProcessHandle:
        return InjectedFixtureProcess(
            scenario=scenario,
            container_id=f"injected-{request.execution_id[-8:]}",
        )

    return factory


def probe_podman_runtime() -> Dict[str, Any]:
    """Best-effort local Podman rootless + alpine/busybox image probe."""
    if not shutil.which("podman"):
        return {
            "rootless": False,
            "image_present": False,
            "image_ref": None,
            "image_digest": None,
            "error": "podman_missing",
        }
    rootless: Optional[bool] = None
    try:
        info_proc = subprocess.run(
            ["podman", "info", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if info_proc.returncode == 0 and info_proc.stdout.strip():
            import json as _json

            info = _json.loads(info_proc.stdout)
            host = info.get("host") if isinstance(info.get("host"), dict) else {}
            security = host.get("security") if isinstance(host.get("security"), dict) else {}
            if "rootless" in security:
                rootless = bool(security.get("rootless"))
            elif "rootless" in host:
                rootless = bool(host.get("rootless"))
    except Exception as exc:  # noqa: BLE001
        return {
            "rootless": None,
            "image_present": False,
            "image_ref": None,
            "image_digest": None,
            "error": f"podman_info_failed:{exc}",
        }
    image_ref = resolve_local_fixture_image()
    digest = None
    if image_ref:
        try:
            dig = subprocess.run(
                ["podman", "image", "inspect", "--format", "{{.Digest}}", image_ref],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if dig.returncode == 0:
                digest = (dig.stdout or "").strip() or None
        except Exception:
            digest = None
    return {
        "rootless": rootless,
        "image_present": bool(image_ref),
        "image_ref": image_ref,
        "image_digest": digest,
    }


def resolve_local_fixture_image() -> Optional[str]:
    """Pick an exact local alpine/busybox image ref; never pull."""
    try:
        listed = subprocess.run(
            ["podman", "images", "--format", "{{.Repository}}:{{.Tag}}"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except Exception:
        return None
    if listed.returncode != 0:
        return None
    names = [ln.strip() for ln in (listed.stdout or "").splitlines() if ln.strip()]
    preferred: List[str] = []
    for name in names:
        lower = name.lower()
        if lower.endswith(":<none>") or lower.endswith(":none"):
            continue
        if "alpine" in lower or "busybox" in lower:
            preferred.append(name)
    # Prefer alpine over busybox, then shorter/more specific tags.
    preferred.sort(key=lambda n: (0 if "alpine" in n.lower() else 1, len(n)))
    return preferred[0] if preferred else None


def evidence_dir_default() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    path = Path(base) / "engineering-os" / "oci-fixture-evidence"
    path.mkdir(parents=True, exist_ok=True)
    return path


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
