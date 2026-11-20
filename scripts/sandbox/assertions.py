#!/usr/bin/env python3
"""Host-side assertion helpers for the Engineering OS sandbox PoC.

Evidence layers (must not be conflated):

1. launcher_config / planned_controls — intent encoded by the planner
2. executed_argv / argv_safety_scan — subprocess arguments actually passed
3. runtime_inspected_controls — read-only podman inspect (when available)
4. behavioral_evidence — negative-test outcomes, canaries, probe statuses

Argv inspection alone is never sufficient to claim isolation enforcement.
These helpers do not launch containers or touch real secrets.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any, Literal

PathKind = Literal["absent", "present_readable", "present_denied", "present_other", "unknown"]
ProbeStatus = Literal["executed_denied", "executed_succeeded", "unavailable", "unknown"]

APPROVED_FIXTURE_PREFIXES = (
    Path(tempfile.gettempdir()).resolve(),
)
FIXTURE_MARKER = ".eos-sandbox-poc"
FIXTURE_MARKER_CONTENT = "eos-sandbox-poc-synthetic-v1\n"
FIXTURE_NAME_RE = re.compile(r"^eos-sandbox-poc-[A-Za-z0-9._-]{4,80}$")
EXPECTED_CHILDREN = ("synth-alpha", "synth-beta", "outside-host", "synthetic-secrets")
ALLOWED_TEST_IDS = tuple(f"P{i}" for i in range(1, 9))
FORBIDDEN_ARGV_MARKERS = (
    "--privileged",
    "--env-host",
    "docker.sock",
    "podman.sock",
    "SSH_AUTH_SOCK",
)
VALID_CONTROL_EVIDENCE_SOURCES = frozenset(
    {
        "runtime_inspected",
        "runtime_inspected_and_behavioral",
    }
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_canary(path: Path, payload: bytes) -> str:
    """Write a synthetic canary and return its SHA-256 hex digest."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return sha256_file(path)


def verify_canary_unchanged(path: Path, expected_sha256: str) -> None:
    if not path.exists():
        raise AssertionError(f"canary missing after execution: {path.name}")
    actual = sha256_file(path)
    if actual != expected_sha256:
        raise AssertionError(
            f"canary integrity failure for {path.name}: "
            f"expected {expected_sha256}, got {actual}"
        )


def classify_path(path: Path) -> PathKind:
    """Differentiate absent paths from present-but-denied paths (host side)."""
    if not path.exists():
        try:
            path.open("rb").close()
        except FileNotFoundError:
            return "absent"
        except PermissionError:
            return "present_denied"
        except OSError:
            return "present_other"
        return "absent"
    try:
        with path.open("rb"):
            return "present_readable"
    except PermissionError:
        return "present_denied"
    except OSError:
        return "present_other"


def assert_denied_or_absent(path: Path, *, require_present: bool = False) -> PathKind:
    kind = classify_path(path)
    if require_present and kind == "absent":
        raise AssertionError(
            f"expected path present but denied; was absent "
            f"(false-positive risk): {path.name}"
        )
    if kind == "present_readable":
        raise AssertionError(f"path unexpectedly readable: {path.name}")
    return kind


def is_within(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def looks_like_repository_path(path: Path) -> bool:
    resolved = path.resolve()
    for parent in (resolved, *resolved.parents):
        if (parent / ".git").exists() and (parent / "docs").exists() and (parent / "scripts").exists():
            return True
    return False


def _approved_prefixes() -> list[Path]:
    prefixes = [p.resolve() for p in APPROVED_FIXTURE_PREFIXES]
    override = os.environ.get("EOS_SANDBOX_FIXTURE_PREFIX")
    if override:
        override_path = Path(override)
        if override_path.exists() and override_path.is_symlink():
            raise AssertionError("EOS_SANDBOX_FIXTURE_PREFIX must not be a symlink")
        resolved = override_path.resolve()
        if not any(is_within(resolved, p) or resolved == p for p in prefixes):
            raise AssertionError("EOS_SANDBOX_FIXTURE_PREFIX outside approved prefixes")
        prefixes.append(resolved)
    return prefixes


def validate_fixture_root(path: Path, *, must_exist: bool = False) -> Path:
    """Fail closed unless fixture root is a dedicated owned disposable subdirectory."""
    if path is None:
        raise AssertionError("fixture root is required")

    if path.exists() and path.is_symlink():
        raise AssertionError("fixture root must not be a symlink")

    resolved = path.resolve()
    if must_exist and not resolved.exists():
        raise AssertionError("fixture root does not exist")

    if looks_like_repository_path(resolved):
        raise AssertionError("fixture root must not be inside the repository tree")

    prefixes = _approved_prefixes()
    if any(resolved == prefix for prefix in prefixes):
        raise AssertionError("fixture root must be a dedicated subdirectory, not the temp parent")

    if not any(is_within(resolved, prefix) for prefix in prefixes):
        raise AssertionError(
            "fixture root must resolve under an approved disposable prefix "
            f"(default: {APPROVED_FIXTURE_PREFIXES[0]})"
        )

    if not FIXTURE_NAME_RE.match(resolved.name):
        raise AssertionError(
            "fixture root name must match eos-sandbox-poc-<unique> "
            "(dedicated uniquely named disposable subdirectory)"
        )

    if resolved.exists():
        if not resolved.is_dir():
            raise AssertionError("fixture root exists but is not a directory")
        st = resolved.stat()
        if st.st_uid != os.getuid():
            raise AssertionError("fixture root must be owned by the current user")
        mode = stat.S_IMODE(st.st_mode)
        if mode & 0o022:
            raise AssertionError("fixture root must not be group/world-writable")
        if mode & 0o077:
            raise AssertionError("fixture root permissions must be owner-only (e.g. 0700)")

        for child in resolved.iterdir():
            if child.is_symlink():
                raise AssertionError(f"unsafe symlink descendant rejected: {child.name}")

        marker = resolved / FIXTURE_MARKER
        contents = [p for p in resolved.iterdir() if p.name != FIXTURE_MARKER]
        if contents and not marker.exists():
            raise AssertionError(
                "refusing to reuse non-empty directory without "
                f"{FIXTURE_MARKER} marker"
            )
        if marker.exists():
            text = marker.read_text(encoding="utf-8")
            if text != FIXTURE_MARKER_CONTENT:
                raise AssertionError("fixture marker content mismatch")
    return resolved


def ensure_fixture_marker(root: Path) -> None:
    root = validate_fixture_root(root, must_exist=True)
    marker = root / FIXTURE_MARKER
    marker.write_text(FIXTURE_MARKER_CONTENT, encoding="utf-8")
    os.chmod(marker, 0o600)


def validate_fixture_structure(root: Path) -> None:
    root = validate_fixture_root(root, must_exist=True)
    marker = root / FIXTURE_MARKER
    if not marker.is_file() or marker.read_text(encoding="utf-8") != FIXTURE_MARKER_CONTENT:
        raise AssertionError("missing or invalid fixture marker")
    for name in EXPECTED_CHILDREN:
        child = root / name
        if not child.is_dir() or child.is_symlink():
            raise AssertionError(f"missing expected synthetic directory: {name}")


def safe_to_cleanup_fixture_root(root: Path) -> bool:
    try:
        resolved = validate_fixture_root(root, must_exist=True)
    except AssertionError:
        return False
    marker = resolved / FIXTURE_MARKER
    if not marker.is_file():
        return False
    if marker.read_text(encoding="utf-8") != FIXTURE_MARKER_CONTENT:
        return False
    if resolved.stat().st_uid != os.getuid():
        return False
    return True


def parse_test_ids(raw: str) -> list[str]:
    """Accept only the fixed P1–P8 catalog tokens."""
    if not raw or not str(raw).strip():
        raise AssertionError("test id list is required")
    parts = [p.strip().upper() for p in str(raw).split(",") if p.strip()]
    if not parts:
        raise AssertionError("test id list is empty")
    unknown = sorted({p for p in parts if p not in ALLOWED_TEST_IDS})
    if unknown:
        raise AssertionError(f"unsupported test ids: {unknown}")
    seen: set[str] = set()
    out: list[str] = []
    for part in parts:
        if part not in seen:
            seen.add(part)
            out.append(part)
    return out


def sanitize_evidence_text(text: str) -> str:
    """Redact common host identity tokens from evidence strings."""
    if not text:
        return ""
    redacted = text
    home = str(Path.home())
    if home:
        redacted = redacted.replace(home, "<HOME>")
    user = os.environ.get("USER") or os.environ.get("LOGNAME")
    if user:
        redacted = re.sub(rf"\b{re.escape(user)}\b", "<USER>", redacted)
    return redacted[:8000]


def scan_argv_safety(cmd: list[str], *, workspace: Path) -> dict[str, Any]:
    """Safety-scan executed/planned argv. This is NOT runtime enforcement proof."""
    if not cmd or cmd[0] != "podman" or "run" not in cmd[:3]:
        return {
            "argv_passed_safety_scan": False,
            "reject_reason": "argv must start with podman run",
            "launcher_argv_controls": {},
            "evidence_layer": "executed_argv",
        }

    joined = " ".join(cmd)
    for marker in FORBIDDEN_ARGV_MARKERS:
        if marker in joined:
            return {
                "argv_passed_safety_scan": False,
                "reject_reason": f"forbidden marker present: {marker}",
                "launcher_argv_controls": {},
                "evidence_layer": "executed_argv",
            }

    home = str(Path.home())
    ws = str(workspace.resolve())
    bind_mounts = [p for p in cmd if p.startswith("type=bind,src=")]
    if len(bind_mounts) != 1:
        return {
            "argv_passed_safety_scan": False,
            "reject_reason": f"expected exactly one bind mount, found {len(bind_mounts)}",
            "launcher_argv_controls": {},
            "evidence_layer": "executed_argv",
        }
    if not bind_mounts[0].startswith(f"type=bind,src={ws},dst=/workspace"):
        return {
            "argv_passed_safety_scan": False,
            "reject_reason": "bind mount must map disposable workspace to /workspace",
            "launcher_argv_controls": {},
            "evidence_layer": "executed_argv",
        }
    if home and home in bind_mounts[0]:
        return {
            "argv_passed_safety_scan": False,
            "reject_reason": "bind mount must not reference host HOME",
            "launcher_argv_controls": {},
            "evidence_layer": "executed_argv",
        }

    def has(*tokens: str) -> bool:
        return all(t in cmd for t in tokens)

    launcher_argv_controls = {
        "read_only_root": "--read-only" in cmd,
        "network_none": has("--network", "none"),
        "cap_drop_all": has("--cap-drop", "ALL"),
        "no_new_privileges": has("--security-opt", "no-new-privileges"),
        "pull_never": "--pull=never" in cmd,
        "rm_flag": "--rm" in cmd,
        "tmpfs_tmp": any(p.startswith("/tmp:") or p.startswith("/tmp=") for p in cmd)
        or any(str(p).startswith("/tmp:") for p in cmd),
        "memory_limit": "--memory" in cmd,
        "cpu_limit": "--cpus" in cmd,
        "pids_limit": "--pids-limit" in cmd,
        "workspace_only_mount": True,
        "no_docker_socket_mount": "docker.sock" not in joined and "podman.sock" not in joined,
        "no_host_home_mount": True,
        "minimal_env": "-e" in cmd and "SSH_AUTH_SOCK" not in joined,
        "userns_keep_id": "--userns=keep-id" in cmd,
        "non_root_user": False,
        "privileged": "--privileged" in cmd,
    }
    if "--user" in cmd:
        idx = cmd.index("--user")
        if idx + 1 < len(cmd):
            user_spec = cmd[idx + 1]
            launcher_argv_controls["non_root_user"] = (
                user_spec != "0:0" and not user_spec.startswith("0:")
            )

    return {
        "argv_passed_safety_scan": True,
        "launcher_argv_controls": launcher_argv_controls,
        "bind_mount_count": len(bind_mounts),
        "evidence_layer": "executed_argv",
        # Explicit: argv-derived flags are not runtime observations.
        "is_runtime_enforcement_proof": False,
    }


# Backward-compatible alias used by older call sites during transition.
def observe_controls_from_argv(cmd: list[str], *, workspace: Path) -> dict[str, Any]:
    """Deprecated name: argv scan only. Does not prove runtime enforcement."""
    probe = scan_argv_safety(cmd, workspace=workspace)
    # Do not present argv flags as observed_controls.
    return {
        "argv_passed_safety_scan": probe.get("argv_passed_safety_scan"),
        "reject_reason": probe.get("reject_reason"),
        "launcher_argv_controls": probe.get("launcher_argv_controls") or {},
        "observed_controls": {},
        "bind_mount_count": probe.get("bind_mount_count"),
        "is_runtime_enforcement_proof": False,
        "evidence_layer": "executed_argv",
    }


def parse_podman_inspect(payload: Any) -> dict[str, Any]:
    """Parse `podman inspect` JSON into runtime-inspected control booleans.

    Read-only transformation of inspect output. Does not execute Podman.
    """
    try:
        data = payload
        if isinstance(payload, str):
            data = json.loads(payload)
        if isinstance(data, list):
            if not data:
                return {"ok": False, "error": "empty_inspect_list"}
            data = data[0]
        if not isinstance(data, dict):
            return {"ok": False, "error": "inspect_payload_not_object"}
    except (json.JSONDecodeError, TypeError) as exc:
        return {"ok": False, "error": f"inspect_parse_failed:{type(exc).__name__}"}

    host = data.get("HostConfig") if isinstance(data.get("HostConfig"), dict) else {}
    cfg = data.get("Config") if isinstance(data.get("Config"), dict) else {}
    state = data.get("State") if isinstance(data.get("State"), dict) else {}

    network_mode = str(host.get("NetworkMode") or "").lower()
    binds = host.get("Binds") or []
    if not isinstance(binds, list):
        binds = []
    cap_drop = [str(x).upper() for x in (host.get("CapDrop") or [])]
    security_opt = [str(x).lower() for x in (host.get("SecurityOpt") or [])]
    privileged = bool(host.get("Privileged"))
    readonly = bool(host.get("ReadonlyRootfs"))
    memory = int(host.get("Memory") or 0)
    pids_limit = int(host.get("PidsLimit") or 0)
    nano_cpus = int(host.get("NanoCpus") or 0)
    user = str(cfg.get("User") or "")
    oom_killed = bool(state.get("OOMKilled"))

    workspace_binds = [
        b
        for b in binds
        if isinstance(b, str)
        and (
            ":/workspace:" in b
            or b.endswith(":/workspace")
            or ":/workspace," in b
        )
    ]
    socket_bound = any(
        isinstance(b, str) and ("docker.sock" in b or "podman.sock" in b) for b in binds
    )
    home_bound = any(isinstance(b, str) and "/home/" in b for b in binds)

    controls = {
        "read_only_root": readonly,
        "network_none": network_mode in {"none", "slug:none"} or network_mode.endswith(":none"),
        "cap_drop_all": "ALL" in cap_drop,
        "no_new_privileges": any("no-new-privileges" in s for s in security_opt),
        "memory_limit": memory > 0,
        "cpu_limit": nano_cpus > 0 or float(host.get("CpuQuota") or 0) > 0,
        "pids_limit": pids_limit > 0,
        "workspace_only_mount": len(binds) == 1 and len(workspace_binds) == 1,
        "no_docker_socket_mount": not socket_bound,
        "no_host_home_mount": not home_bound,
        "non_root_user": bool(user) and user not in {"0", "0:0", "root"},
        "privileged": privileged,
        "rm_flag": False,  # cannot prove --rm from inspect of a remaining container
        "userns_keep_id": "keep-id" in str(data.get("HostConfig", {})).lower()
        or "keep-id" in json.dumps(data.get("IdMappings") or {}).lower(),
    }
    # userns keep-id is not always visible; leave False unless clear evidence.
    annotations = data.get("Annotations") if isinstance(data.get("Annotations"), dict) else {}
    if any("keep-id" in str(v).lower() for v in annotations.values()):
        controls["userns_keep_id"] = True

    return {
        "ok": True,
        "evidence_layer": "runtime_inspected",
        "runtime_inspected_controls": controls,
        "raw_summary": {
            "network_mode": network_mode,
            "readonly_rootfs": readonly,
            "privileged": privileged,
            "memory_bytes": memory,
            "pids_limit": pids_limit,
            "nano_cpus": nano_cpus,
            "binds": [sanitize_evidence_text(str(b)) for b in binds],
            "user": user,
            "oom_killed": oom_killed,
            "cap_drop": cap_drop,
            "security_opt": security_opt,
        },
        "oom_killed": oom_killed,
    }


def parse_container_path_kind(stdout: str) -> PathKind:
    """Parse container-side path classification marker from probe stdout."""
    match = re.search(r"(?m)^CONTAINER_PATH_KIND=(absent|present_readable|present_denied|present_other)$", stdout)
    if not match:
        return "unknown"
    return match.group(1)  # type: ignore[return-value]


def parse_probe_status(stdout: str, prefix: str) -> ProbeStatus:
    """Parse IP_PROBE_STATUS / DNS_PROBE_STATUS style markers."""
    match = re.search(
        rf"(?m)^{re.escape(prefix)}=(executed_denied|executed_succeeded|unavailable)$",
        stdout,
    )
    if not match:
        return "unknown"
    return match.group(1)  # type: ignore[return-value]


def memory_limit_attributed(result: dict[str, Any]) -> bool:
    """True only with attributable memory-limit evidence (not arbitrary nonzero)."""
    if result.get("oom_killed") is True:
        return True
    if result.get("exit_code") == 137:
        return True
    blob = f"{result.get('stdout') or ''}\n{result.get('stderr') or ''}".lower()
    if "oom" in blob or "out of memory" in blob or "memory cgroup" in blob:
        return True
    if result.get("memory_attribution") == "oom_or_cgroup":
        return True
    return False


def pids_limit_attributed(result: dict[str, Any]) -> bool:
    """True only with attributable PID-limit evidence."""
    if result.get("pids_attribution") == "fork_denied":
        return True
    blob = f"{result.get('stdout') or ''}\n{result.get('stderr') or ''}".lower()
    if re.search(r"(?m)^FORK_DENIED=1$", result.get("stdout") or ""):
        return True
    if "resource temporarily unavailable" in blob:
        return True
    if "can't fork" in blob or "cannot fork" in blob:
        return True
    return False


def wall_clock_attributed(result: dict[str, Any]) -> bool:
    return bool(result.get("timed_out")) or result.get("wall_clock_attribution") == "host_timeout"


def evaluate_negative_result(spec: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    """Evaluate results using separated evidence layers."""
    test_id = spec["id"]
    required_controls = set(spec.get("required_controls") or [])
    planned = result.get("planned_controls") or {}
    # Runtime-inspected controls are authoritative for control presence.
    inspected = result.get("runtime_inspected_controls") or {}
    observed = result.get("observed_controls") or inspected
    evidence_source = result.get("control_evidence_source")
    provenance = result.get("controls_provenance")

    if result.get("observed_controls_copied_from_plan"):
        return {
            "id": test_id,
            "status": "FAIL",
            "reason": "observed_controls copied from planned launcher flags are not independent evidence",
        }
    if provenance in {"argv_scan_only", "planned_only", "launcher_argv"}:
        return {
            "id": test_id,
            "status": "FAIL",
            "reason": "argv/launcher configuration alone is not runtime enforcement evidence",
        }
    if evidence_source not in VALID_CONTROL_EVIDENCE_SOURCES:
        return {
            "id": test_id,
            "status": "FAIL",
            "reason": (
                "control_evidence_source must be runtime_inspected or "
                "runtime_inspected_and_behavioral"
            ),
        }
    if planned and observed and observed == planned and not inspected:
        return {
            "id": test_id,
            "status": "FAIL",
            "reason": "observed_controls match planned_controls without runtime inspect",
        }

    missing_controls = sorted(c for c in required_controls if not inspected.get(c))
    if missing_controls:
        return {
            "id": test_id,
            "status": "FAIL",
            "reason": f"required controls not runtime-inspected: {missing_controls}",
        }

    stdout = result.get("stdout") or ""
    expect = spec.get("expect") or {}
    exit_code = result.get("exit_code")
    if "exit_code_in" in expect and exit_code not in expect["exit_code_in"]:
        return {
            "id": test_id,
            "status": "FAIL",
            "reason": f"exit_code {exit_code} not in {expect['exit_code_in']}",
        }
    if "stdout_regex" in expect and not re.search(expect["stdout_regex"], stdout, re.M):
        return {
            "id": test_id,
            "status": "FAIL",
            "reason": "stdout did not match required regex",
        }
    if "stdout_forbids_regex" in expect and re.search(expect["stdout_forbids_regex"], stdout, re.M):
        return {
            "id": test_id,
            "status": "FAIL",
            "reason": "stdout matched forbidden regex",
        }

    if expect.get("require_probe_markers"):
        for marker in expect["require_probe_markers"]:
            if marker not in stdout:
                return {
                    "id": test_id,
                    "status": "FAIL",
                    "reason": f"missing required probe marker {marker!r}; generic failure is not a security PASS",
                }

    if expect.get("canary_unchanged"):
        before = result.get("canary_before")
        after = result.get("canary_after")
        if not before or not after or before != after:
            return {
                "id": test_id,
                "status": "FAIL",
                "reason": "host canary integrity failure",
            }
        if not result.get("canary_verified_on_host"):
            return {
                "id": test_id,
                "status": "FAIL",
                "reason": "canary check must be independently verified on host",
            }

    if expect.get("host_workspace_write_verified"):
        if not result.get("host_workspace_write_verified"):
            return {
                "id": test_id,
                "status": "FAIL",
                "reason": "host workspace write was not independently verified",
            }

    if expect.get("path_classification"):
        kind = result.get("path_kind")
        if kind in {None, "unknown"}:
            return {
                "id": test_id,
                "status": "FAIL",
                "reason": "container path classification missing; hard-coded kinds are forbidden",
            }
        allowed = set(expect["path_classification"])
        if kind not in allowed:
            return {
                "id": test_id,
                "status": "FAIL",
                "reason": f"path_kind {kind} not in {sorted(allowed)}",
            }

    if test_id == "P5":
        ip_status = result.get("ip_probe_status") or "unknown"
        dns_status = result.get("dns_probe_status") or "unknown"
        if ip_status == "executed_succeeded" or result.get("ip_probe_succeeded"):
            return {"id": test_id, "status": "FAIL", "reason": "direct IP probe unexpectedly succeeded"}
        if dns_status == "executed_succeeded" or result.get("dns_probe_succeeded"):
            return {"id": test_id, "status": "FAIL", "reason": "DNS probe unexpectedly succeeded"}
        if ip_status != "executed_denied":
            return {
                "id": test_id,
                "status": "FAIL",
                "reason": f"IP probe not executed-and-denied (status={ip_status})",
            }
        if dns_status != "executed_denied":
            return {
                "id": test_id,
                "status": "FAIL",
                "reason": f"DNS probe not executed-and-denied (status={dns_status})",
            }
        if not result.get("network_namespace_observed"):
            return {
                "id": test_id,
                "status": "FAIL",
                "reason": "network namespace/config was not independently observed",
            }
        if not inspected.get("network_none"):
            return {
                "id": test_id,
                "status": "FAIL",
                "reason": "runtime inspect did not confirm NetworkMode=none",
            }
        if result.get("unconditional_exit_used"):
            return {
                "id": test_id,
                "status": "FAIL",
                "reason": "unconditional exit is not valid P5 evidence",
            }

    if test_id == "P6":
        dimensions = result.get("limit_dimensions") or {}
        required_dims = list(expect.get("required_limit_dimensions") or [])
        for dim in required_dims:
            value = dimensions.get(dim)
            if value is True:
                continue
            if value == "NOT_TESTED":
                return {
                    "id": test_id,
                    "status": "FAIL",
                    "reason": f"mandatory dimension {dim} is NOT_TESTED; cannot PASS P6",
                }
            return {
                "id": test_id,
                "status": "FAIL",
                "reason": f"missing attributable evidence for dimension: {dim}",
            }
        # Optional CPU may be NOT_TESTED without failing when not required.
        if dimensions.get("tmpfs_full") and not dimensions.get("memory"):
            return {
                "id": test_id,
                "status": "FAIL",
                "reason": "tmpfs exhaustion is not proof of memory limit enforcement",
            }
        if not result.get("memory_attributed"):
            if "memory" in required_dims:
                return {
                    "id": test_id,
                    "status": "FAIL",
                    "reason": "memory dimension lacks attributable OOM/cgroup evidence",
                }
        if not result.get("pids_attributed"):
            if "pids" in required_dims:
                return {
                    "id": test_id,
                    "status": "FAIL",
                    "reason": "pids dimension lacks attributable fork-limit evidence",
                }
        if not result.get("wall_clock_attributed"):
            if "wall_clock" in required_dims:
                return {
                    "id": test_id,
                    "status": "FAIL",
                    "reason": "wall_clock dimension lacks host-timeout attribution",
                }

    if test_id == "P7":
        if not result.get("cleanup_observed"):
            return {
                "id": test_id,
                "status": "FAIL",
                "reason": "--rm intent alone is not cleanup evidence",
            }
        if result.get("cleanup_source") in {None, "planned_rm_flag", "inspect_error_assumed_absent"}:
            return {
                "id": test_id,
                "status": "FAIL",
                "reason": "cleanup must be independently observed with reliable presence checks",
            }
        if result.get("cleanup_presence_error"):
            return {
                "id": test_id,
                "status": "FAIL",
                "reason": "podman presence/inspect error cannot confirm cleanup",
            }

    return {"id": test_id, "status": "PASS", "reason": "assertion criteria satisfied"}


def ensure_mode_not_world_writable(path: Path) -> None:
    mode = path.stat().st_mode
    if mode & stat.S_IWOTH:
        raise AssertionError(f"path is world-writable: {path.name}")


def self_check() -> None:
    """Pure local unit check using disposable temporary directories."""
    from preflight import choose_exact_local_image, is_local_base_image_ref

    assert is_local_base_image_ref("alpine:3.20", "alpine")
    assert is_local_base_image_ref("docker.io/library/alpine:3.20", "alpine")
    assert not is_local_base_image_ref("localhost/3.20:latest", "alpine")
    assert choose_exact_local_image(["localhost/3.20:latest"]) is None
    assert parse_test_ids("P1,P5,P1") == ["P1", "P5"]

    # Synthetic inspect payload (no podman execution).
    fake_inspect = [
        {
            "HostConfig": {
                "NetworkMode": "none",
                "ReadonlyRootfs": True,
                "Privileged": False,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"],
                "Memory": 16 * 1024 * 1024,
                "PidsLimit": 32,
                "NanoCpus": 250000000,
                "Binds": ["/tmp/eos-sandbox-poc-x/synth-alpha:/workspace:rw"],
            },
            "Config": {"User": "1000:1001"},
            "State": {"OOMKilled": True},
            "Annotations": {},
        }
    ]
    parsed = parse_podman_inspect(fake_inspect)
    assert parsed["ok"] is True
    assert parsed["runtime_inspected_controls"]["network_none"] is True
    assert parsed["runtime_inspected_controls"]["workspace_only_mount"] is True
    assert parsed["oom_killed"] is True

    assert parse_container_path_kind("CONTAINER_PATH_KIND=absent\n") == "absent"
    assert parse_container_path_kind("no marker") == "unknown"
    assert parse_probe_status("IP_PROBE_STATUS=executed_denied\n", "IP_PROBE_STATUS") == "executed_denied"
    assert parse_probe_status("IP_PROBE_STATUS=unavailable\n", "IP_PROBE_STATUS") == "unavailable"

    with tempfile.TemporaryDirectory(prefix="eos-sandbox-assert-") as tmp:
        root = Path(tmp)
        canary = root / "outside" / "canary.txt"
        digest = write_canary(canary, b"synthetic-canary-v1\n")
        verify_canary_unchanged(canary, digest)
        if classify_path(root / "missing.txt") != "absent":
            raise AssertionError("missing path not classified as absent")

        ws = root / "eos-ws"
        ws.mkdir()
        safe_cmd = [
            "podman",
            "run",
            "--pull=never",
            "--read-only",
            "--network",
            "none",
            "--userns=keep-id",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--memory",
            "64m",
            "--cpus",
            "0.2",
            "--pids-limit",
            "32",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=64m",
            "--mount",
            f"type=bind,src={ws.resolve()},dst=/workspace,rw",
            "--workdir",
            "/workspace",
            "--rm",
            "-e",
            "PATH=/usr/bin",
            "alpine:3.20",
            "/bin/sh",
            "-c",
            "true",
        ]
        probe = scan_argv_safety(safe_cmd, workspace=ws)
        if not probe.get("argv_passed_safety_scan"):
            raise AssertionError(f"safe argv rejected: {probe}")
        if probe.get("is_runtime_enforcement_proof"):
            raise AssertionError("argv scan must not claim runtime enforcement proof")

        # Argv-only evidence must FAIL evaluation.
        argv_only = evaluate_negative_result(
            {
                "id": "P8",
                "required_controls": ["no_docker_socket_mount"],
                "expect": {"exit_code_in": [0]},
            },
            {
                "exit_code": 0,
                "stdout": "",
                "stderr": "",
                "observed_controls": {"no_docker_socket_mount": True},
                "control_evidence_source": "runtime_observed",
                "controls_provenance": "argv_scan_only",
            },
        )
        if argv_only["status"] != "FAIL":
            raise AssertionError("argv-only provenance must FAIL")

        # P5 unavailable must FAIL
        p5_unavail = evaluate_negative_result(
            {
                "id": "P5",
                "required_controls": ["network_none"],
                "expect": {"exit_code_in": [0]},
            },
            {
                "exit_code": 0,
                "stdout": "IP_PROBE_STATUS=unavailable\nDNS_PROBE_STATUS=unavailable\n",
                "stderr": "",
                "runtime_inspected_controls": {"network_none": True},
                "control_evidence_source": "runtime_inspected_and_behavioral",
                "controls_provenance": "runtime_inspect",
                "ip_probe_status": "unavailable",
                "dns_probe_status": "unavailable",
                "network_namespace_observed": True,
            },
        )
        if p5_unavail["status"] != "FAIL":
            raise AssertionError("unavailable network probes must FAIL P5")

        # P2 hard-coded/unknown path kind must FAIL
        p2_unknown = evaluate_negative_result(
            {
                "id": "P2",
                "required_controls": ["workspace_only_mount", "read_only_root"],
                "expect": {
                    "exit_code_in": [1, 2],
                    "canary_unchanged": True,
                    "path_classification": ["absent", "present_denied"],
                    "require_probe_markers": ["CONTAINER_PATH_KIND="],
                },
            },
            {
                "exit_code": 1,
                "stdout": "oops",
                "stderr": "",
                "runtime_inspected_controls": {
                    "workspace_only_mount": True,
                    "read_only_root": True,
                },
                "control_evidence_source": "runtime_inspected_and_behavioral",
                "controls_provenance": "runtime_inspect",
                "canary_before": "a",
                "canary_after": "a",
                "canary_verified_on_host": True,
                "path_kind": "unknown",
            },
        )
        if p2_unknown["status"] != "FAIL":
            raise AssertionError("unknown path classification must FAIL")

        # P6 unattributed memory must FAIL
        p6 = evaluate_negative_result(
            {
                "id": "P6",
                "required_controls": ["memory_limit", "pids_limit"],
                "expect": {"required_limit_dimensions": ["memory", "pids", "wall_clock"]},
            },
            {
                "exit_code": 1,
                "stdout": "",
                "stderr": "",
                "runtime_inspected_controls": {
                    "memory_limit": True,
                    "pids_limit": True,
                },
                "control_evidence_source": "runtime_inspected_and_behavioral",
                "controls_provenance": "runtime_inspect",
                "limit_dimensions": {"memory": True, "pids": True, "wall_clock": True, "cpu": "NOT_TESTED"},
                "memory_attributed": False,
                "pids_attributed": True,
                "wall_clock_attributed": True,
            },
        )
        if p6["status"] != "FAIL":
            raise AssertionError("unattributed memory must FAIL P6")

        # Fixture safety
        good = Path(tempfile.mkdtemp(prefix="eos-sandbox-poc-"))
        os.chmod(good, 0o700)
        try:
            validate_fixture_root(good)
            ensure_fixture_marker(good)
            for name in EXPECTED_CHILDREN:
                (good / name).mkdir()
            validate_fixture_structure(good)
            if not safe_to_cleanup_fixture_root(good):
                raise AssertionError("marked fixture root should be safe to cleanup")
        finally:
            for child in sorted(good.rglob("*"), reverse=True):
                if child.is_file() or child.is_symlink():
                    child.unlink(missing_ok=True)
                elif child.is_dir():
                    child.rmdir()
            good.rmdir()

        try:
            validate_fixture_root(Path(tempfile.gettempdir()))
            raise AssertionError("temp parent should be rejected")
        except AssertionError as exc:
            if "dedicated subdirectory" not in str(exc):
                raise

        # P7 inspect-error cleanup assumption must FAIL
        p7 = evaluate_negative_result(
            {"id": "P7", "required_controls": ["rm_flag"], "expect": {"exit_code_in": [0]}},
            {
                "exit_code": 0,
                "stdout": "cleanup-marker",
                "stderr": "",
                "runtime_inspected_controls": {"rm_flag": True},
                "control_evidence_source": "runtime_inspected_and_behavioral",
                "controls_provenance": "runtime_inspect",
                "cleanup_observed": True,
                "cleanup_source": "inspect_error_assumed_absent",
            },
        )
        if p7["status"] != "FAIL":
            raise AssertionError("inspect-error cleanup assumption must FAIL")

    print("assertions.self_check: PASS")


if __name__ == "__main__":
    self_check()
