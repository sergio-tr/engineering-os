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
FORBIDDEN_LAUNCHER_FLAGS = (
    "--privileged",
    "--env-host",
)
# Socket path literals are forbidden in mount/volume *sources*, not in workload text.
SOCKET_PATH_MARKERS = (
    "docker.sock",
    "podman.sock",
)
# Options after `podman run` that consume a following value token.
PODMAN_RUN_VALUE_OPTS = frozenset(
    {
        "--network",
        "--user",
        "--cap-drop",
        "--security-opt",
        "--memory",
        "--cpus",
        "--pids-limit",
        "--tmpfs",
        "--mount",
        "--workdir",
        "--name",
        "--volume",
        "-v",
        "-e",
        "--env",
        "--annotation",
        "--label",
        "-l",
        "--uidmap",
        "--gidmap",
        "--userns",
        "--runtime",
        "--cgroup-manager",
        "--pull",
    }
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


def split_podman_run_argv(cmd: list[str]) -> dict[str, Any]:
    """Split ``podman run [opts...] IMAGE [workload...]`` into layers.

    Workload arguments are the fixed-catalog test script and must not be treated
    as launcher mount/security configuration.
    """
    if not cmd or cmd[0] != "podman" or "run" not in cmd[:3]:
        return {
            "ok": False,
            "error": "argv must start with podman run",
            "launcher_opts": [],
            "image": None,
            "workload": [],
        }
    # Support both ``podman run`` and ``podman --x run`` (we only emit the former).
    try:
        run_idx = cmd.index("run")
    except ValueError:
        return {
            "ok": False,
            "error": "missing run subcommand",
            "launcher_opts": [],
            "image": None,
            "workload": [],
        }
    i = run_idx + 1
    while i < len(cmd):
        arg = cmd[i]
        if arg == "--":
            i += 1
            break
        if arg.startswith("-"):
            base = arg.split("=", 1)[0]
            if "=" in arg:
                i += 1
                continue
            if base in PODMAN_RUN_VALUE_OPTS:
                i += 2
                continue
            i += 1
            continue
        # First non-option token is the image reference.
        image = arg
        launcher_opts = cmd[:i]
        workload = cmd[i + 1 :]
        return {
            "ok": True,
            "launcher_opts": launcher_opts,
            "image": image,
            "workload": workload,
            "image_index": i,
        }
    return {
        "ok": False,
        "error": "image reference not found in podman run argv",
        "launcher_opts": cmd,
        "image": None,
        "workload": [],
    }


def _mount_specs_from_launcher(launcher_opts: list[str]) -> list[str]:
    """Collect bind/volume mount specification strings from launcher options only."""
    specs: list[str] = []
    i = 0
    while i < len(launcher_opts):
        arg = launcher_opts[i]
        if arg == "--mount" and i + 1 < len(launcher_opts):
            specs.append(launcher_opts[i + 1])
            i += 2
            continue
        if arg.startswith("--mount="):
            specs.append(arg.split("=", 1)[1])
            i += 1
            continue
        if arg in {"-v", "--volume"} and i + 1 < len(launcher_opts):
            specs.append(launcher_opts[i + 1])
            i += 2
            continue
        if arg.startswith("--volume="):
            specs.append(arg.split("=", 1)[1])
            i += 1
            continue
        i += 1
    return specs


def _env_assignments_from_launcher(launcher_opts: list[str]) -> list[str]:
    values: list[str] = []
    i = 0
    while i < len(launcher_opts):
        arg = launcher_opts[i]
        if arg in {"-e", "--env"} and i + 1 < len(launcher_opts):
            values.append(launcher_opts[i + 1])
            i += 2
            continue
        if arg.startswith("--env="):
            values.append(arg.split("=", 1)[1])
            i += 1
            continue
        i += 1
    return values


def scan_argv_safety(cmd: list[str], *, workspace: Path) -> dict[str, Any]:
    """Safety-scan launcher options and mounts only (not workload text).

    This is NOT runtime enforcement proof. Socket path strings inside the fixed
    P8 negative-test workload are allowed; mounting those sockets is not.
    """
    split = split_podman_run_argv(cmd)
    if not split.get("ok"):
        return {
            "argv_passed_safety_scan": False,
            "reject_reason": split.get("error") or "invalid podman run argv",
            "launcher_argv_controls": {},
            "evidence_layer": "executed_argv",
        }

    launcher_opts: list[str] = list(split["launcher_opts"])
    workload: list[str] = list(split["workload"] or [])
    home = str(Path.home())
    ws = str(workspace.resolve())

    # Forbidden launcher flags (never acceptable in opts).
    for flag in FORBIDDEN_LAUNCHER_FLAGS:
        if flag in launcher_opts:
            return {
                "argv_passed_safety_scan": False,
                "reject_reason": f"forbidden launcher flag present: {flag}",
                "launcher_argv_controls": {},
                "evidence_layer": "executed_argv",
            }

    # Credential / agent env inheritance via launcher env options.
    for env_assign in _env_assignments_from_launcher(launcher_opts):
        key = env_assign.split("=", 1)[0]
        if key in {"SSH_AUTH_SOCK", "GITHUB_TOKEN", "GH_TOKEN", "AWS_SECRET_ACCESS_KEY"}:
            return {
                "argv_passed_safety_scan": False,
                "reject_reason": f"forbidden inherited credential env: {key}",
                "launcher_argv_controls": {},
                "evidence_layer": "executed_argv",
            }
        if "SSH_AUTH_SOCK" in env_assign:
            return {
                "argv_passed_safety_scan": False,
                "reject_reason": "forbidden SSH_AUTH_SOCK in launcher env",
                "launcher_argv_controls": {},
                "evidence_layer": "executed_argv",
            }

    mount_specs = _mount_specs_from_launcher(launcher_opts)
    # Reject socket mounts and arbitrary host binds (inspect mount sources only).
    for spec in mount_specs:
        lowered = spec.lower()
        for sock in SOCKET_PATH_MARKERS:
            if sock in lowered:
                return {
                    "argv_passed_safety_scan": False,
                    "reject_reason": f"forbidden runtime socket mount: {sock}",
                    "launcher_argv_controls": {},
                    "evidence_layer": "executed_argv",
                }
        # Classic -v /path:/path form: source is before first colon.
        if spec.startswith("type=bind,src="):
            src = spec[len("type=bind,src=") :].split(",dst=", 1)[0]
        else:
            src = spec.split(":", 1)[0]
        if home and (src == home or src.startswith(home + "/")):
            return {
                "argv_passed_safety_scan": False,
                "reject_reason": "bind mount must not reference host HOME",
                "launcher_argv_controls": {},
                "evidence_layer": "executed_argv",
            }

    bind_mounts = [s for s in mount_specs if s.startswith("type=bind,src=")]
    # Also treat bare -v specs as binds.
    volume_binds = [s for s in mount_specs if not s.startswith("type=")]
    all_binds = bind_mounts + volume_binds
    if len(all_binds) != 1:
        return {
            "argv_passed_safety_scan": False,
            "reject_reason": f"expected exactly one bind mount, found {len(all_binds)}",
            "launcher_argv_controls": {},
            "evidence_layer": "executed_argv",
        }
    only = all_binds[0]
    if only.startswith("type=bind,src="):
        if not only.startswith(f"type=bind,src={ws},dst=/workspace"):
            return {
                "argv_passed_safety_scan": False,
                "reject_reason": "bind mount must map disposable workspace to /workspace",
                "launcher_argv_controls": {},
                "evidence_layer": "executed_argv",
            }
    else:
        # -v src:dst[:opts]
        parts = only.split(":")
        if len(parts) < 2 or parts[0] != ws or parts[1] != "/workspace":
            return {
                "argv_passed_safety_scan": False,
                "reject_reason": "volume bind must map disposable workspace to /workspace",
                "launcher_argv_controls": {},
                "evidence_layer": "executed_argv",
            }

    # Workload may mention socket paths (P8). Launcher opts must not.
    launcher_joined = " ".join(launcher_opts)
    for sock in SOCKET_PATH_MARKERS:
        if sock in launcher_joined:
            return {
                "argv_passed_safety_scan": False,
                "reject_reason": f"forbidden socket marker in launcher options: {sock}",
                "launcher_argv_controls": {},
                "evidence_layer": "executed_argv",
            }

    def has(*tokens: str) -> bool:
        return all(t in launcher_opts for t in tokens)

    launcher_argv_controls = {
        "read_only_root": "--read-only" in launcher_opts,
        "network_none": has("--network", "none"),
        "cap_drop_all": has("--cap-drop", "ALL"),
        "no_new_privileges": has("--security-opt", "no-new-privileges"),
        "pull_never": "--pull=never" in launcher_opts or any(
            a.startswith("--pull=") and a.endswith("never") for a in launcher_opts
        ),
        "rm_flag": "--rm" in launcher_opts,
        "tmpfs_tmp": any(
            a == "--tmpfs" or a.startswith("--tmpfs=") or a.startswith("/tmp:")
            for a in launcher_opts
        ),
        "memory_limit": "--memory" in launcher_opts
        or any(a.startswith("--memory=") for a in launcher_opts),
        "cpu_limit": "--cpus" in launcher_opts
        or any(a.startswith("--cpus=") for a in launcher_opts),
        "pids_limit": "--pids-limit" in launcher_opts
        or any(a.startswith("--pids-limit=") for a in launcher_opts),
        "workspace_only_mount": True,
        "no_docker_socket_mount": True,
        "no_host_home_mount": True,
        "minimal_env": ("-e" in launcher_opts or "--env" in launcher_opts),
        "userns_keep_id": "--userns=keep-id" in launcher_opts
        or has("--userns", "keep-id"),
        "non_root_user": False,
        "privileged": "--privileged" in launcher_opts,
    }
    if "--user" in launcher_opts:
        idx = launcher_opts.index("--user")
        if idx + 1 < len(launcher_opts):
            user_spec = launcher_opts[idx + 1]
            launcher_argv_controls["non_root_user"] = (
                user_spec != "0:0" and not user_spec.startswith("0:")
            )

    return {
        "argv_passed_safety_scan": True,
        "launcher_argv_controls": launcher_argv_controls,
        "bind_mount_count": len(all_binds),
        "workload_len": len(workload),
        "workload_may_mention_sockets": any(
            sock in part for part in workload for sock in SOCKET_PATH_MARKERS
        ),
        "evidence_layer": "executed_argv",
        "is_runtime_enforcement_proof": False,
    }


def observe_controls_from_argv(cmd: list[str], *, workspace: Path) -> dict[str, Any]:
    """Inspect launcher configuration/mounts only; workload text is not config.

    Does not prove runtime enforcement. Socket literals in P8 workload are OK;
    socket bind mounts are rejected.
    """
    probe = scan_argv_safety(cmd, workspace=workspace)
    return {
        "argv_passed_safety_scan": probe.get("argv_passed_safety_scan"),
        "reject_reason": probe.get("reject_reason"),
        "launcher_argv_controls": probe.get("launcher_argv_controls") or {},
        "observed_controls": {},
        "bind_mount_count": probe.get("bind_mount_count"),
        "workload_may_mention_sockets": probe.get("workload_may_mention_sockets"),
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


def parse_cpu_max(text: str) -> dict[str, Any]:
    """Parse cgroup v2 ``cpu.max`` (``QUOTA PERIOD`` or ``max PERIOD``)."""
    raw = (text or "").strip()
    if not raw:
        return {"ok": False, "error": "empty_cpu_max", "unlimited": None}
    parts = raw.split()
    if len(parts) != 2:
        return {"ok": False, "error": "malformed_cpu_max", "raw": raw[:80]}
    quota_s, period_s = parts[0], parts[1]
    try:
        period = int(period_s)
    except ValueError:
        return {"ok": False, "error": "invalid_period", "raw": raw[:80]}
    if period <= 0:
        return {"ok": False, "error": "non_positive_period", "raw": raw[:80]}
    if quota_s == "max":
        return {
            "ok": True,
            "unlimited": True,
            "quota_usec": None,
            "period_usec": period,
            "cpus_equiv": None,
            "raw": raw,
        }
    try:
        quota = int(quota_s)
    except ValueError:
        return {"ok": False, "error": "invalid_quota", "raw": raw[:80]}
    if quota < 0:
        return {"ok": False, "error": "negative_quota", "raw": raw[:80]}
    return {
        "ok": True,
        "unlimited": False,
        "quota_usec": quota,
        "period_usec": period,
        "cpus_equiv": round(quota / period, 6),
        "raw": raw,
    }


def parse_cpu_stat(text: str) -> dict[str, Any]:
    """Parse cgroup v2 ``cpu.stat`` key/value lines into integers."""
    raw = text or ""
    if not raw.strip():
        return {"ok": False, "error": "empty_cpu_stat"}
    values: dict[str, int] = {}
    for line in raw.splitlines():
        parts = line.strip().split()
        if len(parts) != 2:
            continue
        key, val = parts[0], parts[1]
        try:
            values[key] = int(val)
        except ValueError:
            continue
    required = ("usage_usec", "nr_periods", "nr_throttled", "throttled_usec")
    missing = [k for k in required if k not in values]
    if missing:
        return {"ok": False, "error": "missing_cpu_stat_keys", "missing": missing, "values": values}
    return {"ok": True, "values": values}


def cpu_quota_matches_configured(
    cpu_max: dict[str, Any],
    *,
    configured_cpus: float,
    tolerance: float = 0.05,
) -> bool:
    """True when effective cpu.max ratio matches the configured ``--cpus`` value."""
    if not cpu_max.get("ok") or cpu_max.get("unlimited"):
        return False
    equiv = cpu_max.get("cpus_equiv")
    if equiv is None:
        return False
    if configured_cpus <= 0:
        return False
    return abs(float(equiv) - float(configured_cpus)) <= float(tolerance)


def cpu_stat_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Compute signed deltas for the CPU throttle/usage counters."""
    if not before.get("ok") or not after.get("ok"):
        return {"ok": False, "error": "incomplete_cpu_stat_pair"}
    b = before["values"]
    a = after["values"]
    deltas = {
        key: int(a[key]) - int(b[key])
        for key in ("usage_usec", "nr_periods", "nr_throttled", "throttled_usec")
    }
    return {"ok": True, "deltas": deltas}


def cpu_throttling_attributed(delta: dict[str, Any]) -> bool:
    """True only when throttle counters increase under load (behavioral)."""
    if not delta.get("ok"):
        return False
    deltas = delta.get("deltas") or {}
    return int(deltas.get("nr_throttled") or 0) > 0 or int(deltas.get("throttled_usec") or 0) > 0


def cpu_limit_attributed(result: dict[str, Any]) -> bool:
    """True only with container-scoped quota + observed throttling evidence."""
    if result.get("cpu_attribution") == "quota_and_throttle":
        return True
    if result.get("cpu_attributed") is True:
        return True
    return False


def parse_proc_status_capabilities(text: str) -> dict[str, Any]:
    """Parse Cap* / NoNewPrivs / Seccomp fields from ``/proc/self/status`` text."""
    raw = text or ""
    fields = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp")
    found: dict[str, str] = {}
    for line in raw.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        if key in fields:
            found[key] = value.strip()
    missing = [k for k in fields if k not in found]
    if missing:
        return {"ok": False, "error": "missing_status_fields", "missing": missing, "fields": found}
    return {"ok": True, "fields": found}


def _cap_hex_is_zero(value: str) -> bool:
    token = (value or "").strip().lower()
    if not token:
        return False
    if token.startswith("0x"):
        token = token[2:]
    try:
        return int(token, 16) == 0
    except ValueError:
        return False


def capability_drop_all_attributed(caps: dict[str, Any]) -> dict[str, Any]:
    """Evaluate ``--cap-drop=ALL`` using process capability sets (not argv)."""
    if not caps.get("ok"):
        return {
            "status": "NOT_TESTED",
            "reason": caps.get("error") or "capability_fields_unavailable",
            "attributed": False,
        }
    fields = caps.get("fields") or {}
    nonzero = [
        name
        for name in ("CapPrm", "CapEff", "CapBnd", "CapAmb")
        if not _cap_hex_is_zero(str(fields.get(name) or ""))
    ]
    no_new = str(fields.get("NoNewPrivs") or "")
    if nonzero:
        return {
            "status": "FAIL",
            "reason": f"unexpected nonzero capability sets: {nonzero}",
            "attributed": False,
            "fields": fields,
        }
    if no_new != "1":
        return {
            "status": "FAIL",
            "reason": f"NoNewPrivs expected 1, got {no_new!r}",
            "attributed": False,
            "fields": fields,
        }
    return {
        "status": "PASS",
        "reason": "CapPrm/CapEff/CapBnd/CapAmb zero with NoNewPrivs=1",
        "attributed": True,
        "fields": fields,
    }


def parse_id_map(text: str) -> dict[str, Any]:
    """Parse ``uid_map`` / ``gid_map`` lines: ``container_id host_id length``."""
    raw = text or ""
    rows: list[dict[str, int]] = []
    for line in raw.splitlines():
        parts = line.strip().split()
        if len(parts) != 3:
            continue
        try:
            rows.append(
                {
                    "container_id": int(parts[0]),
                    "host_id": int(parts[1]),
                    "length": int(parts[2]),
                }
            )
        except ValueError:
            return {"ok": False, "error": "malformed_id_map_line", "raw": line[:80]}
    if not rows:
        return {"ok": False, "error": "empty_id_map"}
    return {"ok": True, "rows": rows}


def id_maps_cover_identity(
    uid_map: dict[str, Any],
    gid_map: dict[str, Any],
    *,
    container_uid: int,
    container_gid: int,
    host_uid: int,
    host_gid: int,
) -> dict[str, Any]:
    """Check that maps translate the effective container IDs to the host identity."""

    def covers(mapping: dict[str, Any], container_id: int, host_id: int) -> bool:
        if not mapping.get("ok"):
            return False
        for row in mapping.get("rows") or []:
            start = int(row["container_id"])
            length = int(row["length"])
            host_start = int(row["host_id"])
            if start <= container_id < start + length:
                return host_start + (container_id - start) == host_id
        return False

    if not uid_map.get("ok") or not gid_map.get("ok"):
        return {
            "status": "NOT_TESTED",
            "reason": "uid_map_or_gid_map_unavailable",
            "attributed": False,
        }
    uid_ok = covers(uid_map, container_uid, host_uid)
    gid_ok = covers(gid_map, container_gid, host_gid)
    if not uid_ok or not gid_ok:
        return {
            "status": "FAIL",
            "reason": "id_map_does_not_match_host_identity",
            "attributed": False,
            "uid_ok": uid_ok,
            "gid_ok": gid_ok,
        }
    return {
        "status": "PASS",
        "reason": "uid_map_and_gid_map_cover_host_identity",
        "attributed": True,
        "uid_ok": True,
        "gid_ok": True,
    }


def userns_keep_id_attributed(evidence: dict[str, Any]) -> dict[str, Any]:
    """Evaluate keep-id consistency from runtime observations (not inspect booleans)."""
    required = (
        "container_uid",
        "container_gid",
        "host_uid",
        "host_gid",
        "uid_map",
        "gid_map",
        "workspace_owner_uid",
        "marker_owner_uid",
    )
    missing = [k for k in required if evidence.get(k) is None]
    if missing:
        return {
            "status": "NOT_TESTED",
            "reason": f"missing_userns_fields:{missing}",
            "attributed": False,
        }
    try:
        container_uid = int(evidence["container_uid"])
        container_gid = int(evidence["container_gid"])
        host_uid = int(evidence["host_uid"])
        host_gid = int(evidence["host_gid"])
        workspace_owner = int(evidence["workspace_owner_uid"])
        marker_owner = int(evidence["marker_owner_uid"])
    except (TypeError, ValueError):
        return {
            "status": "NOT_TESTED",
            "reason": "non_integer_identity_fields",
            "attributed": False,
        }

    # keep-id policy: process identity equals host identity inside the container.
    if container_uid != host_uid or container_gid != host_gid:
        return {
            "status": "FAIL",
            "reason": "container_euid_egid_do_not_match_host_identity",
            "attributed": False,
        }
    if workspace_owner != host_uid or marker_owner != host_uid:
        return {
            "status": "FAIL",
            "reason": "workspace_or_marker_owner_mismatch",
            "attributed": False,
        }

    map_verdict = id_maps_cover_identity(
        evidence.get("uid_map") or {},
        evidence.get("gid_map") or {},
        container_uid=container_uid,
        container_gid=container_gid,
        host_uid=host_uid,
        host_gid=host_gid,
    )
    if map_verdict.get("status") != "PASS":
        return map_verdict
    return {
        "status": "PASS",
        "reason": "keep_id_identity_and_maps_consistent",
        "attributed": True,
        "map_verdict": map_verdict,
    }


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
        if "cpu" in required_dims:
            if dimensions.get("cpu") is not True:
                return {
                    "id": test_id,
                    "status": "FAIL",
                    "reason": "cpu dimension lacks attributable quota+throttle evidence",
                }
            if not cpu_limit_attributed(result) and not result.get("cpu_attributed"):
                return {
                    "id": test_id,
                    "status": "FAIL",
                    "reason": "cpu dimension lacks attributable quota+throttle evidence",
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

        # P8 workload may mention socket paths; mounts must still be rejected.
        p8_cmd = list(safe_cmd[:-1]) + [
            "/bin/sh",
            "-c",
            "for p in /var/run/docker.sock /run/podman/podman.sock; do "
            "if [ -S \"$p\" ]; then exit 10; fi; done; exit 0",
        ]
        p8_probe = scan_argv_safety(p8_cmd, workspace=ws)
        if not p8_probe.get("argv_passed_safety_scan"):
            raise AssertionError(f"P8 workload socket literals incorrectly rejected: {p8_probe}")
        if not p8_probe.get("workload_may_mention_sockets"):
            raise AssertionError("P8 probe should note workload socket literals")

        docker_sock_mount = list(safe_cmd)
        mi = docker_sock_mount.index("--mount")
        docker_sock_mount[mi + 1] = (
            f"type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock,rw"
        )
        bad_docker = scan_argv_safety(docker_sock_mount, workspace=ws)
        if bad_docker.get("argv_passed_safety_scan"):
            raise AssertionError("docker.sock bind mount must be rejected")

        podman_sock_mount = list(safe_cmd)
        mi = podman_sock_mount.index("--mount")
        podman_sock_mount[mi + 1] = (
            "type=bind,src=/run/podman/podman.sock,dst=/run/podman/podman.sock,rw"
        )
        bad_podman = scan_argv_safety(podman_sock_mount, workspace=ws)
        if bad_podman.get("argv_passed_safety_scan"):
            raise AssertionError("podman.sock bind mount must be rejected")

        # Place --privileged in launcher opts (before image), not after workload.
        priv = list(safe_cmd)
        priv.insert(priv.index("alpine:3.20"), "--privileged")
        bad_priv = scan_argv_safety(priv, workspace=ws)
        if bad_priv.get("argv_passed_safety_scan"):
            raise AssertionError("privileged mode must be rejected")

        arbitrary = list(safe_cmd)
        mi = arbitrary.index("--mount")
        arbitrary[mi + 1] = f"type=bind,src={root.resolve()},dst=/workspace,rw"
        bad_arb = scan_argv_safety(arbitrary, workspace=ws)
        if bad_arb.get("argv_passed_safety_scan"):
            raise AssertionError("arbitrary host bind mount must be rejected")

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

        # --- B2: CPU / capability / userns unit checks (mocked; no containers) ---
        cpu_max_ok = parse_cpu_max("50000 100000")
        assert cpu_max_ok["ok"] is True
        assert cpu_max_ok["unlimited"] is False
        assert abs(cpu_max_ok["cpus_equiv"] - 0.5) < 1e-9
        assert cpu_quota_matches_configured(cpu_max_ok, configured_cpus=0.50)
        assert not cpu_quota_matches_configured(cpu_max_ok, configured_cpus=1.0)

        cpu_max_unlimited = parse_cpu_max("max 100000")
        assert cpu_max_unlimited["ok"] is True and cpu_max_unlimited["unlimited"] is True
        assert not cpu_quota_matches_configured(cpu_max_unlimited, configured_cpus=0.50)
        assert parse_cpu_max("")["ok"] is False
        assert parse_cpu_max("not-a-quota")["ok"] is False

        stat_before = parse_cpu_stat(
            "usage_usec 1000\nnr_periods 10\nnr_throttled 1\nthrottled_usec 100\n"
        )
        stat_after = parse_cpu_stat(
            "usage_usec 5000\nnr_periods 40\nnr_throttled 5\nthrottled_usec 900\n"
        )
        assert stat_before["ok"] and stat_after["ok"]
        delta_pos = cpu_stat_delta(stat_before, stat_after)
        assert delta_pos["ok"] and cpu_throttling_attributed(delta_pos)
        assert delta_pos["deltas"]["usage_usec"] == 4000

        stat_flat = parse_cpu_stat(
            "usage_usec 2000\nnr_periods 20\nnr_throttled 1\nthrottled_usec 100\n"
        )
        delta_neg = cpu_stat_delta(stat_before, stat_flat)
        assert delta_neg["ok"] and not cpu_throttling_attributed(delta_neg)
        assert parse_cpu_stat("usage_usec 1\n")["ok"] is False
        assert cpu_stat_delta({"ok": False}, stat_after)["ok"] is False

        # Planned cpu_limit flag alone must not attribute enforcement.
        assert not cpu_limit_attributed({"planned_controls": {"cpu_limit": True}})
        assert cpu_limit_attributed({"cpu_attribution": "quota_and_throttle"})

        p6_cpu_missing = evaluate_negative_result(
            {
                "id": "P6",
                "required_controls": ["memory_limit", "pids_limit", "cpu_limit"],
                "expect": {
                    "required_limit_dimensions": ["memory", "pids", "wall_clock", "cpu"]
                },
            },
            {
                "exit_code": 124,
                "stdout": "",
                "stderr": "",
                "runtime_inspected_controls": {
                    "memory_limit": True,
                    "pids_limit": True,
                    "cpu_limit": True,
                },
                "control_evidence_source": "runtime_inspected_and_behavioral",
                "controls_provenance": "runtime_inspect",
                "limit_dimensions": {
                    "memory": True,
                    "pids": True,
                    "wall_clock": True,
                    "cpu": "NOT_TESTED",
                },
                "memory_attributed": True,
                "pids_attributed": True,
                "wall_clock_attributed": True,
                "cpu_attributed": False,
            },
        )
        if p6_cpu_missing["status"] != "FAIL":
            raise AssertionError("P6 with cpu NOT_TESTED must FAIL when cpu is required")

        caps_zero = parse_proc_status_capabilities(
            "CapInh:\t0000000000000000\n"
            "CapPrm:\t0000000000000000\n"
            "CapEff:\t0000000000000000\n"
            "CapBnd:\t0000000000000000\n"
            "CapAmb:\t0000000000000000\n"
            "NoNewPrivs:\t1\n"
            "Seccomp:\t2\n"
        )
        assert caps_zero["ok"] is True
        cap_pass = capability_drop_all_attributed(caps_zero)
        assert cap_pass["status"] == "PASS" and cap_pass["attributed"] is True

        caps_nonzero = parse_proc_status_capabilities(
            "CapInh:\t0000000000000000\n"
            "CapPrm:\t00000000a80425fb\n"
            "CapEff:\t00000000a80425fb\n"
            "CapBnd:\t00000000a80425fb\n"
            "CapAmb:\t0000000000000000\n"
            "NoNewPrivs:\t1\n"
            "Seccomp:\t2\n"
        )
        cap_fail = capability_drop_all_attributed(caps_nonzero)
        assert cap_fail["status"] == "FAIL"

        caps_missing = parse_proc_status_capabilities("NoNewPrivs:\t1\n")
        assert caps_missing["ok"] is False
        assert capability_drop_all_attributed(caps_missing)["status"] == "NOT_TESTED"

        uid_map = parse_id_map("0 100000 1000\n1000 1000 1\n1001 101001 64535\n")
        gid_map = parse_id_map("0 100000 1000\n1001 1001 1\n1002 101002 64534\n")
        assert uid_map["ok"] and gid_map["ok"]
        userns_ok = userns_keep_id_attributed(
            {
                "container_uid": 1000,
                "container_gid": 1001,
                "host_uid": 1000,
                "host_gid": 1001,
                "uid_map": uid_map,
                "gid_map": gid_map,
                "workspace_owner_uid": 1000,
                "marker_owner_uid": 1000,
            }
        )
        assert userns_ok["status"] == "PASS"

        userns_bad_uid = userns_keep_id_attributed(
            {
                "container_uid": 0,
                "container_gid": 1001,
                "host_uid": 1000,
                "host_gid": 1001,
                "uid_map": uid_map,
                "gid_map": gid_map,
                "workspace_owner_uid": 1000,
                "marker_owner_uid": 1000,
            }
        )
        assert userns_bad_uid["status"] == "FAIL"

        userns_missing = userns_keep_id_attributed({"container_uid": 1000})
        assert userns_missing["status"] == "NOT_TESTED"

        assert parse_id_map("")["ok"] is False
        assert id_maps_cover_identity(
            {"ok": False},
            gid_map,
            container_uid=1000,
            container_gid=1001,
            host_uid=1000,
            host_gid=1001,
        )["status"] == "NOT_TESTED"

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
