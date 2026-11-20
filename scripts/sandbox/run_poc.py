#!/usr/bin/env python3
"""Fail-closed synthetic isolation PoC launcher for Engineering OS.

Phase B2: runtime security evidence closure (CPU, capabilities, userns).

Evidence layers (never conflated):
  1. launcher_config / planned_controls
  2. executed_argv (safety scan only; not enforcement proof)
  3. runtime_inspected_controls (read-only podman inspect)
  4. behavioral_evidence (probes, canaries, attributable limit signals)

Agent validation of this increment must not pass the Owner execution gate.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

SANDBOX_DIR = Path(__file__).resolve().parent
if str(SANDBOX_DIR) not in sys.path:
    sys.path.insert(0, str(SANDBOX_DIR))

from assertions import (  # noqa: E402
    capability_drop_all_attributed,
    cpu_quota_matches_configured,
    cpu_stat_delta,
    cpu_throttling_attributed,
    ensure_fixture_marker,
    evaluate_negative_result,
    memory_limit_attributed,
    parse_container_path_kind,
    parse_cpu_max,
    parse_cpu_stat,
    parse_id_map,
    parse_podman_inspect,
    parse_probe_status,
    parse_proc_status_capabilities,
    parse_test_ids,
    pids_limit_attributed,
    safe_to_cleanup_fixture_root,
    sanitize_evidence_text,
    scan_argv_safety,
    sha256_file,
    userns_keep_id_attributed,
    validate_fixture_root,
    validate_fixture_structure,
    wall_clock_attributed,
    write_canary,
)
from preflight import assess, is_local_base_image_ref  # noqa: E402

SYNTH_ALPHA = "synth-alpha"
SYNTH_BETA = "synth-beta"
SECRET_NAME = "host-secret-canary.txt"
OUTSIDE_NAME = "outside-canary.txt"
ALLOWED_TEST_IDS = tuple(f"P{i}" for i in range(1, 9))
CONTAINER_NAME_PREFIX = "eos-sandbox-poc-"

UID_POLICY = {
    "status": "podman_keep_id_mapped_host_uid",
    "runtime": "podman",
    "userns": "keep-id",
    "user_spec": "host_uid:host_gid",
    "fixed_user_65532": "forbidden",
    "notes": [
        "Workspace must be owned by the launching host UID before execute.",
        "keep-id + matching --user <host_uid>:<host_gid> is the PoC policy.",
        "Incompatible fixed-user assumptions (65532) are not used.",
    ],
}


def _die(message: str, code: int = 2) -> None:
    print(f"FAIL_CLOSED: {message}", file=sys.stderr)
    raise SystemExit(code)


def _host_uid_gid() -> tuple[int, int]:
    return os.getuid(), os.getgid()


def resolve_uid_policy(*, runtime: str) -> dict[str, Any]:
    if runtime != "podman":
        _die("Phase B1 execute path supports rootless Podman only")
    uid, gid = _host_uid_gid()
    if uid == 0:
        _die("refusing to run PoC as host root")
    policy = dict(UID_POLICY)
    policy["host_uid"] = uid
    policy["host_gid"] = gid
    policy["user_flag"] = f"{uid}:{gid}"
    return policy


def _select_image_for_runtime(report: dict, runtime: str) -> str | None:
    store = (report.get("images") or {}).get(runtime) or {}
    if not store.get("ready_for_execution"):
        return None
    selected = store.get("selected_image")
    if not selected:
        return None
    if not (
        is_local_base_image_ref(selected, "alpine")
        or is_local_base_image_ref(selected, "busybox")
    ):
        return None
    return selected


def _runtime_choice(report: dict) -> tuple[str | None, str]:
    suitability = report["suitability"]
    if suitability["runtime_execution_blocked"]:
        return None, suitability["block_reason"]
    selected = suitability["selected_runtime"]
    if selected and selected.startswith("podman"):
        return "podman", "podman_rootless_selected"
    if selected and selected.startswith("docker"):
        return None, "docker_rootless_not_authorized_for_phase_b1"
    return None, suitability["block_reason"]


def verify_workspace_ownership(workspace: Path, policy: dict[str, Any]) -> None:
    workspace = workspace.resolve()
    if not workspace.is_dir():
        _die(f"workspace missing: {workspace.name}")
    st = workspace.stat()
    if st.st_uid != policy["host_uid"]:
        _die(
            f"workspace UID {st.st_uid} != host UID {policy['host_uid']}; "
            "refusing execute under keep-id policy"
        )


def build_command(
    runtime: str,
    *,
    image: str,
    workspace: Path,
    workdir_in_container: str = "/workspace",
    network: str = "none",
    memory: str = "256m",
    cpus: str = "0.50",
    pids: int = 64,
    tmpfs_size: str = "64m",
    inner_command: list[str],
    name: str | None = None,
    rm: bool = False,
) -> tuple[list[str], dict[str, bool]]:
    """Construct a fail-closed OCI invocation. Does not execute it.

    Default rm=False so the future execute path can inspect the container.
    """
    if runtime != "podman":
        _die("build_command Phase B1 supports podman only")
    if network != "none":
        _die("network must be none for PoC (default deny)")
    if not image or image.startswith("<"):
        _die("refusing to build command without an exact local image reference")
    if not (
        is_local_base_image_ref(image, "alpine")
        or is_local_base_image_ref(image, "busybox")
    ):
        _die(f"image ref not an allowed local alpine/busybox exact ref: {image!r}")
    if not re.fullmatch(r"[0-9]+[kKmMgG]?", tmpfs_size):
        _die(f"invalid tmpfs size: {tmpfs_size!r}")

    policy = resolve_uid_policy(runtime=runtime)
    verify_workspace_ownership(workspace, policy)
    ws = str(workspace.resolve())

    planned_controls = {
        "read_only_root": True,
        "network_none": True,
        "non_root_user": policy["host_uid"] != 0,
        "cap_drop_all": True,
        "no_new_privileges": True,
        "memory_limit": True,
        "cpu_limit": True,
        "pids_limit": True,
        "tmpfs_tmp": True,
        "workspace_only_mount": True,
        "pull_never": True,
        "rm_flag": bool(rm),
        "no_docker_socket_mount": True,
        "no_host_home_mount": True,
        "minimal_env": True,
        "userns_keep_id": True,
    }

    # Launcher options only (image + workload appended after validation).
    launcher: list[str] = [
        "podman",
        "run",
        "--pull=never",
        "--read-only",
        "--network",
        "none",
        "--userns=keep-id",
        "--user",
        policy["user_flag"],
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--memory",
        memory,
        "--cpus",
        cpus,
        "--pids-limit",
        str(pids),
        "--tmpfs",
        f"/tmp:rw,noexec,nosuid,size={tmpfs_size}",
        "--mount",
        f"type=bind,src={ws},dst={workdir_in_container},rw",
        "--workdir",
        workdir_in_container,
    ]
    if rm:
        launcher.append("--rm")
    if name:
        if not re.fullmatch(r"eos-sandbox-poc-[A-Za-z0-9._-]{4,80}", name):
            _die(f"refusing non-PoC container name: {name!r}")
        launcher.extend(["--name", name])

    launcher.extend(
        [
            "-e",
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "-e",
            "HOME=/tmp",
            "-e",
            "LANG=C.UTF-8",
        ]
    )

    # Fail closed on launcher/mount configuration before attaching workload.
    # Socket path literals inside fixed-catalog workload scripts (P8) are allowed.
    cmd = launcher + [image, *inner_command]
    argv_probe = scan_argv_safety(cmd, workspace=workspace)
    if not argv_probe.get("argv_passed_safety_scan"):
        _die(f"command failed argv safety scan: {argv_probe.get('reject_reason')}")

    return cmd, planned_controls


def prepare_fixtures(root: Path) -> dict[str, str]:
    root = validate_fixture_root(root)
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    root = validate_fixture_root(root, must_exist=True)
    ensure_fixture_marker(root)

    alpha = root / SYNTH_ALPHA
    beta = root / SYNTH_BETA
    outside = root / "outside-host"
    secrets = root / "synthetic-secrets"
    for path in (alpha, beta, outside, secrets):
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, 0o700)

    digests = {
        "outside": write_canary(outside / OUTSIDE_NAME, b"EOS-SYNTH-OUTSIDE-CANARY-v1\n"),
        "secret": write_canary(secrets / SECRET_NAME, b"EOS-SYNTH-SECRET-CANARY-v1\n"),
        "beta": write_canary(beta / "marker.txt", b"EOS-SYNTH-BETA-MARKER-v1\n"),
    }
    (alpha / "README.txt").write_text("synthetic alpha workspace\n", encoding="utf-8")
    validate_fixture_structure(root)
    return digests


def cleanup_fixture_tree(root: Path) -> bool:
    if not safe_to_cleanup_fixture_root(root):
        return False
    for child in sorted(root.rglob("*"), reverse=True):
        if child.is_symlink() or child.is_file():
            child.unlink(missing_ok=True)
        elif child.is_dir():
            child.rmdir()
    root.rmdir()
    return True


def _inner_p2() -> str:
    return (
        "echo PROBE_MARKER=P2; "
        "target_dir=/outside; target=/outside/outside-canary.txt; "
        "if [ -e \"$target_dir\" ] || [ -L \"$target_dir\" ]; then "
        "  if [ -r \"$target_dir\" ]; then echo CONTAINER_PATH_KIND=present_readable; "
        "  else echo CONTAINER_PATH_KIND=present_denied; fi; "
        "else echo CONTAINER_PATH_KIND=absent; fi; "
        "if echo leak > \"$target\" 2>/tmp/p2.err; then "
        "  echo WRITE_SUCCEEDED=1; exit 10; "
        "fi; "
        "echo WRITE_SUCCEEDED=0; exit 1"
    )


def _inner_p3() -> str:
    return (
        "echo PROBE_MARKER=P3; "
        "target=/beta/marker.txt; "
        "if [ -e \"$target\" ] || [ -L \"$target\" ]; then "
        "  if [ -r \"$target\" ]; then echo CONTAINER_PATH_KIND=present_readable; "
        "  else echo CONTAINER_PATH_KIND=present_denied; fi; "
        "else echo CONTAINER_PATH_KIND=absent; fi; "
        "if content=$(cat \"$target\" 2>/tmp/p3.err); then "
        "  echo READ_SUCCEEDED=1; echo \"$content\"; exit 10; "
        "fi; "
        "echo READ_SUCCEEDED=0; exit 1"
    )


def _inner_p4() -> str:
    return (
        "echo PROBE_MARKER=P4; "
        "target=/secrets/host-secret-canary.txt; "
        "if [ -e \"$target\" ] || [ -L \"$target\" ]; then "
        "  if [ -r \"$target\" ]; then echo CONTAINER_PATH_KIND=present_readable; "
        "  else echo CONTAINER_PATH_KIND=present_denied; fi; "
        "else echo CONTAINER_PATH_KIND=absent; fi; "
        "if content=$(cat \"$target\" 2>/tmp/p4.err); then "
        "  echo READ_SUCCEEDED=1; echo \"$content\"; exit 10; "
        "fi; "
        "echo READ_SUCCEEDED=0; exit 1"
    )


def _inner_p5() -> str:
    return (
        "echo PROBE_MARKER=P5; "
        "echo NETNS_IFACES=$(ls /sys/class/net 2>/dev/null | tr '\\n' ',' ); "
        "ip_status=unavailable; "
        "if command -v wget >/dev/null 2>&1; then "
        "  if wget -q -T 2 -O - http://1.1.1.1/ >/dev/null 2>&1; "
        "  then ip_status=executed_succeeded; else ip_status=executed_denied; fi; "
        "elif command -v busybox >/dev/null 2>&1; then "
        "  if busybox wget -q -T 2 -O - http://1.1.1.1/ >/dev/null 2>&1; "
        "  then ip_status=executed_succeeded; else ip_status=executed_denied; fi; "
        "fi; "
        "echo IP_PROBE_STATUS=$ip_status; "
        "dns_status=unavailable; "
        "if command -v nslookup >/dev/null 2>&1; then "
        "  if nslookup example.com >/dev/null 2>&1; "
        "  then dns_status=executed_succeeded; else dns_status=executed_denied; fi; "
        "elif command -v getent >/dev/null 2>&1; then "
        "  if getent hosts example.com >/dev/null 2>&1; "
        "  then dns_status=executed_succeeded; else dns_status=executed_denied; fi; "
        "elif command -v busybox >/dev/null 2>&1; then "
        "  if busybox nslookup example.com >/dev/null 2>&1; "
        "  then dns_status=executed_succeeded; else dns_status=executed_denied; fi; "
        "fi; "
        "echo DNS_PROBE_STATUS=$dns_status; "
        "if [ \"$ip_status\" = \"executed_succeeded\" ] || "
        "[ \"$dns_status\" = \"executed_succeeded\" ]; then exit 10; fi; "
        "if [ \"$ip_status\" != \"executed_denied\" ] || "
        "[ \"$dns_status\" != \"executed_denied\" ]; then exit 20; fi; "
        "exit 0"
    )


def _inner_p6_pids() -> str:
    return (
        "echo PROBE_MARKER=P6_PIDS; "
        "FORK_DENIED=0; i=0; "
        "while [ \"$i\" -lt 64 ]; do "
        "  if ! /bin/sh -c 'sleep 2' >/dev/null 2>&1 & then "
        "    FORK_DENIED=1; break; "
        "  fi; "
        "  i=$((i+1)); "
        "done; "
        "echo FORK_DENIED=$FORK_DENIED; "
        "echo FORK_ATTEMPTS=$i; "
        "wait; "
        "if [ \"$FORK_DENIED\" -eq 1 ]; then exit 1; fi; "
        "exit 0"
    )


def _inner_p6_cpu() -> str:
    """Bounded CPU-saturating workload (no extra packages)."""
    return (
        "echo PROBE_MARKER=P6_CPU; "
        "echo CPU_WORK_START=1; "
        "i=0; while [ \"$i\" -lt 4 ]; do "
        "  (while true; do :; done) & "
        "  i=$((i+1)); "
        "done; "
        "sleep 8; "
        "echo CPU_WORK_END=1; "
        "kill $(jobs -p) 2>/dev/null; "
        "wait 2>/dev/null; "
        "exit 0"
    )


def _inner_security_identity() -> str:
    """Write ownership marker, emit euid/egid, then hold for host-side sampling.

    In-container uid_map/gid_map text is emitted only as diagnostic context; B3
    attribution uses host-side ``/proc/<pid>/*_map`` reads instead.
    """
    return (
        "echo PROBE_MARKER=SECURITY_IDENTITY; "
        "echo CONTAINER_UID=$(id -u); "
        "echo CONTAINER_GID=$(id -g); "
        "echo marker > /workspace/security-identity-marker.txt; "
        "test -s /workspace/security-identity-marker.txt; "
        "echo MARKER_WRITTEN=1; "
        "echo READY_FOR_HOST_SAMPLE=1; "
        # Bounded hold so the launcher can read host-side procfs maps.
        "sleep 12; "
        "echo HOLD_COMPLETE=1; "
        "exit 0"
    )


def plan_tests(
    root: Path,
    runtime: str,
    image: str,
    test_ids: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Build fixed-catalog entries.

    When *test_ids* is provided, only those allow-listed ids are constructed.
    Requesting ``P1`` must not fail due to unrelated ``P8`` workload strings.
    """
    if runtime != "podman":
        runtime = "podman"
    selected = set(test_ids) if test_ids is not None else set(ALLOWED_TEST_IDS)
    unknown = sorted(selected - set(ALLOWED_TEST_IDS))
    if unknown:
        _die(f"unsupported test ids in plan_tests: {unknown}")
    alpha = root / SYNTH_ALPHA
    outside = root / "outside-host"
    secrets = root / "synthetic-secrets"
    beta = root / SYNTH_BETA
    policy = resolve_uid_policy(runtime="podman")

    def entry(
        test_id: str,
        title: str,
        inner: list[str],
        *,
        assertion: dict[str, Any],
        memory: str = "256m",
        cpus: str = "0.50",
        pids: int = 64,
        host_timeout_seconds: int = 30,
        canary: str | None = None,
        rm: bool = False,
    ) -> dict[str, Any]:
        if image.startswith("<"):
            cmd = [
                "podman",
                "run",
                "--pull=never",
                "--read-only",
                "--network",
                "none",
                "--userns=keep-id",
                "--user",
                policy["user_flag"],
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--memory",
                memory,
                "--cpus",
                cpus,
                "--pids-limit",
                str(pids),
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=64m",
                "--mount",
                f"type=bind,src={alpha.resolve()},dst=/workspace,rw",
                "--workdir",
                "/workspace",
                image,
                *inner,
            ]
            controls = {
                "read_only_root": True,
                "network_none": True,
                "non_root_user": True,
                "cap_drop_all": True,
                "no_new_privileges": True,
                "memory_limit": True,
                "cpu_limit": True,
                "pids_limit": True,
                "tmpfs_tmp": True,
                "workspace_only_mount": True,
                "pull_never": True,
                "rm_flag": bool(rm),
                "no_docker_socket_mount": True,
                "no_host_home_mount": True,
                "minimal_env": True,
                "userns_keep_id": True,
            }
        else:
            cmd, controls = build_command(
                runtime,
                image=image,
                workspace=alpha,
                memory=memory,
                cpus=cpus,
                pids=pids,
                inner_command=inner,
                rm=rm,
            )
        item: dict[str, Any] = {
            "id": test_id,
            "title": title,
            "command": cmd,
            "required_controls": sorted(
                k for k, v in controls.items() if v and k in (assertion.get("required_controls") or controls)
            ),
            "planned_controls": controls,
            "assertion": assertion,
            "status": "NOT_TESTED",
            "host_timeout_seconds": host_timeout_seconds,
            "inner_command": inner,
            "memory": memory,
            "cpus": cpus,
            "pids": pids,
            "rm": rm,
        }
        # Prefer assertion-declared required_controls.
        if assertion.get("required_controls"):
            item["required_controls"] = list(assertion["required_controls"])
        if canary:
            item["canary"] = canary
        return item

    catalog = [
        ("P1", lambda: entry(
            "P1",
            "Allowed write inside authorized workspace",
            ["/bin/sh", "-c", "echo ok > /workspace/p1.txt; test -s /workspace/p1.txt"],
            assertion={
                "id": "P1",
                "required_controls": [
                    "workspace_only_mount",
                    "read_only_root",
                    "non_root_user",
                ],
                "expect": {
                    "exit_code_in": [0],
                    "stdout_forbids_regex": r"DENIED_AS_EXPECTED",
                    "host_workspace_write_verified": True,
                },
                "notes": [
                    "PASS requires exit 0, host-visible workspace file, and runtime inspect.",
                    "userns keep-id is planned; reported separately if inspect cannot prove it.",
                ],
            },
        )),
        ("P2", lambda: entry(
            "P2",
            "Denied write outside authorized workspace",
            ["/bin/sh", "-c", _inner_p2()],
            assertion={
                "id": "P2",
                "required_controls": ["workspace_only_mount", "read_only_root"],
                "expect": {
                    "exit_code_in": [1, 2],
                    "canary_unchanged": True,
                    "path_classification": ["absent", "present_denied"],
                    "require_probe_markers": ["PROBE_MARKER=P2", "CONTAINER_PATH_KIND="],
                },
            },
            canary=str(outside / OUTSIDE_NAME),
        )),
        ("P3", lambda: entry(
            "P3",
            "Denied read of second synthetic project",
            ["/bin/sh", "-c", _inner_p3()],
            assertion={
                "id": "P3",
                "required_controls": ["workspace_only_mount"],
                "expect": {
                    "exit_code_in": [1, 2],
                    "canary_unchanged": True,
                    "stdout_forbids_regex": r"EOS-SYNTH-BETA-MARKER",
                    "path_classification": ["absent", "present_denied"],
                    "require_probe_markers": ["PROBE_MARKER=P3", "CONTAINER_PATH_KIND="],
                },
            },
            canary=str(beta / "marker.txt"),
        )),
        ("P4", lambda: entry(
            "P4",
            "Denied access to synthetic host-secret canary",
            ["/bin/sh", "-c", _inner_p4()],
            assertion={
                "id": "P4",
                "required_controls": ["workspace_only_mount", "no_host_home_mount"],
                "expect": {
                    "exit_code_in": [1, 2],
                    "canary_unchanged": True,
                    "stdout_forbids_regex": r"EOS-SYNTH-SECRET-CANARY",
                    "path_classification": ["absent", "present_denied"],
                    "require_probe_markers": ["PROBE_MARKER=P4", "CONTAINER_PATH_KIND="],
                },
            },
            canary=str(secrets / SECRET_NAME),
        )),
        ("P5", lambda: entry(
            "P5",
            "Default-deny network egress",
            ["/bin/sh", "-c", _inner_p5()],
            assertion={
                "id": "P5",
                "required_controls": ["network_none"],
                "expect": {
                    "exit_code_in": [0],
                    "stdout_regex": r"(?m)^IP_PROBE_STATUS=executed_denied$",
                    "require_probe_markers": [
                        "PROBE_MARKER=P5",
                        "IP_PROBE_STATUS=",
                        "DNS_PROBE_STATUS=",
                        "NETNS_IFACES=",
                    ],
                },
                "notes": [
                    "PASS requires IP and DNS executed_denied, netns observation,",
                    "and runtime NetworkMode=none. unavailable probes FAIL.",
                ],
            },
        )),
        ("P6", lambda: entry(
            "P6",
            "Resource and wall-clock limits",
            ["/bin/sh", "-c", "dd if=/dev/zero of=/tmp/big bs=1M count=200"],
            assertion={
                "id": "P6",
                "required_controls": ["memory_limit", "pids_limit", "cpu_limit"],
                "expect": {
                    "exit_code_in": [0, 1, 137, 139, 143, 124],
                    "required_limit_dimensions": ["memory", "pids", "wall_clock", "cpu"],
                },
                "notes": [
                    "CPU PASS requires container-scoped cpu.max matching --cpus=0.50",
                    "and attributable nr_throttled/throttled_usec growth under load.",
                    "Missing/deleted cgroup yields NOT_TESTED (never PASS).",
                    "Arbitrary nonzero exits are not memory/PID proof.",
                ],
            },
            memory="32m",
            cpus="0.50",
            pids=32,
            host_timeout_seconds=45,
        )),
        ("P7", lambda: entry(
            "P7",
            "Clean shutdown and cleanup",
            ["/bin/sh", "-c", "echo cleanup-marker"],
            assertion={
                "id": "P7",
                "required_controls": ["workspace_only_mount", "read_only_root"],
                "expect": {"exit_code_in": [0]},
                "notes": [
                    "PASS requires reliable presence checks after success (--rm) and abnormal stop.",
                    "Inspect errors must not be treated as absence.",
                ],
            },
        )),
        ("P8", lambda: entry(
            "P8",
            "Denied host container-runtime sockets",
            [
                "/bin/sh",
                "-c",
                "echo PROBE_MARKER=P8; "
                "for p in /var/run/docker.sock /run/podman/podman.sock "
                "/var/run/podman/podman.sock; do "
                "if [ -S \"$p\" ]; then echo SOCKET_VISIBLE=1; exit 10; fi; done; "
                "echo SOCKET_VISIBLE=0; exit 0",
            ],
            assertion={
                "id": "P8",
                "required_controls": ["no_docker_socket_mount"],
                "expect": {
                    "exit_code_in": [0],
                    "require_probe_markers": ["PROBE_MARKER=P8", "SOCKET_VISIBLE=0"],
                },
            },
        )),
    ]
    # Construct only selected allow-listed entries (P1 request must not build P8).
    return [builder() for tid, builder in catalog if tid in selected]


def sanitize_command(cmd: list[str], workspace: Path) -> list[str]:
    token = "<DISPOSABLE_WORKSPACE>"
    ws = str(workspace.resolve())
    home = str(Path.home())
    out: list[str] = []
    for part in cmd:
        text = part.replace(ws, token)
        if home and home in text:
            text = text.replace(home, "<HOME>")
        out.append(text)
    return out


def _host_podman_env() -> dict[str, str]:
    allow = (
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "LANG",
        "LC_ALL",
        "XDG_RUNTIME_DIR",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "DBUS_SESSION_BUS_ADDRESS",
    )
    env: dict[str, str] = {key: os.environ[key] for key in allow if key in os.environ}
    env.setdefault("PATH", "/usr/bin:/bin")
    env.setdefault("LANG", "C.UTF-8")
    for banned in (
        "SSH_AUTH_SOCK",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_ACCESS_KEY_ID",
        "GOOGLE_APPLICATION_CREDENTIALS",
    ):
        env.pop(banned, None)
    return env


def _run_subprocess(cmd: list[str], *, timeout: float) -> dict[str, Any]:
    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=_host_podman_env(),
            start_new_session=True,
        )
    except OSError as exc:
        return {
            "exit_code": 127,
            "stdout": "",
            "stderr": sanitize_evidence_text(str(exc)),
            "timed_out": False,
            "duration_seconds": 0.0,
        }

    timed_out = False
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            proc.kill()
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            stdout, stderr = "", "communicate_timeout_after_kill"
        code = 124
    else:
        code = int(proc.returncode if proc.returncode is not None else 1)

    return {
        "exit_code": code,
        "stdout": sanitize_evidence_text(stdout or ""),
        "stderr": sanitize_evidence_text(stderr or ""),
        "timed_out": timed_out,
        "duration_seconds": round(time.monotonic() - started, 3),
    }


def _unique_name(suffix: str) -> str:
    token = uuid.uuid4().hex[:10]
    name = f"{CONTAINER_NAME_PREFIX}{suffix}-{token}"
    if not re.fullmatch(r"eos-sandbox-poc-[A-Za-z0-9._-]{4,80}", name):
        _die("internal container name generation failed safety check")
    return name


def _podman_presence(name: str) -> dict[str, Any]:
    """Reliable presence check. Inspect/CLI errors are not treated as absence."""
    try:
        rc = subprocess.run(
            ["podman", "container", "exists", name],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            env=_host_podman_env(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "state": "inspect_error",
            "error": type(exc).__name__,
            "present": None,
        }
    if rc.returncode == 0:
        return {"state": "present", "present": True}
    if rc.returncode == 1:
        return {"state": "absent", "present": False}
    return {
        "state": "inspect_error",
        "present": None,
        "rc": rc.returncode,
        "stderr": sanitize_evidence_text(rc.stderr or ""),
    }


def _podman_inspect_runtime(name: str) -> dict[str, Any]:
    try:
        rc = subprocess.run(
            ["podman", "inspect", name, "--format", "json"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
            env=_host_podman_env(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": type(exc).__name__, "evidence_layer": "runtime_inspected"}
    if rc.returncode != 0:
        return {
            "ok": False,
            "error": "inspect_rc_nonzero",
            "rc": rc.returncode,
            "stderr": sanitize_evidence_text(rc.stderr or ""),
            "evidence_layer": "runtime_inspected",
        }
    return parse_podman_inspect(rc.stdout)


def _force_remove_container(name: str) -> dict[str, Any]:
    try:
        rc = subprocess.run(
            ["podman", "rm", "-f", name],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
            env=_host_podman_env(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"forced": False, "error": type(exc).__name__}
    return {
        "forced": True,
        "rc": rc.returncode,
        "stderr": sanitize_evidence_text(rc.stderr or "")[:500],
    }


def _podman_inspect_object(name: str) -> dict[str, Any]:
    """Return the first inspect object for a container, or an error envelope."""
    try:
        rc = subprocess.run(
            ["podman", "inspect", name, "--format", "json"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
            env=_host_podman_env(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": type(exc).__name__}
    if rc.returncode != 0:
        return {
            "ok": False,
            "error": "inspect_rc_nonzero",
            "rc": rc.returncode,
            "stderr": sanitize_evidence_text(rc.stderr or ""),
        }
    try:
        data = json.loads(rc.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "error": "inspect_json_decode_failed"}
    if isinstance(data, list):
        if not data:
            return {"ok": False, "error": "empty_inspect_list"}
        data = data[0]
    if not isinstance(data, dict):
        return {"ok": False, "error": "inspect_payload_not_object"}
    return {"ok": True, "object": data}


def _read_cgroup_file(cgroup_dir: Path, name: str) -> dict[str, Any]:
    path = cgroup_dir / name
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return {"ok": False, "error": "cgroup_file_missing", "path": name}
    except OSError as exc:
        return {"ok": False, "error": type(exc).__name__, "path": name}
    return {"ok": True, "text": text, "path": str(path)}


def locate_container_cgroup_dir(
    *,
    container_id: str | None,
    cgroup_path_hint: str | None,
) -> dict[str, Any]:
    """Resolve the container's own cgroup v2 directory (never an ancestor substitute)."""
    candidates: list[Path] = []
    hint = (cgroup_path_hint or "").strip()
    if hint:
        if hint.startswith("/sys/fs/cgroup"):
            candidates.append(Path(hint))
        elif hint.startswith("/"):
            candidates.append(Path("/sys/fs/cgroup") / hint.lstrip("/"))
            candidates.append(Path(hint))
        else:
            candidates.append(Path("/sys/fs/cgroup") / hint)

    cid = (container_id or "").strip().lower()
    if cid:
        short = cid[:12]
        roots = [Path("/sys/fs/cgroup")]
        # Prefer scoped search under the current user slice when present.
        uid = os.getuid()
        user_slice = Path(f"/sys/fs/cgroup/user.slice/user-{uid}.slice")
        if user_slice.is_dir():
            roots.insert(0, user_slice)
        for root in roots:
            try:
                for match in root.rglob(f"libpod-{cid}.scope"):
                    candidates.append(match)
                    break
                for match in root.rglob(f"libpod-{short}*.scope"):
                    candidates.append(match)
                    break
            except OSError:
                continue

    def _is_container_scope(path: Path) -> bool:
        name = path.name
        # Reject well-known ancestor / system nodes even if they expose cpu.*.
        banned = {
            "cgroup",
            "user.slice",
            f"user-{os.getuid()}.slice",
            "system.slice",
            "init.scope",
            "payload",
        }
        if name in banned or name.startswith("user@") and name.endswith(".service"):
            return False
        if cid:
            # When the container id is known, only accept the matching libpod scope.
            return name == f"libpod-{cid}.scope" or (
                name.startswith(f"libpod-{cid[:12]}") and name.endswith(".scope")
            )
        # Without an id, still require a libpod scope leaf (never a slice/service).
        return name.startswith("libpod-") and name.endswith(".scope")

    seen: set[str] = set()
    for cand in candidates:
        key = str(cand)
        if key in seen:
            continue
        seen.add(key)
        if not cand.is_dir():
            continue
        # Require container-local cpu controller files.
        if not (cand / "cpu.max").is_file() or not (cand / "cpu.stat").is_file():
            continue
        if not _is_container_scope(cand):
            continue
        return {
            "ok": True,
            "path": str(cand),
            "linked_container_id": cid or None,
            "hint": hint or None,
        }
    return {
        "ok": False,
        "error": "container_cgroup_not_found",
        "hint": hint or None,
        "container_id": cid or None,
    }


def _sample_container_cpu_cgroup(name: str) -> dict[str, Any]:
    """Inspect a live container and sample its cgroup cpu.max / cpu.stat."""
    inspected = _podman_inspect_object(name)
    if not inspected.get("ok"):
        return {
            "ok": False,
            "error": inspected.get("error") or "inspect_failed",
            "cgroup": None,
        }
    obj = inspected["object"]
    state = obj.get("State") if isinstance(obj.get("State"), dict) else {}
    container_id = str(obj.get("Id") or state.get("Cid") or "")
    cgroup_hint = str(state.get("CgroupPath") or obj.get("CgroupPath") or "")
    located = locate_container_cgroup_dir(
        container_id=container_id,
        cgroup_path_hint=cgroup_hint,
    )
    if not located.get("ok"):
        return {
            "ok": False,
            "error": located.get("error") or "cgroup_unresolved",
            "container_id": container_id,
            "cgroup_path_hint": cgroup_hint,
            "cgroup": located,
        }
    cgroup_dir = Path(str(located["path"]))
    cpu_max_raw = _read_cgroup_file(cgroup_dir, "cpu.max")
    cpu_stat_raw = _read_cgroup_file(cgroup_dir, "cpu.stat")
    if not cpu_max_raw.get("ok") or not cpu_stat_raw.get("ok"):
        return {
            "ok": False,
            "error": "cgroup_files_unreadable",
            "container_id": container_id,
            "cgroup": located,
            "cpu_max_raw": cpu_max_raw,
            "cpu_stat_raw": cpu_stat_raw,
        }
    return {
        "ok": True,
        "container_name": name,
        "container_id": container_id,
        "cgroup": located,
        "cpu_max": parse_cpu_max(cpu_max_raw["text"]),
        "cpu_stat": parse_cpu_stat(cpu_stat_raw["text"]),
        "cpu_max_text": sanitize_evidence_text(cpu_max_raw["text"]),
        "cpu_stat_text": sanitize_evidence_text(cpu_stat_raw["text"]),
    }


def _run_cpu_quota_probe(
    *,
    image: str,
    workspace: Path,
    started_names: list[str],
    configured_cpus: float = 0.50,
) -> dict[str, Any]:
    """Run a live CPU stress container and attribute quota + throttling."""
    name = _unique_name("p6c")
    started_names.append(name)
    cmd, planned = build_command(
        "podman",
        image=image,
        workspace=workspace,
        memory="128m",
        cpus=f"{configured_cpus:.2f}",
        pids=64,
        tmpfs_size="64m",
        inner_command=["/bin/sh", "-c", _inner_p6_cpu()],
        name=name,
        rm=False,
    )
    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=_host_podman_env(),
            start_new_session=True,
        )
    except OSError as exc:
        return {
            "dim": "cpu",
            "ok": False,
            "cpu_attribution": "launch_failed",
            "error": type(exc).__name__,
            "limit_ok": False,
            "cpu_attributed": False,
            "planned_controls": planned,
            "sanitized_command": sanitize_command(cmd, workspace),
        }

    sample_before: dict[str, Any] | None = None
    sample_after: dict[str, Any] | None = None
    timed_out = False
    stdout = ""
    stderr = ""
    exit_code = 1

    try:
        # Wait until the container is present, then sample cgroup before/during load.
        for _ in range(50):
            presence = _podman_presence(name)
            if presence.get("state") == "present":
                sample_before = _sample_container_cpu_cgroup(name)
                break
            if proc.poll() is not None:
                break
            time.sleep(0.1)

        # Allow the busy-loop interval to accumulate throttle counters.
        time.sleep(4.0)
        if _podman_presence(name).get("state") == "present":
            sample_after = _sample_container_cpu_cgroup(name)

        try:
            stdout, stderr = proc.communicate(timeout=20)
            exit_code = int(proc.returncode if proc.returncode is not None else 1)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                proc.kill()
            try:
                stdout, stderr = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                stdout, stderr = "", "communicate_timeout_after_kill"
            exit_code = 124
    finally:
        presence_now = _podman_presence(name)
        force_result = None
        if presence_now.get("state") in {"present", "inspect_error"}:
            force_result = _force_remove_container(name)
        presence_after = _podman_presence(name)

    inspect_controls = {}
    inspect_ok = False
    if sample_before and sample_before.get("ok"):
        # Re-use controls from a final inspect attempt if container lingered.
        pass
    # Controls: parse from planned argv + optional inspect while alive was embedded.
    argv_probe = scan_argv_safety(cmd, workspace=workspace)

    cpu_max = (sample_after or sample_before or {}).get("cpu_max") or {}
    before_stat = (sample_before or {}).get("cpu_stat") or {"ok": False}
    after_stat = (sample_after or {}).get("cpu_stat") or {"ok": False}
    delta = cpu_stat_delta(before_stat, after_stat)

    quota_ok = cpu_quota_matches_configured(cpu_max, configured_cpus=configured_cpus)
    throttle_ok = cpu_throttling_attributed(delta)
    cgroup_ok = bool((sample_before or {}).get("ok")) and bool((sample_after or {}).get("ok"))

    if not cgroup_ok:
        attribution = "cgroup_unavailable"
        attributed = False
        limit_value: Any = "NOT_TESTED"
    elif cpu_max.get("unlimited"):
        attribution = "unlimited_cpu_max"
        attributed = False
        limit_value = False
    elif not quota_ok:
        attribution = "quota_mismatch_or_unreadable"
        attributed = False
        limit_value = False
    elif not throttle_ok:
        attribution = "quota_observed_without_throttle"
        attributed = False
        limit_value = "NOT_TESTED"
    else:
        attribution = "quota_and_throttle"
        attributed = True
        limit_value = True

    # Prefer runtime inspect controls from sample metadata via a dedicated inspect
    # while present; if already removed, fall back to argv-only (not for PASS).
    if sample_after and sample_after.get("ok"):
        # Container may still exist briefly; try inspect for control booleans.
        if _podman_presence(name).get("state") == "present":
            parsed = _podman_inspect_runtime(name)
            if parsed.get("ok"):
                inspect_controls = parsed.get("runtime_inspected_controls") or {}
                inspect_ok = True

    return {
        "dim": "cpu",
        "ok": attributed,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "duration_seconds": round(time.monotonic() - started, 3),
        "configured_cpus": configured_cpus,
        "cpu_max": cpu_max,
        "cpu_stat_before": before_stat,
        "cpu_stat_after": after_stat,
        "cpu_stat_delta": delta,
        "sample_before_ok": bool((sample_before or {}).get("ok")),
        "sample_after_ok": bool((sample_after or {}).get("ok")),
        "cgroup": (sample_after or sample_before or {}).get("cgroup"),
        "container_id": (sample_after or sample_before or {}).get("container_id"),
        "container_name": name,
        "cpu_attribution": attribution,
        "cpu_attributed": attributed,
        "limit_ok": limit_value,
        "quota_ok": quota_ok,
        "throttle_ok": throttle_ok,
        "stdout": sanitize_evidence_text(stdout or ""),
        "stderr": sanitize_evidence_text(stderr or ""),
        "planned_controls": planned,
        "launcher_argv_controls": argv_probe.get("launcher_argv_controls") or {},
        "runtime_inspected_controls": inspect_controls,
        "inspect_ok": inspect_ok,
        "cleanup_absent": presence_after.get("state") == "absent",
        "force_cleanup": force_result,
        "sanitized_command": sanitize_command(cmd, workspace),
    }


def _parse_marker_block(stdout: str, start: str, end: str) -> str:
    pattern = rf"{re.escape(start)}\n(.*?){re.escape(end)}"
    match = re.search(pattern, stdout, re.S)
    return match.group(1).strip() if match else ""


def _read_proc_file(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return {"ok": False, "error": "proc_file_missing", "path": str(path)}
    except PermissionError:
        return {"ok": False, "error": "proc_file_permission_denied", "path": str(path)}
    except OSError as exc:
        return {"ok": False, "error": type(exc).__name__, "path": str(path)}
    return {"ok": True, "text": text, "path": str(path)}


def _proc_starttime(pid: int) -> dict[str, Any]:
    """Read field 22 (starttime) from ``/proc/<pid>/stat`` for PID-reuse guards."""
    raw = _read_proc_file(Path(f"/proc/{pid}/stat"))
    if not raw.get("ok"):
        return raw
    text = raw["text"]
    # Comm may contain spaces/parentheses; split after the closing ')'.
    try:
        rparen = text.rfind(")")
        fields = text[rparen + 2 :].split()
        starttime = int(fields[19])  # starttime is the 22nd overall field → index 19 after state
    except (IndexError, ValueError):
        return {"ok": False, "error": "stat_starttime_unparseable", "raw": text[:120]}
    return {"ok": True, "starttime": starttime, "pid": pid}


def _ns_inode(path: Path) -> dict[str, Any]:
    try:
        st = path.stat()
    except FileNotFoundError:
        return {"ok": False, "error": "ns_missing"}
    except OSError as exc:
        return {"ok": False, "error": type(exc).__name__}
    return {"ok": True, "inode": int(st.st_ino), "dev": int(st.st_dev)}


def _link_container_pid(
    *,
    name: str,
    expected_id: str | None,
    pid: int | None,
) -> dict[str, Any]:
    if not pid or int(pid) <= 1:
        return {"ok": False, "error": "missing_or_invalid_pid", "pid": pid}
    presence = _podman_presence(name)
    if presence.get("state") != "present":
        return {
            "ok": False,
            "error": "container_not_present_for_pid_link",
            "presence": presence,
            "pid": pid,
        }
    inspected = _podman_inspect_object(name)
    if not inspected.get("ok"):
        return {"ok": False, "error": "inspect_failed_for_pid_link", "detail": inspected}
    obj = inspected["object"]
    state = obj.get("State") if isinstance(obj.get("State"), dict) else {}
    cid = str(obj.get("Id") or "")
    live_pid = state.get("Pid")
    if expected_id and cid and not (
        cid == expected_id or cid.startswith(expected_id) or expected_id.startswith(cid)
    ):
        return {
            "ok": False,
            "error": "container_id_mismatch",
            "expected_id": expected_id,
            "observed_id": cid,
        }
    if live_pid is None or int(live_pid) != int(pid):
        return {
            "ok": False,
            "error": "pid_mismatch_against_inspect",
            "expected_pid": pid,
            "observed_pid": live_pid,
            "container_id": cid,
        }
    start = _proc_starttime(int(pid))
    if not start.get("ok"):
        return {"ok": False, "error": "proc_starttime_unreadable", "detail": start, "pid": pid}
    ns = _ns_inode(Path(f"/proc/{int(pid)}/ns/user"))
    if not ns.get("ok"):
        return {"ok": False, "error": "userns_inode_unreadable", "detail": ns, "pid": pid}
    return {
        "ok": True,
        "pid": int(pid),
        "container_name": name,
        "container_id": cid,
        "starttime": start["starttime"],
        "userns_inode": ns["inode"],
    }


def _sample_host_side_identity(pid: int, *, starttime: int) -> dict[str, Any]:
    """Read maps/caps/ns from launching-host context; guard against PID reuse."""
    live = _proc_starttime(pid)
    if not live.get("ok"):
        return {"ok": False, "error": "process_disappeared_during_sample", "detail": live}
    if int(live["starttime"]) != int(starttime):
        return {
            "ok": False,
            "error": "pid_reuse_detected",
            "expected_starttime": starttime,
            "observed_starttime": live["starttime"],
        }
    uid_raw = _read_proc_file(Path(f"/proc/{pid}/uid_map"))
    gid_raw = _read_proc_file(Path(f"/proc/{pid}/gid_map"))
    status_raw = _read_proc_file(Path(f"/proc/{pid}/status"))
    ns = _ns_inode(Path(f"/proc/{pid}/ns/user"))
    reader_ns = _ns_inode(Path("/proc/self/ns/user"))
    if not uid_raw.get("ok") or not gid_raw.get("ok"):
        return {
            "ok": False,
            "error": "host_side_maps_unreadable",
            "uid_raw": uid_raw,
            "gid_raw": gid_raw,
        }
    uid_map = parse_id_map(uid_raw["text"])
    gid_map = parse_id_map(gid_raw["text"])
    uid_map["reader_context"] = "launching_host"
    gid_map["reader_context"] = "launching_host"
    caps = parse_proc_status_capabilities(status_raw.get("text") or "")
    # Re-check starttime after reads.
    live_after = _proc_starttime(pid)
    if not live_after.get("ok") or int(live_after.get("starttime") or -1) != int(starttime):
        return {
            "ok": False,
            "error": "process_changed_during_sample",
            "before": live,
            "after": live_after,
        }
    return {
        "ok": True,
        "pid": pid,
        "starttime": starttime,
        "host_side_uid_map": uid_map,
        "host_side_gid_map": gid_map,
        "capabilities": caps,
        "container_userns": ns,
        "reader_userns": reader_ns,
        "reader_uid": os.getuid(),
        "reader_gid": os.getgid(),
        "same_userns_as_reader": bool(
            ns.get("ok")
            and reader_ns.get("ok")
            and ns.get("inode") == reader_ns.get("inode")
        ),
    }


def _execute_security_identity_probe(
    *,
    image: str,
    workspace: Path,
    started_names: list[str],
    host_uid: int,
    host_gid: int,
) -> dict[str, Any]:
    """Synthetic probe: Cap* + keep-id via host-side procfs while container is alive."""
    name = _unique_name("secid")
    started_names.append(name)
    marker_name = "security-identity-marker.txt"
    marker_path = workspace / marker_name
    if marker_path.exists():
        marker_path.unlink()

    cmd, planned = build_command(
        "podman",
        image=image,
        workspace=workspace,
        memory="128m",
        cpus="0.50",
        pids=64,
        tmpfs_size="64m",
        inner_command=["/bin/sh", "-c", _inner_security_identity()],
        name=name,
        rm=False,
    )
    argv_probe = scan_argv_safety(cmd, workspace=workspace)
    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=_host_podman_env(),
            start_new_session=True,
        )
    except OSError as exc:
        return {
            "probe": "security_identity",
            "exit_code": 127,
            "error": type(exc).__name__,
            "capability": {"verdict": {"status": "NOT_TESTED", "attributed": False}},
            "userns": {
                "verdict": {
                    "status": "NOT_TESTED",
                    "reason": "launch_failed",
                    "attributed": False,
                }
            },
            "cleanup_observed": True,
            "sanitized_command": sanitize_command(cmd, workspace),
        }

    sample: dict[str, Any] | None = None
    pid_link: dict[str, Any] = {"ok": False, "error": "not_sampled"}
    container_id: str | None = None
    inspect_controls: dict[str, Any] = {}
    inspect_ok = False
    timed_out = False
    stdout = ""
    stderr = ""
    exit_code = 1

    try:
        for _ in range(80):
            presence = _podman_presence(name)
            if presence.get("state") == "present":
                inspected = _podman_inspect_object(name)
                if inspected.get("ok"):
                    obj = inspected["object"]
                    state = obj.get("State") if isinstance(obj.get("State"), dict) else {}
                    container_id = str(obj.get("Id") or "")
                    pid = state.get("Pid")
                    parsed_controls = parse_podman_inspect([obj])
                    if parsed_controls.get("ok"):
                        inspect_controls = (
                            parsed_controls.get("runtime_inspected_controls") or {}
                        )
                        inspect_ok = True
                    pid_link = _link_container_pid(
                        name=name, expected_id=container_id, pid=pid
                    )
                    if pid_link.get("ok"):
                        # Wait briefly for marker write + READY marker.
                        time.sleep(0.5)
                        sample = _sample_host_side_identity(
                            int(pid_link["pid"]),
                            starttime=int(pid_link["starttime"]),
                        )
                        # Confirm linkage still matches the same container/PID.
                        relink = _link_container_pid(
                            name=name,
                            expected_id=container_id,
                            pid=int(pid_link["pid"]),
                        )
                        if not relink.get("ok") or relink.get("starttime") != pid_link.get(
                            "starttime"
                        ):
                            sample = {
                                "ok": False,
                                "error": "container_identity_changed_during_sample",
                                "pid_link_before": pid_link,
                                "pid_link_after": relink,
                            }
                    break
            if proc.poll() is not None:
                break
            time.sleep(0.1)

        try:
            stdout, stderr = proc.communicate(timeout=20)
            exit_code = int(proc.returncode if proc.returncode is not None else 1)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                proc.kill()
            try:
                stdout, stderr = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                stdout, stderr = "", "communicate_timeout_after_kill"
            exit_code = 124
    finally:
        presence_now = _podman_presence(name)
        force_result = None
        if presence_now.get("state") in {"present", "inspect_error"}:
            force_result = _force_remove_container(name)
        presence_after = _podman_presence(name)

    stdout_s = sanitize_evidence_text(stdout or "")
    uid_match = re.search(r"(?m)^CONTAINER_UID=(\d+)$", stdout_s)
    gid_match = re.search(r"(?m)^CONTAINER_GID=(\d+)$", stdout_s)
    container_uid = int(uid_match.group(1)) if uid_match else None
    container_gid = int(gid_match.group(1)) if gid_match else None

    ws_uid = workspace.stat().st_uid if workspace.exists() else None
    ws_gid = workspace.stat().st_gid if workspace.exists() else None
    marker_uid = marker_path.stat().st_uid if marker_path.is_file() else None
    marker_gid = marker_path.stat().st_gid if marker_path.is_file() else None

    caps_parsed = (sample or {}).get("capabilities") or {"ok": False, "error": "not_sampled"}
    # Prefer host-side /proc/<pid>/status; fall back unavailable rather than argv.
    cap_verdict = capability_drop_all_attributed(caps_parsed)

    host_uid_map = (sample or {}).get("host_side_uid_map") or {
        "ok": False,
        "error": "not_sampled",
    }
    host_gid_map = (sample or {}).get("host_side_gid_map") or {
        "ok": False,
        "error": "not_sampled",
    }

    userns_evidence = {
        "container_uid": container_uid,
        "container_gid": container_gid,
        "host_uid": host_uid,
        "host_gid": host_gid,
        "workspace_owner_uid": ws_uid,
        "workspace_owner_gid": ws_gid,
        "marker_owner_uid": marker_uid,
        "marker_owner_gid": marker_gid,
        "marker_written": bool(marker_path.is_file()),
        "host_side_uid_map": host_uid_map,
        "host_side_gid_map": host_gid_map,
        "pid_link": pid_link,
        "require_pid_link": True,
        "sample_ok": bool((sample or {}).get("ok")),
        "sample_error": None if (sample or {}).get("ok") else (sample or {}).get("error"),
        "reader_uid": (sample or {}).get("reader_uid"),
        "reader_gid": (sample or {}).get("reader_gid"),
        "container_userns": (sample or {}).get("container_userns"),
        "reader_userns": (sample or {}).get("reader_userns"),
    }
    if not (sample or {}).get("ok"):
        userns_verdict = {
            "status": "NOT_TESTED",
            "reason": (sample or {}).get("error") or pid_link.get("error") or "host_side_sample_failed",
            "attributed": False,
            "pid_link": pid_link,
            "sample": sample,
        }
    else:
        userns_verdict = userns_keep_id_attributed(userns_evidence)

    return {
        "probe": "security_identity",
        "phase": "B3",
        "exit_code": exit_code,
        "timed_out": timed_out,
        "duration_seconds": round(time.monotonic() - started, 3),
        "stdout": stdout_s,
        "stderr": sanitize_evidence_text(stderr or ""),
        "planned_controls": planned,
        "launcher_argv_controls": argv_probe.get("launcher_argv_controls") or {},
        "runtime_inspected_controls": inspect_controls,
        "inspect_ok": inspect_ok,
        "capability": {
            "parsed": caps_parsed,
            "verdict": cap_verdict,
            "source": "host_side_proc_status",
        },
        "userns": {
            "evidence": userns_evidence,
            "verdict": userns_verdict,
            "source": "host_side_procfs",
        },
        "pid_link": pid_link,
        "host_sample": {
            "ok": bool((sample or {}).get("ok")),
            "error": None if (sample or {}).get("ok") else (sample or {}).get("error"),
            "pid": (sample or {}).get("pid"),
            "starttime": (sample or {}).get("starttime"),
        },
        "cleanup_observed": presence_after.get("state") == "absent",
        "force_cleanup": force_result,
        "sanitized_command": sanitize_command(cmd, workspace),
        "evidence_layers": {
            "launcher_config": planned,
            "executed_argv": argv_probe.get("launcher_argv_controls") or {},
            "runtime_inspected": inspect_controls,
            "argv_is_not_enforcement_proof": True,
            "behavioral": {
                "host_side_userns": userns_verdict.get("status"),
                "capability": cap_verdict.get("status"),
            },
        },
    }


def _compose_evidence(
    *,
    planned: dict[str, bool],
    cmd: list[str],
    workspace: Path,
    inspect_result: dict[str, Any] | None,
) -> dict[str, Any]:
    argv_probe = scan_argv_safety(cmd, workspace=workspace)
    inspected = {}
    inspect_ok = False
    oom_killed = False
    if inspect_result and inspect_result.get("ok"):
        inspected = dict(inspect_result.get("runtime_inspected_controls") or {})
        inspect_ok = True
        oom_killed = bool(inspect_result.get("oom_killed"))

    return {
        "evidence_layers": {
            "launcher_config": planned,
            "executed_argv": argv_probe.get("launcher_argv_controls") or {},
            "runtime_inspected": inspected,
            "argv_is_not_enforcement_proof": True,
        },
        "planned_controls": planned,
        "launcher_argv_controls": argv_probe.get("launcher_argv_controls") or {},
        "runtime_inspected_controls": inspected,
        # observed_controls alias for evaluator: runtime inspect only.
        "observed_controls": inspected,
        "control_evidence_source": (
            "runtime_inspected_and_behavioral" if inspect_ok else "invalid_missing_inspect"
        ),
        "controls_provenance": "runtime_inspect" if inspect_ok else "missing_inspect",
        "observed_controls_copied_from_plan": False,
        "independent_control_probe": inspect_ok,
        "oom_killed": oom_killed,
        "inspect_summary": (inspect_result or {}).get("raw_summary"),
        "inspect_ok": inspect_ok,
        "inspect_error": None if inspect_ok else (inspect_result or {}).get("error"),
    }


def _run_inspectable(
    *,
    image: str,
    workspace: Path,
    inner: list[str],
    name: str,
    timeout: float,
    memory: str = "256m",
    cpus: str = "0.50",
    pids: int = 64,
    tmpfs_size: str = "64m",
    rm: bool = False,
    started_names: list[str] | None = None,
) -> dict[str, Any]:
    """Run a named container, inspect when possible, always best-effort cleanup."""
    if started_names is not None:
        started_names.append(name)
    cmd, planned = build_command(
        "podman",
        image=image,
        workspace=workspace,
        memory=memory,
        cpus=cpus,
        pids=pids,
        tmpfs_size=tmpfs_size,
        inner_command=inner,
        name=name,
        rm=rm,
    )
    run = _run_subprocess(cmd, timeout=timeout)
    inspect_result: dict[str, Any] | None = None
    cleanup_meta: dict[str, Any] = {
        "auto_rm": bool(rm),
        "forced_cleanup": False,
        "presence_before_cleanup": None,
        "presence_after_cleanup": None,
    }

    try:
        if not rm:
            presence = _podman_presence(name)
            cleanup_meta["presence_before_cleanup"] = presence
            if presence.get("state") == "present":
                inspect_result = _podman_inspect_runtime(name)
            elif presence.get("state") == "inspect_error":
                inspect_result = {
                    "ok": False,
                    "error": "presence_inspect_error",
                    "detail": presence,
                }
            else:
                # Absent without --rm is unexpected; still not an inspect success.
                inspect_result = {"ok": False, "error": "container_absent_before_inspect"}
        else:
            # With --rm, inspect of a finished container is usually impossible.
            presence = _podman_presence(name)
            cleanup_meta["presence_before_cleanup"] = presence
            if presence.get("state") == "present":
                inspect_result = _podman_inspect_runtime(name)
            else:
                inspect_result = {
                    "ok": False,
                    "error": "rm_removed_before_inspect",
                    "note": "use non-rm sibling run for control inspect when needed",
                }
    finally:
        # Guaranteed best-effort cleanup for timeout and exception paths.
        presence_now = _podman_presence(name)
        if presence_now.get("state") == "present":
            force = _force_remove_container(name)
            cleanup_meta["forced_cleanup"] = True
            cleanup_meta["force_result"] = force
        elif presence_now.get("state") == "inspect_error":
            # Still attempt force remove; record uncertainty.
            force = _force_remove_container(name)
            cleanup_meta["forced_cleanup"] = True
            cleanup_meta["force_result"] = force
            cleanup_meta["presence_uncertain"] = True
        after = _podman_presence(name)
        cleanup_meta["presence_after_cleanup"] = after

    evidence = _compose_evidence(
        planned=planned,
        cmd=cmd,
        workspace=workspace,
        inspect_result=inspect_result,
    )
    return {
        **evidence,
        **run,
        "container_name": name,
        "sanitized_command": sanitize_command(cmd, workspace),
        "cleanup_meta": cleanup_meta,
        "planned_controls": planned,
    }


def _cleanup_all(names: list[str]) -> list[dict[str, Any]]:
    reports = []
    for name in names:
        presence = _podman_presence(name)
        entry = {"name": name, "before": presence}
        if presence.get("state") in {"present", "inspect_error"}:
            entry["force"] = _force_remove_container(name)
        entry["after"] = _podman_presence(name)
        reports.append(entry)
    return reports


def execute_single(
    test: dict[str, Any],
    *,
    root: Path,
    image: str,
    started_names: list[str],
) -> dict[str, Any]:
    alpha = root / SYNTH_ALPHA
    test_id = test["id"]
    timeout = float(test.get("host_timeout_seconds") or 30)
    canary_path = Path(test["canary"]) if test.get("canary") else None
    canary_before = sha256_file(canary_path) if canary_path and canary_path.exists() else None

    if test_id == "P6":
        return _execute_p6(root=root, image=image, test=test, started_names=started_names)
    if test_id == "P7":
        return _execute_p7(root=root, image=image, test=test, started_names=started_names)

    # Control-inspectable run (no --rm), then guaranteed cleanup.
    name = _unique_name(test_id.lower())
    raw = _run_inspectable(
        image=image,
        workspace=alpha,
        inner=list(test["inner_command"]),
        name=name,
        timeout=timeout,
        memory=str(test.get("memory") or "256m"),
        cpus=str(test.get("cpus") or "0.50"),
        pids=int(test.get("pids") or 64),
        rm=False,
        started_names=started_names,
    )

    after = (raw.get("cleanup_meta") or {}).get("presence_after_cleanup") or {}
    if after.get("state") == "absent":
        raw["cleanup_observed"] = True
        raw["cleanup_source"] = (
            "forced_cleanup" if (raw.get("cleanup_meta") or {}).get("forced_cleanup") else "auto_or_forced"
        )
        raw["cleanup_presence_error"] = False
    elif after.get("state") == "inspect_error":
        raw["cleanup_observed"] = False
        raw["cleanup_source"] = "inspect_error_assumed_absent"
        raw["cleanup_presence_error"] = True
    else:
        raw["cleanup_observed"] = False
        raw["cleanup_source"] = "container_still_present"
        raw["cleanup_presence_error"] = False

    if canary_path is not None:
        canary_after = sha256_file(canary_path) if canary_path.exists() else None
        raw["canary_before"] = canary_before
        raw["canary_after"] = canary_after
        raw["canary_verified_on_host"] = True
        raw["path_kind"] = parse_container_path_kind(raw.get("stdout") or "")

    if test_id == "P1":
        host_file = alpha / "p1.txt"
        ok = host_file.is_file() and host_file.read_text(encoding="utf-8").strip() == "ok"
        raw["host_workspace_write_verified"] = ok

    if test_id == "P5":
        stdout = raw.get("stdout") or ""
        ip_status = parse_probe_status(stdout, "IP_PROBE_STATUS")
        dns_status = parse_probe_status(stdout, "DNS_PROBE_STATUS")
        raw["ip_probe_status"] = ip_status
        raw["dns_probe_status"] = dns_status
        raw["ip_probe_succeeded"] = ip_status == "executed_succeeded"
        raw["dns_probe_succeeded"] = dns_status == "executed_succeeded"
        raw["network_namespace_observed"] = bool(re.search(r"NETNS_IFACES=", stdout))
        raw["unconditional_exit_used"] = False
        m = re.search(r"NETNS_IFACES=([^\n]*)", stdout)
        raw["network_ifaces_observed"] = m.group(1) if m else ""

    # P2/P3/P4: present_readable inside container is a security FAIL via path_classification.
    return raw


def _execute_p6(
    *,
    root: Path,
    image: str,
    test: dict[str, Any],
    started_names: list[str],
) -> dict[str, Any]:
    alpha = root / SYNTH_ALPHA
    dimensions: dict[str, Any] = {
        "memory": False,
        "cpu": "NOT_TESTED",
        "pids": False,
        "tmpfs": False,
        "wall_clock": False,
        "tmpfs_full": False,
    }
    sub_results: list[dict[str, Any]] = []

    # Memory: require attributable OOM/cgroup evidence via inspect + exit.
    mem_name = _unique_name("p6m")
    mem_raw = _run_inspectable(
        image=image,
        workspace=alpha,
        inner=["/bin/sh", "-c", "dd if=/dev/zero of=/tmp/big bs=1M count=200"],
        name=mem_name,
        timeout=15,
        memory="16m",
        cpus="0.25",
        pids=32,
        tmpfs_size="256m",
        rm=False,
        started_names=started_names,
    )
    mem_attr = {
        "exit_code": mem_raw.get("exit_code"),
        "stdout": mem_raw.get("stdout"),
        "stderr": mem_raw.get("stderr"),
        "oom_killed": mem_raw.get("oom_killed"),
    }
    err = f"{mem_raw.get('stderr') or ''} {mem_raw.get('stdout') or ''}".lower()
    if "no space" in err:
        dimensions["tmpfs"] = True
        dimensions["tmpfs_full"] = True
        mem_raw["memory_attribution"] = "tmpfs_enospc_not_memory"
    elif memory_limit_attributed(mem_attr):
        dimensions["memory"] = True
        mem_raw["memory_attribution"] = "oom_or_cgroup"
    else:
        mem_raw["memory_attribution"] = "unattributed_nonzero_or_success"
    sub_results.append({"dim": "memory", **{k: mem_raw.get(k) for k in (
        "exit_code", "timed_out", "memory_attribution", "oom_killed", "inspect_ok"
    )}})

    # PIDs: require FORK_DENIED marker / attribution.
    pids_name = _unique_name("p6p")
    pids_raw = _run_inspectable(
        image=image,
        workspace=alpha,
        inner=["/bin/sh", "-c", _inner_p6_pids()],
        name=pids_name,
        timeout=15,
        memory="64m",
        cpus="0.25",
        pids=8,
        rm=False,
        started_names=started_names,
    )
    if pids_limit_attributed(pids_raw):
        dimensions["pids"] = True
        pids_raw["pids_attribution"] = "fork_denied"
    else:
        pids_raw["pids_attribution"] = "unattributed"
    sub_results.append({"dim": "pids", **{k: pids_raw.get(k) for k in (
        "exit_code", "timed_out", "pids_attribution", "inspect_ok"
    )}})

    # Wall-clock: host timeout must fire; container must be cleaned up.
    wall_name = _unique_name("p6w")
    wall_raw = _run_inspectable(
        image=image,
        workspace=alpha,
        inner=["/bin/sh", "-c", "sleep 120"],
        name=wall_name,
        timeout=3,
        memory="64m",
        cpus="0.25",
        pids=32,
        rm=False,
        started_names=started_names,
    )
    if wall_clock_attributed(wall_raw):
        dimensions["wall_clock"] = True
        wall_raw["wall_clock_attribution"] = "host_timeout"
    else:
        wall_raw["wall_clock_attribution"] = "unattributed"
    # Ensure resource-test container is not left running after timeout.
    after_wall = (wall_raw.get("cleanup_meta") or {}).get("presence_after_cleanup") or {}
    wall_cleanup_ok = after_wall.get("state") == "absent"
    sub_results.append(
        {
            "dim": "wall_clock",
            "exit_code": wall_raw.get("exit_code"),
            "timed_out": wall_raw.get("timed_out"),
            "wall_clock_attribution": wall_raw.get("wall_clock_attribution"),
            "cleanup_absent": wall_cleanup_ok,
        }
    )

    # CPU: container-scoped cpu.max + behavioral throttling under load.
    cpu_raw = _run_cpu_quota_probe(
        image=image,
        workspace=alpha,
        started_names=started_names,
        configured_cpus=0.50,
    )
    dimensions["cpu"] = cpu_raw.get("limit_ok")
    sub_results.append(
        {
            "dim": "cpu",
            "exit_code": cpu_raw.get("exit_code"),
            "timed_out": cpu_raw.get("timed_out"),
            "cpu_attribution": cpu_raw.get("cpu_attribution"),
            "configured_cpus": cpu_raw.get("configured_cpus"),
            "quota_ok": cpu_raw.get("quota_ok"),
            "throttle_ok": cpu_raw.get("throttle_ok"),
            "cpu_max": cpu_raw.get("cpu_max"),
            "cpu_stat_delta": cpu_raw.get("cpu_stat_delta"),
            "cgroup": cpu_raw.get("cgroup"),
            "container_id": cpu_raw.get("container_id"),
            "cleanup_absent": cpu_raw.get("cleanup_absent"),
            "sample_before_ok": cpu_raw.get("sample_before_ok"),
            "sample_after_ok": cpu_raw.get("sample_after_ok"),
        }
    )

    # Supporting security identity probe (capabilities + keep-id maps).
    policy = resolve_uid_policy(runtime="podman")
    security_raw = _execute_security_identity_probe(
        image=image,
        workspace=alpha,
        started_names=started_names,
        host_uid=int(policy["host_uid"]),
        host_gid=int(policy["host_gid"]),
    )

    # Prefer memory run inspect for control evidence (limits configured).
    evidence = {
        "evidence_layers": mem_raw.get("evidence_layers"),
        "planned_controls": mem_raw.get("planned_controls"),
        "launcher_argv_controls": mem_raw.get("launcher_argv_controls"),
        "runtime_inspected_controls": mem_raw.get("runtime_inspected_controls") or {},
        "observed_controls": mem_raw.get("runtime_inspected_controls") or {},
        "control_evidence_source": mem_raw.get("control_evidence_source"),
        "controls_provenance": mem_raw.get("controls_provenance"),
        "observed_controls_copied_from_plan": False,
        "independent_control_probe": mem_raw.get("independent_control_probe"),
        "inspect_ok": mem_raw.get("inspect_ok"),
    }
    # If memory inspect failed, fall back to pids inspect.
    if not evidence.get("inspect_ok") and pids_raw.get("inspect_ok"):
        evidence["runtime_inspected_controls"] = pids_raw.get("runtime_inspected_controls") or {}
        evidence["observed_controls"] = evidence["runtime_inspected_controls"]
        evidence["control_evidence_source"] = pids_raw.get("control_evidence_source")
        evidence["controls_provenance"] = pids_raw.get("controls_provenance")
        evidence["inspect_ok"] = True
        evidence["independent_control_probe"] = True
    # Ensure cpu_limit appears in inspected controls when memory inspect saw it.
    if evidence.get("runtime_inspected_controls") is not None:
        # cpu_limit may already be true from NanoCpus; leave as-is.
        pass

    overall_exit = mem_raw.get("exit_code")
    if dimensions["wall_clock"]:
        overall_exit = 124
    # CPU subprobe success (exit 0) must not override attributable failures.
    if dimensions.get("cpu") is True and overall_exit not in {1, 137, 139, 143, 124}:
        overall_exit = 0

    cpu_cleanup_ok = bool(cpu_raw.get("cleanup_absent"))
    security_cleanup_ok = bool(security_raw.get("cleanup_observed"))

    return {
        **evidence,
        "exit_code": overall_exit,
        "stdout": sanitize_evidence_text(
            "\n".join(f"{s['dim']}:{json.dumps(s, sort_keys=True)}" for s in sub_results)
        ),
        "stderr": "",
        "timed_out": bool(wall_raw.get("timed_out")),
        "limit_dimensions": dimensions,
        "sub_results": sub_results,
        "sanitized_command": mem_raw.get("sanitized_command"),
        "memory_attributed": bool(dimensions["memory"]),
        "pids_attributed": bool(dimensions["pids"]),
        "wall_clock_attributed": bool(dimensions["wall_clock"]) and wall_cleanup_ok,
        "cpu_attributed": bool(dimensions.get("cpu") is True),
        "cpu_attribution": cpu_raw.get("cpu_attribution"),
        "cpu_evidence": {
            "configured_cpus": cpu_raw.get("configured_cpus"),
            "cpu_max": cpu_raw.get("cpu_max"),
            "cpu_stat_before": cpu_raw.get("cpu_stat_before"),
            "cpu_stat_after": cpu_raw.get("cpu_stat_after"),
            "cpu_stat_delta": cpu_raw.get("cpu_stat_delta"),
            "cgroup": cpu_raw.get("cgroup"),
            "container_id": cpu_raw.get("container_id"),
            "container_name": cpu_raw.get("container_name"),
            "quota_ok": cpu_raw.get("quota_ok"),
            "throttle_ok": cpu_raw.get("throttle_ok"),
            "attribution": cpu_raw.get("cpu_attribution"),
        },
        "capability_evidence": security_raw.get("capability"),
        "userns_evidence": security_raw.get("userns"),
        "security_identity_probe": {
            "exit_code": security_raw.get("exit_code"),
            "cleanup_observed": security_cleanup_ok,
            "sanitized_command": security_raw.get("sanitized_command"),
        },
        "cleanup_observed": wall_cleanup_ok and cpu_cleanup_ok and security_cleanup_ok,
        "cleanup_source": "p6_forced_cleanup_after_subprobes",
        "oom_killed": mem_raw.get("oom_killed"),
    }


def _execute_p7(
    *,
    root: Path,
    image: str,
    test: dict[str, Any],
    started_names: list[str],
) -> dict[str, Any]:
    alpha = root / SYNTH_ALPHA

    # Success path with --rm: verify absence without treating inspect errors as gone.
    name_ok = _unique_name("p7ok")
    started_names.append(name_ok)
    cmd_ok, planned = build_command(
        "podman",
        image=image,
        workspace=alpha,
        inner_command=["/bin/sh", "-c", "echo cleanup-marker"],
        name=name_ok,
        rm=True,
    )
    run_ok = _run_subprocess(cmd_ok, timeout=20)
    presence_ok = _podman_presence(name_ok)
    success_auto_removed = presence_ok.get("state") == "absent"
    success_presence_error = presence_ok.get("state") == "inspect_error"
    if presence_ok.get("state") == "present":
        _force_remove_container(name_ok)
        presence_ok_after = _podman_presence(name_ok)
        success_forced = True
    else:
        presence_ok_after = presence_ok
        success_forced = False

    # Separate inspectable sibling for runtime controls (not using --rm).
    name_inspect = _unique_name("p7insp")
    insp = _run_inspectable(
        image=image,
        workspace=alpha,
        inner=["/bin/sh", "-c", "true"],
        name=name_inspect,
        timeout=20,
        rm=False,
        started_names=started_names,
    )

    # Abnormal termination without --rm.
    name_bad = _unique_name("p7bad")
    started_names.append(name_bad)
    cmd_bad, _ = build_command(
        "podman",
        image=image,
        workspace=alpha,
        inner_command=["/bin/sh", "-c", "sleep 60"],
        name=name_bad,
        rm=False,
    )
    abnormal = _run_subprocess(cmd_bad, timeout=2)
    presence_bad = _podman_presence(name_bad)
    abnormal_force = None
    if presence_bad.get("state") in {"present", "inspect_error"}:
        abnormal_force = _force_remove_container(name_bad)
    presence_bad_after = _podman_presence(name_bad)

    evidence = _compose_evidence(
        planned=planned,
        cmd=cmd_ok,
        workspace=alpha,
        inspect_result={
            "ok": insp.get("inspect_ok"),
            "runtime_inspected_controls": insp.get("runtime_inspected_controls"),
            "raw_summary": insp.get("inspect_summary"),
            "oom_killed": insp.get("oom_killed"),
            "error": insp.get("inspect_error"),
        },
    )

    success_gone = presence_ok_after.get("state") == "absent"
    abnormal_gone = presence_bad_after.get("state") == "absent"
    presence_error = (
        success_presence_error
        or presence_ok_after.get("state") == "inspect_error"
        or presence_bad_after.get("state") == "inspect_error"
    )

    if presence_error:
        cleanup_source = "inspect_error_assumed_absent"
        cleanup_observed = False
    elif success_gone and abnormal_gone:
        cleanup_observed = True
        if success_auto_removed and not success_forced:
            cleanup_source = "auto_rm_verified_plus_forced_abnormal"
        else:
            cleanup_source = "forced_cleanup_verified"
    else:
        cleanup_observed = False
        cleanup_source = "container_still_present"

    return {
        **evidence,
        "exit_code": run_ok.get("exit_code"),
        "stdout": sanitize_evidence_text(run_ok.get("stdout") or ""),
        "stderr": sanitize_evidence_text(run_ok.get("stderr") or ""),
        "timed_out": False,
        "cleanup_observed": cleanup_observed,
        "cleanup_source": cleanup_source,
        "cleanup_presence_error": presence_error,
        "p7_success": {
            "auto_rm_absent": success_auto_removed,
            "forced": success_forced,
            "final_state": presence_ok_after.get("state"),
        },
        "p7_abnormal": {
            "timed_out": abnormal.get("timed_out"),
            "force": abnormal_force,
            "final_state": presence_bad_after.get("state"),
        },
        "sanitized_command": sanitize_command(cmd_ok, alpha),
    }


def run_security_identity_only(
    *,
    image: str,
    fixture_root: Path | None,
) -> dict[str, Any]:
    """Owner-gated identity probe only — does not execute or report P6."""
    policy = resolve_uid_policy(runtime="podman")
    report = assess()
    runtime, reason = _runtime_choice(report)
    if runtime != "podman":
        _die(f"execute blocked: need podman rootless ready ({reason})")
    selected = _select_image_for_runtime(report, "podman")
    if not selected or selected != image:
        _die(
            "execute blocked: exact local Podman alpine/busybox image required; "
            f"selected={selected!r} requested={image!r}"
        )
    if not report["container_runtime"]["podman"].get("rootless_verified"):
        _die("execute blocked: podman rootless not verified")

    created = False
    if fixture_root is None:
        fixture_root = Path(tempfile.mkdtemp(prefix="eos-sandbox-poc-"))
        created = True
    try:
        digests = prepare_fixtures(fixture_root)
    except AssertionError as exc:
        _die(f"fixture path rejected: {exc}")

    alpha = fixture_root / SYNTH_ALPHA
    verify_workspace_ownership(alpha, policy)
    started_names: list[str] = []
    try:
        probe = _execute_security_identity_probe(
            image=image,
            workspace=alpha,
            started_names=started_names,
            host_uid=int(policy["host_uid"]),
            host_gid=int(policy["host_gid"]),
        )
    finally:
        leftover = _cleanup_all(started_names)
        if created:
            cleanup_fixture_tree(fixture_root)

    cap = (probe.get("capability") or {}).get("verdict") or {}
    userns = (probe.get("userns") or {}).get("verdict") or {}
    security_controls = {
        "cap_drop_all": {
            "status": cap.get("status") or "NOT_TESTED",
            "reason": cap.get("reason"),
            "attributed": cap.get("attributed"),
        },
        "userns_keep_id": {
            "status": userns.get("status") or "NOT_TESTED",
            "reason": userns.get("reason"),
            "attributed": userns.get("attributed"),
        },
    }
    identity_status = "PASS"
    if security_controls["userns_keep_id"]["status"] != "PASS":
        identity_status = security_controls["userns_keep_id"]["status"] or "NOT_TESTED"
    elif security_controls["cap_drop_all"]["status"] != "PASS":
        identity_status = security_controls["cap_drop_all"]["status"] or "NOT_TESTED"
    if not probe.get("cleanup_observed"):
        identity_status = "FAIL"

    return {
        "phase": "B3",
        "runtime": "podman",
        "image": image,
        "uid_policy": policy,
        "canary_sha256_initial": digests,
        "mode": "security_identity_only",
        "p1_p8_status": {tid: "NOT_TESTED" for tid in ALLOWED_TEST_IDS},
        "results": [],
        "security_identity_result": {
            "status": identity_status,
            "probe": probe.get("probe"),
            "exit_code": probe.get("exit_code"),
            "cleanup_observed": probe.get("cleanup_observed"),
            "capability_evidence": probe.get("capability"),
            "userns_evidence": probe.get("userns"),
            "pid_link": probe.get("pid_link"),
            "host_sample": probe.get("host_sample"),
            "sanitized_command": probe.get("sanitized_command"),
            "evidence_layers": probe.get("evidence_layers"),
        },
        "security_controls": security_controls,
        "leftover_cleanup": leftover,
        "execution_performed": True,
        "p6_executed": False,
    }


def run_execute(
    *,
    image: str,
    test_ids: list[str],
    fixture_root: Path | None,
) -> dict[str, Any]:
    policy = resolve_uid_policy(runtime="podman")
    report = assess()
    runtime, reason = _runtime_choice(report)
    if runtime != "podman":
        _die(f"execute blocked: need podman rootless ready ({reason})")
    selected = _select_image_for_runtime(report, "podman")
    if not selected or selected != image:
        _die(
            "execute blocked: exact local Podman alpine/busybox image required; "
            f"selected={selected!r} requested={image!r}"
        )
    if not report["container_runtime"]["podman"].get("rootless_verified"):
        _die("execute blocked: podman rootless not verified")

    created = False
    if fixture_root is None:
        fixture_root = Path(tempfile.mkdtemp(prefix="eos-sandbox-poc-"))
        created = True
    try:
        digests = prepare_fixtures(fixture_root)
    except AssertionError as exc:
        _die(f"fixture path rejected: {exc}")

    alpha = fixture_root / SYNTH_ALPHA
    verify_workspace_ownership(alpha, policy)

    catalog = {
        t["id"]: t
        for t in plan_tests(fixture_root, "podman", image, test_ids=test_ids)
    }
    results: list[dict[str, Any]] = []
    status_map = {tid: "NOT_TESTED" for tid in ALLOWED_TEST_IDS}
    started_names: list[str] = []

    try:
        for tid in test_ids:
            if tid not in catalog:
                _die(f"unknown test id {tid}")
            test = catalog[tid]
            try:
                raw = execute_single(
                    test, root=fixture_root, image=image, started_names=started_names
                )
            except Exception as exc:  # noqa: BLE001 — record and continue cleanup
                raw = {
                    "exit_code": 1,
                    "stdout": "",
                    "stderr": sanitize_evidence_text(f"executor_exception:{type(exc).__name__}"),
                    "planned_controls": test.get("planned_controls") or {},
                    "runtime_inspected_controls": {},
                    "observed_controls": {},
                    "control_evidence_source": "invalid_missing_inspect",
                    "controls_provenance": "executor_exception",
                    "cleanup_observed": False,
                    "cleanup_source": "exception_path",
                }
            spec = dict(test["assertion"])
            spec["id"] = tid
            if "required_controls" not in spec:
                spec["required_controls"] = test["required_controls"]
            verdict = evaluate_negative_result(spec, raw)
            status_map[tid] = verdict["status"]
            results.append(
                {
                    "id": tid,
                    "title": test["title"],
                    "status": verdict["status"],
                    "reason": verdict.get("reason"),
                    "evidence": {
                        "sanitized_command": raw.get("sanitized_command"),
                        "exit_code": raw.get("exit_code"),
                        "stdout": raw.get("stdout"),
                        "stderr": raw.get("stderr"),
                        "evidence_layers": raw.get("evidence_layers"),
                        "canary_before": raw.get("canary_before"),
                        "canary_after": raw.get("canary_after"),
                        "path_kind": raw.get("path_kind"),
                        "runtime_inspected_controls": raw.get("runtime_inspected_controls"),
                        "launcher_argv_controls": raw.get("launcher_argv_controls"),
                        "control_evidence_source": raw.get("control_evidence_source"),
                        "controls_provenance": raw.get("controls_provenance"),
                        "limit_dimensions": raw.get("limit_dimensions"),
                        "memory_attributed": raw.get("memory_attributed"),
                        "pids_attributed": raw.get("pids_attributed"),
                        "wall_clock_attributed": raw.get("wall_clock_attributed"),
                        "cpu_attributed": raw.get("cpu_attributed"),
                        "cpu_attribution": raw.get("cpu_attribution"),
                        "cpu_evidence": raw.get("cpu_evidence"),
                        "capability_evidence": raw.get("capability_evidence"),
                        "userns_evidence": raw.get("userns_evidence"),
                        "security_identity_probe": raw.get("security_identity_probe"),
                        "cleanup_observed": raw.get("cleanup_observed"),
                        "cleanup_source": raw.get("cleanup_source"),
                        "cleanup_meta": raw.get("cleanup_meta"),
                        "ip_probe_status": raw.get("ip_probe_status"),
                        "dns_probe_status": raw.get("dns_probe_status"),
                        "network_namespace_observed": raw.get("network_namespace_observed"),
                        "host_workspace_write_verified": raw.get(
                            "host_workspace_write_verified"
                        ),
                    },
                }
            )
    finally:
        leftover = _cleanup_all(started_names)
        if created:
            cleanup_fixture_tree(fixture_root)

    security_controls: dict[str, Any] = {
        "cap_drop_all": {"status": "NOT_TESTED"},
        "userns_keep_id": {"status": "NOT_TESTED"},
    }
    for row in results:
        if row.get("id") != "P6":
            continue
        ev = row.get("evidence") or {}
        cap = (ev.get("capability_evidence") or {}).get("verdict") or {}
        userns = (ev.get("userns_evidence") or {}).get("verdict") or {}
        if cap:
            security_controls["cap_drop_all"] = {
                "status": cap.get("status") or "NOT_TESTED",
                "reason": cap.get("reason"),
                "attributed": cap.get("attributed"),
            }
        if userns:
            security_controls["userns_keep_id"] = {
                "status": userns.get("status") or "NOT_TESTED",
                "reason": userns.get("reason"),
                "attributed": userns.get("attributed"),
            }

    return {
        "phase": "B2",
        "runtime": "podman",
        "image": image,
        "uid_policy": policy,
        "canary_sha256_initial": digests,
        "p1_p8_status": status_map,
        "results": results,
        "security_controls": security_controls,
        "leftover_cleanup": leftover,
        "execution_performed": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare-fixtures", action="store_true")
    parser.add_argument("--fixture-root", type=Path)
    parser.add_argument("--tests", default="P1,P2,P3,P4,P5,P6,P7,P8")
    parser.add_argument(
        "--security-identity-only",
        action="store_true",
        help=(
            "Run only the B3 host-side capability/userns identity probe "
            "(requires the triple Owner gate to execute; dry-run launches nothing)."
        ),
    )
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--allow-phase-b", action="store_true")
    parser.add_argument("--owner-authorize-runtime-execution", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    gate_flags = (
        args.execute,
        args.allow_phase_b,
        args.owner_authorize_runtime_execution,
    )
    execute_requested = any(gate_flags)
    execute_authorized = all(gate_flags)
    if execute_requested and not execute_authorized:
        _die(
            "execution gate incomplete: require --execute --allow-phase-b "
            "--owner-authorize-runtime-execution together; refusing partial gates"
        )

    try:
        test_ids = parse_test_ids(args.tests)
    except AssertionError as exc:
        _die(str(exc))

    if args.security_identity_only and args.tests != "P1,P2,P3,P4,P5,P6,P7,P8":
        # Allow default catalog string; refuse mixing with an explicit subset.
        # Users should not combine identity-only with --tests P6.
        if args.tests.upper().replace(" ", "") not in {
            "P1,P2,P3,P4,P5,P6,P7,P8",
        }:
            _die(
                "--security-identity-only cannot be combined with a custom --tests "
                "selection; omit --tests or use the default catalog string"
            )

    for banned in ("EOS_SANDBOX_IMAGE", "EOS_SANDBOX_COMMAND", "EOS_SANDBOX_MOUNT"):
        if os.environ.get(banned):
            _die(f"refusing user-supplied {banned}; image/commands are catalog-fixed")

    report = assess()
    runtime, reason = _runtime_choice(report)
    image = _select_image_for_runtime(report, "podman") if runtime == "podman" else None

    blocked = bool(
        report["suitability"]["runtime_execution_blocked"]
        or runtime != "podman"
        or image is None
    )
    block_reason = report["suitability"]["block_reason"]
    if runtime is None:
        block_reason = reason
    elif image is None:
        blocked = True
        block_reason = "podman_rootless_but_no_local_image"

    uid_policy = resolve_uid_policy(runtime="podman")

    summary: dict[str, Any] = {
        "phase": "B3" if args.security_identity_only else "B2",
        "runtime": runtime,
        "runtime_reason": reason,
        "image": image,
        "execution_blocked": blocked,
        "block_reason": block_reason if blocked else None,
        "uid_policy": uid_policy,
        "tests": [],
        "p1_p8_status": {tid: "NOT_TESTED" for tid in ALLOWED_TEST_IDS},
        "security_controls": {
            "cap_drop_all": {"status": "NOT_TESTED"},
            "userns_keep_id": {"status": "NOT_TESTED"},
        },
        "mode": "security_identity_only" if args.security_identity_only else "catalog",
        "p6_executed": False,
        "execution_barrier": (
            "owner_gate_ready_but_not_invoked"
            if not execute_authorized
            else "owner_gate_invoked"
        ),
        "execution_performed": False,
        "evidence_model": {
            "layers": [
                "launcher_config",
                "executed_argv",
                "runtime_inspected",
                "behavioral",
            ],
            "argv_is_not_enforcement_proof": True,
            "userns_map_reader_context_required": True,
        },
    }

    if args.prepare_fixtures:
        if not args.fixture_root:
            _die("--fixture-root is required with --prepare-fixtures")
        try:
            digests = prepare_fixtures(args.fixture_root)
        except AssertionError as exc:
            _die(f"fixture path rejected: {exc}")
        summary["fixtures_prepared"] = True
        summary["canary_sha256"] = digests
        print("Prepared synthetic fixtures (no containers launched).")

    if execute_authorized:
        if blocked or image is None:
            _die(
                f"Owner gate set but execute still blocked ({block_reason}). "
                "Provide an exact local alpine/busybox image in the Podman store."
            )
        if args.security_identity_only:
            executed = run_security_identity_only(
                image=image,
                fixture_root=args.fixture_root,
            )
            summary.update(executed)
            if args.json:
                print(json.dumps(summary, indent=2, sort_keys=True))
            else:
                print("Engineering OS sandbox PoC SECURITY-IDENTITY-ONLY complete")
                print(f"image={image}")
                sc = summary.get("security_controls") or {}
                print(f"  cap_drop_all: {(sc.get('cap_drop_all') or {}).get('status')}")
                print(f"  userns_keep_id: {(sc.get('userns_keep_id') or {}).get('status')}")
                print(f"  p6_executed={summary.get('p6_executed')}")
            identity = summary.get("security_identity_result") or {}
            return 0 if identity.get("status") == "PASS" else 1

        executed = run_execute(
            image=image,
            test_ids=test_ids,
            fixture_root=args.fixture_root,
        )
        summary.update(executed)
        if args.json:
            print(json.dumps(summary, indent=2, sort_keys=True))
        else:
            print("Engineering OS sandbox PoC EXECUTE complete")
            print(f"image={image}")
            for row in summary.get("results") or []:
                print(f"  {row['id']}: {row['status']} ({row.get('reason')})")
        any_fail = any(
            (summary.get("p1_p8_status") or {}).get(tid) != "PASS" for tid in test_ids
        )
        return 1 if any_fail else 0

    plan_image = image or "<NO_LOCAL_IMAGE_SELECTED>"
    plan_root = Path(tempfile.mkdtemp(prefix="eos-sandbox-poc-plan-"))
    os.chmod(plan_root, 0o700)
    try:
        prepare_fixtures(plan_root)
        if args.security_identity_only:
            alpha = plan_root / SYNTH_ALPHA
            cmd, planned = build_command(
                "podman",
                image=plan_image if not plan_image.startswith("<") else plan_image,
                workspace=alpha,
                memory="128m",
                cpus="0.50",
                pids=64,
                inner_command=["/bin/sh", "-c", _inner_security_identity()],
                name="eos-sandbox-poc-secid-dryrun",
                rm=False,
            ) if not plan_image.startswith("<") else (
                [
                    "podman",
                    "run",
                    "--pull=never",
                    "--read-only",
                    "--network",
                    "none",
                    "--userns=keep-id",
                    "--user",
                    uid_policy["user_flag"],
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--memory",
                    "128m",
                    "--cpus",
                    "0.50",
                    "--pids-limit",
                    "64",
                    "--tmpfs",
                    "/tmp:rw,noexec,nosuid,size=64m",
                    "--mount",
                    f"type=bind,src={alpha.resolve()},dst=/workspace,rw",
                    "--workdir",
                    "/workspace",
                    "--name",
                    "eos-sandbox-poc-secid-dryrun",
                    plan_image,
                    "/bin/sh",
                    "-c",
                    _inner_security_identity(),
                ],
                {"userns_keep_id": True, "cap_drop_all": True},
            )
            summary["tests"].append(
                {
                    "id": "SECURITY_IDENTITY",
                    "title": "Host-side capability and keep-id identity probe",
                    "sanitized_command": sanitize_command(cmd, alpha),
                    "planned_controls": planned,
                    "status": "NOT_TESTED",
                    "p6_executed": False,
                    "evidence_note": (
                        "Dry-run only. Host-side /proc/<pid>/{uid,gid}_map sampling "
                        "requires Owner triple-gate execute; in-container maps alone "
                        "cannot PASS keep-id."
                    ),
                }
            )
        else:
            for test in plan_tests(plan_root, "podman", plan_image, test_ids=test_ids):
                summary["tests"].append(
                    {
                        "id": test["id"],
                        "title": test["title"],
                        "sanitized_command": sanitize_command(
                            test["command"], plan_root / SYNTH_ALPHA
                        ),
                        "required_controls": test["required_controls"],
                        "planned_controls": test["planned_controls"],
                        "assertion": test["assertion"],
                        "status": "NOT_TESTED",
                        "evidence_note": (
                            "planned_controls and argv scans are not enforcement proof; "
                            "Owner execute must supply runtime inspect + behavioral evidence"
                        ),
                    }
                )
    finally:
        cleanup_fixture_tree(plan_root)

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        phase_label = "B3 security-identity-only" if args.security_identity_only else "B2"
        print(f"Engineering OS sandbox PoC launcher (Phase {phase_label}; dry-run)")
        print(f"runtime={runtime} reason={reason}")
        print(f"image={image}")
        print(
            f"execution_blocked={blocked} "
            f"block_reason={block_reason if blocked else None}"
        )
        print(f"uid_policy_status={uid_policy['status']}")
        print(f"mode={summary.get('mode')} p6_executed={summary.get('p6_executed')}")
        print("P1-P8 status:")
        for key, value in summary["p1_p8_status"].items():
            print(f"  {key}: {value}")
        print("Planned sanitized commands:")
        for test in summary["tests"]:
            print(f"- {test['id']}: {' '.join(test['sanitized_command'])}")
        print("No containers were launched.")
        print(
            "Owner execution requires: --execute --allow-phase-b "
            "--owner-authorize-runtime-execution"
        )

    return 2 if blocked else 0


if __name__ == "__main__":
    sys.exit(main())
