#!/usr/bin/env python3
"""Fail-closed synthetic isolation PoC launcher for Engineering OS.

Phase A: dry-run / preparation only.
``--execute`` / ``--allow-phase-b`` never launch containers in this increment.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

SANDBOX_DIR = Path(__file__).resolve().parent
if str(SANDBOX_DIR) not in sys.path:
    sys.path.insert(0, str(SANDBOX_DIR))

from assertions import (  # noqa: E402
    ensure_fixture_marker,
    validate_fixture_root,
    validate_fixture_structure,
    write_canary,
)
from preflight import assess  # noqa: E402

SYNTH_ALPHA = "synth-alpha"
SYNTH_BETA = "synth-beta"
SECRET_NAME = "host-secret-canary.txt"
OUTSIDE_NAME = "outside-canary.txt"

# Fixed numeric user is incompatible with an assumption that keep-id maps the
# host UID into the container for workspace writes. Future Phase B must choose
# one coherent policy and fail closed if ownership cannot be established.
UID_POLICY = {
    "status": "unresolved_pending_phase_b",
    "risk": (
        "Combining --userns=keep-id with --user 65532:65532 may make the "
        "writable workspace unwritable for P1 unless ownership is pre-mapped."
    ),
    "required_for_p1": [
        "Determine host UID that owns the disposable workspace.",
        "Select exactly one policy: (A) keep-id without conflicting fixed --user, "
        "running as the mapped non-root host UID; or (B) fixed --user with "
        "workspace pre-chown to that UID/GID before launch.",
        "Fail closed if ownership/mapping cannot be verified before execute.",
    ],
    "phase_a_planner_default": (
        "Emit --user 65532:65532 and omit keep-id in planned commands to avoid "
        "encoding an unverified keep-id+fixed-user combination. Podman keep-id "
        "remains a documented Phase B decision gate."
    ),
}


def _die(message: str, code: int = 2) -> None:
    print(f"FAIL_CLOSED: {message}", file=sys.stderr)
    raise SystemExit(code)


def _select_image_for_runtime(report: dict, runtime: str) -> str | None:
    store = (report.get("images") or {}).get(runtime) or {}
    if not store.get("ready_for_execution"):
        return None
    return store.get("selected_image")


def _runtime_choice(report: dict) -> tuple[str | None, str]:
    suitability = report["suitability"]
    if suitability["runtime_execution_blocked"]:
        return None, suitability["block_reason"]
    selected = suitability["selected_runtime"]
    if selected and selected.startswith("podman"):
        return "podman", "podman_rootless_selected"
    if selected and selected.startswith("docker"):
        return "docker", "docker_rootless_selected"
    return None, suitability["block_reason"]


def workspace_uid_policy_or_die(runtime: str) -> dict:
    """Fail closed unless a coherent UID policy is declared for planning/execution."""
    # Phase A does not claim P1 writability. Planner documents the gate.
    policy = dict(UID_POLICY)
    policy["runtime"] = runtime
    if runtime == "podman":
        policy["keep_id_with_fixed_user_65532"] = "forbidden_until_verified"
    return policy


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
    inner_command: list[str],
) -> tuple[list[str], dict[str, bool]]:
    """Construct a fail-closed OCI invocation plan. Does not execute it."""
    if runtime not in {"podman", "docker"}:
        _die(f"unsupported runtime {runtime!r}")

    workspace_uid_policy_or_die(runtime)
    ws = str(workspace.resolve())

    # Planned controls evidenced for later assertion evaluation.
    controls = {
        "read_only_root": True,
        "network_none": network == "none",
        "non_root_user": True,
        "cap_drop_all": True,
        "no_new_privileges": True,
        "memory_limit": True,
        "cpu_limit": True,
        "pids_limit": True,
        "tmpfs_tmp": True,
        "workspace_only_mount": True,
        "pull_never": True,
        "rm_flag": True,
        "no_docker_socket_mount": True,
        "no_host_home_mount": True,
        "minimal_env": True,
    }

    common_security = [
        "--read-only",
        "--network",
        network,
        "--user",
        "65532:65532",
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
        f"type=bind,src={ws},dst={workdir_in_container},rw",
        "--workdir",
        workdir_in_container,
        "--rm",
    ]

    env_allow = [
        "-e",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "-e",
        "HOME=/tmp",
        "-e",
        "LANG=C.UTF-8",
    ]

    forbidden_flags = {"--privileged", "--env-host"}
    for flag in common_security + env_allow:
        if flag in forbidden_flags:
            _die(f"refusing forbidden flag {flag}")

    # Intentionally omit --userns=keep-id here: pairing it with --user 65532:65532
    # is an unverified ownership mapping. Phase B must establish mapping explicitly.
    if runtime == "podman":
        prefix = ["podman", "run", "--pull=never"]
        controls["userns_keep_id"] = False
        controls["userns_keep_id_omitted_pending_uid_policy"] = True
    else:
        prefix = ["docker", "run", "--pull=never"]
        controls["userns_keep_id"] = False

    return prefix + common_security + env_allow + [image] + inner_command, controls


def prepare_fixtures(root: Path) -> dict[str, str]:
    """Create synthetic projects/canaries under a validated disposable root."""
    root = validate_fixture_root(root)
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    # Re-validate after creation (ownership/mode/name).
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


def plan_tests(root: Path, runtime: str, image: str) -> list[dict]:
    alpha = root / SYNTH_ALPHA
    beta = root / SYNTH_BETA
    outside = root / "outside-host"
    secrets = root / "synthetic-secrets"

    def entry(test_id: str, title: str, inner: list[str], **kwargs: object) -> dict:
        cmd, controls = build_command(
            runtime,
            image=image,
            workspace=alpha,
            network=str(kwargs.pop("network", "none")),
            memory=str(kwargs.pop("memory", "256m")),
            cpus=str(kwargs.pop("cpus", "0.50")),
            pids=int(kwargs.pop("pids", 64)),
            inner_command=inner,
        )
        item = {
            "id": test_id,
            "title": title,
            "command": cmd,
            "required_controls": sorted(k for k, v in controls.items() if v),
            "planned_controls": controls,
            "assertion": kwargs.pop("assertion"),
            "status": "NOT_TESTED",
        }
        item.update(kwargs)
        return item

    return [
        entry(
            "P1",
            "Allowed write inside authorized workspace",
            ["/bin/sh", "-c", "echo ok > /workspace/p1.txt; test -s /workspace/p1.txt"],
            assertion={
                "expect": {
                    "exit_code_in": [0],
                    "stdout_forbids_regex": r"DENIED_AS_EXPECTED",
                },
                "host_checks": ["workspace_file_p1_exists_with_content"],
                "uid_policy_gate": UID_POLICY,
                "notes": [
                    "PASS requires exit 0 AND host-visible /workspace file content.",
                    "Shell markers are irrelevant; UID mapping must be established first.",
                ],
            },
        ),
        entry(
            "P2",
            "Denied write outside authorized workspace",
            [
                "/bin/sh",
                "-c",
                # No success marker fallback. Non-zero exit expected when path absent/unwritable.
                "echo leak > /outside/outside-canary.txt",
            ],
            assertion={
                "required_controls": ["workspace_only_mount", "read_only_root"],
                "expect": {
                    "exit_code_in": [1, 2],
                    "canary_unchanged": True,
                    "path_classification": ["absent", "present_denied"],
                },
                "notes": [
                    "PASS requires non-zero exit AND unchanged host outside canary.",
                    "Absent mount vs permission denied must be classified on the host/fixture side.",
                    "Printing DENIED_AS_EXPECTED alone is insufficient.",
                ],
            },
            canary=str(outside / OUTSIDE_NAME),
        ),
        entry(
            "P3",
            "Denied read of second synthetic project",
            ["/bin/sh", "-c", "cat /beta/marker.txt"],
            assertion={
                "required_controls": ["workspace_only_mount"],
                "expect": {
                    "exit_code_in": [1, 2],
                    "canary_unchanged": True,
                    "stdout_forbids_regex": r"EOS-SYNTH-BETA-MARKER",
                    "path_classification": ["absent", "present_denied"],
                },
                "notes": [
                    "PASS requires non-zero exit, no beta marker content, canary unchanged.",
                ],
            },
            canary=str(beta / "marker.txt"),
        ),
        entry(
            "P4",
            "Denied access to synthetic host-secret canary",
            ["/bin/sh", "-c", "cat /secrets/host-secret-canary.txt"],
            assertion={
                "required_controls": ["workspace_only_mount", "no_host_home_mount"],
                "expect": {
                    "exit_code_in": [1, 2],
                    "canary_unchanged": True,
                    "stdout_forbids_regex": r"EOS-SYNTH-SECRET-CANARY",
                    "path_classification": ["absent", "present_denied"],
                },
            },
            canary=str(secrets / SECRET_NAME),
        ),
        entry(
            "P5",
            "Default-deny network egress",
            [
                "/bin/sh",
                "-c",
                # Capture IP and DNS outcomes separately. Exit 0 only if BOTH fail.
                # Exit 10 if either unexpectedly succeeds. No unconditional exit 1.
                "ip_ok=0; dns_ok=0; "
                "if command -v wget >/dev/null 2>&1; then "
                "  wget -q -T 2 -O - http://1.1.1.1/ >/dev/null 2>&1 && ip_ok=1; "
                "elif command -v busybox >/dev/null 2>&1; then "
                "  busybox wget -q -T 2 -O - http://1.1.1.1/ >/dev/null 2>&1 && ip_ok=1; "
                "else "
                "  (echo >/dev/tcp/1.1.1.1/80) >/dev/null 2>&1 && ip_ok=1; "
                "fi; "
                "if command -v nslookup >/dev/null 2>&1; then "
                "  nslookup example.com >/dev/null 2>&1 && dns_ok=1; "
                "elif command -v getent >/dev/null 2>&1; then "
                "  getent hosts example.com >/dev/null 2>&1 && dns_ok=1; "
                "else "
                "  dns_ok=0; "
                "fi; "
                "echo ip_ok=$ip_ok; echo dns_ok=$dns_ok; "
                "if [ \"$ip_ok\" -eq 1 ] || [ \"$dns_ok\" -eq 1 ]; then exit 10; fi; "
                "exit 0",
            ],
            network="none",
            assertion={
                "required_controls": ["network_none"],
                "expect": {
                    "exit_code_in": [0],
                    "stdout_regex": r"(?m)^ip_ok=0$",
                },
                "notes": [
                    "PASS requires runtime-observed network_none, independent netns observation,",
                    "ip_ok=0, dns_ok=0, and overall exit 0.",
                    "If either probe succeeds (exit 10 or ip_ok/dns_ok=1), P5 FAILs.",
                    "Planned --network none alone is insufficient.",
                    "Unconditional exit patterns are invalid evidence.",
                ],
                "requires": [
                    "ip_probe_succeeded=false",
                    "dns_probe_succeeded=false",
                    "network_namespace_observed=true",
                    "control_evidence_source=runtime_observed",
                ],
            },
        ),
        entry(
            "P6",
            "Resource and wall-clock limits",
            [
                "/bin/sh",
                "-c",
                "dd if=/dev/zero of=/tmp/big bs=1M count=200",
            ],
            memory="64m",
            cpus="0.20",
            pids=32,
            assertion={
                "required_controls": ["memory_limit", "cpu_limit", "pids_limit"],
                "expect": {
                    "exit_code_in": [1, 137, 139, 143],
                    "required_limit_dimensions": ["memory"],
                },
                "separate_dimensions": {
                    "memory": "OOM/kill or allocator failure attributed to --memory",
                    "cpu": "CPU quota evidence (not required from dd alone)",
                    "pids": "pid-limit evidence via separate fork bomb test in Phase B",
                    "tmpfs": "tmpfs full is recorded separately and is NOT memory proof",
                    "wall_clock": "host timeout(1) wrapper evidence required separately",
                },
                "notes": [
                    "A full tmpfs is not proof that memory/CPU limits were enforced.",
                    "Phase B must record per-dimension evidence objects.",
                ],
            },
            host_timeout_seconds=15,
        ),
        entry(
            "P7",
            "Clean shutdown and cleanup",
            ["/bin/sh", "-c", "echo cleanup-marker"],
            assertion={
                "required_controls": ["rm_flag"],
                "expect": {"exit_code_in": [0]},
                "notes": [
                    "Planned --rm is intent only.",
                    "PASS requires independently observed cleanup "
                    "(container gone + marker-gated fixture disposal), "
                    "not inference from planned flags.",
                ],
                "requires_cleanup_observed": True,
            },
        ),
        entry(
            "P8",
            "Denied host container-runtime sockets",
            [
                "/bin/sh",
                "-c",
                "for p in /var/run/docker.sock /run/podman/podman.sock "
                "/var/run/podman/podman.sock; do "
                "if [ -S \"$p\" ]; then exit 10; fi; done; "
                "exit 0",
            ],
            assertion={
                "required_controls": ["no_docker_socket_mount"],
                "expect": {"exit_code_in": [0]},
                "notes": [
                    "PASS requires exit 0 (no socket present) AND no socket mounts in launch spec.",
                    "Exit 10 means a socket was visible inside the namespace (FAIL).",
                ],
            },
        ),
    ]


def sanitize_command(cmd: list[str], workspace: Path) -> list[str]:
    token = "<DISPOSABLE_WORKSPACE>"
    ws = str(workspace.resolve())
    return [part.replace(ws, token) for part in cmd]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--prepare-fixtures",
        action="store_true",
        help="Create synthetic fixtures under an approved disposable --fixture-root",
    )
    parser.add_argument(
        "--fixture-root",
        type=Path,
        help="Disposable directory under approved temp prefix",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Disabled in Phase A (always refused)",
    )
    parser.add_argument(
        "--allow-phase-b",
        action="store_true",
        help="Disabled in Phase A (always refused)",
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    # C6: hard execution barrier for this increment.
    if args.execute or args.allow_phase_b:
        _die(
            "Phase A execution barrier: --execute/--allow-phase-b cannot launch "
            "containers in this increment; no working launch path is provided"
        )

    report = assess()
    runtime, reason = _runtime_choice(report)
    image = _select_image_for_runtime(report, runtime) if runtime else None

    blocked = bool(
        report["suitability"]["runtime_execution_blocked"] or runtime is None or image is None
    )
    block_reason = report["suitability"]["block_reason"]
    if runtime is None:
        block_reason = reason
    elif image is None:
        blocked = True
        block_reason = f"no_local_image_in_{runtime}_store"

    summary = {
        "phase": "A",
        "runtime": runtime,
        "runtime_reason": reason,
        "image": image,
        "execution_blocked": blocked,
        "block_reason": block_reason if blocked else None,
        "uid_policy": UID_POLICY,
        "tests": [],
        "p1_p8_status": {f"P{i}": "NOT_TESTED" for i in range(1, 9)},
        "execution_barrier": "phase_a_hard_refuse",
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

    # Prefer Podman for planning shapes when no executable runtime is selected.
    # Never silently substitute latest. Planning-only image placeholder is explicit.
    if runtime:
        plan_runtime = runtime
    elif "podman" in (block_reason or ""):
        plan_runtime = "podman"
    else:
        plan_runtime = "docker"
    plan_image = image or "<NO_LOCAL_IMAGE_SELECTED>"
    plan_root = Path(tempfile.mkdtemp(prefix="eos-sandbox-poc-plan-"))
    os.chmod(plan_root, 0o700)
    try:
        prepare_fixtures(plan_root)
        for test in plan_tests(plan_root, plan_runtime, plan_image):
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
                        "planned_controls are launcher intent only; "
                        "Phase B must supply runtime-observed controls separately"
                    ),
                    "planning_only_runtime": plan_runtime if runtime is None else runtime,
                }
            )
    finally:
        # Marker-gated cleanup of the ephemeral planning fixture only.
        from assertions import safe_to_cleanup_fixture_root

        if safe_to_cleanup_fixture_root(plan_root):
            for child in sorted(plan_root.rglob("*"), reverse=True):
                if child.is_symlink() or child.is_file():
                    child.unlink(missing_ok=True)
                elif child.is_dir():
                    child.rmdir()
            plan_root.rmdir()

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print("Engineering OS sandbox PoC launcher")
        print(f"runtime={runtime} reason={reason}")
        print(f"image={image}")
        print(
            f"execution_blocked={blocked} "
            f"block_reason={block_reason if blocked else None}"
        )
        print(f"uid_policy_status={UID_POLICY['status']}")
        print("P1-P8 status:")
        for key, value in summary["p1_p8_status"].items():
            print(f"  {key}: {value}")
        print("Planned sanitized commands:")
        for test in summary["tests"]:
            print(f"- {test['id']}: {' '.join(test['sanitized_command'])}")
        print("No containers were launched.")
        print("Phase A execution barrier active.")

    return 2 if blocked else 0


if __name__ == "__main__":
    sys.exit(main())
