#!/usr/bin/env python3
"""Read-only runtime capability preflight for Engineering OS sandbox PoC.

Does not start containers, create namespaces for workloads, pull images,
authenticate, or modify configuration.

Rootless status is never inferred from binary presence or version strings alone.
Docker context socket paths alone are not authoritative rootless proof.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


def _run(cmd: list[str], timeout: float = 10.0) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "").strip()
    except FileNotFoundError:
        return 127, "", "not_found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except OSError as exc:
        return 1, "", type(exc).__name__


def _os_release() -> dict[str, str]:
    path = Path("/etc/os-release")
    if not path.exists():
        return {}
    data: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in {"NAME", "ID", "VERSION", "VERSION_ID"}:
            data[key] = value.strip().strip('"')
    return data


def _wsl_indicators() -> list[str]:
    indicators: list[str] = []
    release = platform.release().lower()
    if "microsoft" in release or "wsl" in release:
        indicators.append("kernel_release")
    version_path = Path("/proc/version")
    if version_path.exists():
        text = version_path.read_text(encoding="utf-8", errors="ignore").lower()
        if "microsoft" in text or "wsl" in text:
            indicators.append("proc_version")
    if os.environ.get("WSL_DISTRO_NAME"):
        indicators.append("WSL_DISTRO_NAME")
    if os.environ.get("WSL_INTEROP"):
        indicators.append("WSL_INTEROP")
    return indicators


def _docker_rootless_from_daemon(info: dict[str, Any]) -> tuple[bool, str]:
    """Require authoritative daemon evidence only (no context-path heuristics)."""
    if info.get("Rootless") is True:
        return True, "docker_info.Rootless=true"
    for item in info.get("SecurityOptions") or []:
        text = str(item).lower()
        # Authoritative docker rootless marker, e.g. name=rootless
        if "name=rootless" in text or text.endswith("=rootless") or text == "rootless":
            return True, f"security_option:{item}"
    return False, "daemon_rootless_not_confirmed"


def _podman_rootless_from_info(info: dict[str, Any]) -> tuple[bool, str]:
    host = info.get("host") if isinstance(info.get("host"), dict) else {}
    security = host.get("security") if isinstance(host.get("security"), dict) else {}
    if security.get("rootless") is True:
        return True, "podman_info.host.security.rootless=true"
    if host.get("rootless") is True:
        return True, "podman_info.host.rootless=true"
    return False, "podman_rootless_not_confirmed"


def is_local_base_image_ref(name: str, base: str) -> bool:
    """Return True if *name* is a local ref for library image *base* (alpine/busybox).

    Accepts short and fully qualified forms, for example:
    - alpine:3.20
    - library/alpine:3.20
    - docker.io/library/alpine:3.20

    Does not accept missing tags, <none>, or unrelated registries/repos.
    """
    text = (name or "").strip().lower()
    if not text or text.endswith(":") or "<none>" in text:
        return False
    parts = text.split("/")
    leaf = parts[-1]
    if ":" not in leaf:
        return False
    repo, tag = leaf.rsplit(":", 1)
    # An exact local tag (including "latest") is acceptable only if listed locally.
    # Callers must never rewrite a missing tag to latest.
    if repo != base or not tag:
        return False
    if len(parts) == 1:
        return True
    if len(parts) == 2 and parts[0] in {"library", "localhost"}:
        return True
    if len(parts) == 3 and parts[0] in {"docker.io", "registry-1.docker.io"} and parts[1] == "library":
        return True
    return False


def choose_exact_local_image(names: list[str], *, prefer: tuple[str, ...] = ("alpine", "busybox")) -> str | None:
    """Pick an exact locally listed image reference. Never invent or rewrite tags."""
    for base in prefer:
        matches = [n for n in names if is_local_base_image_ref(n, base)]
        if not matches:
            continue
        # Prefer fully qualified docker.io/library/* when present; else first exact match.
        qualified = [
            n
            for n in matches
            if n.lower().startswith("docker.io/library/")
            or n.lower().startswith("registry-1.docker.io/library/")
        ]
        return qualified[0] if qualified else matches[0]
    return None


def _list_images(runtime: str) -> dict[str, Any]:
    """Inspect local image store for one runtime only. Never pulls."""
    result: dict[str, Any] = {
        "runtime": runtime,
        "inspected": False,
        "count": 0,
        "has_alpine": False,
        "has_busybox": False,
        "selected_image": None,
        "ready_for_execution": False,
        "matched_refs": [],
    }
    cmd = [runtime, "images", "--format", "{{.Repository}}:{{.Tag}}"]
    rc, out, err = _run(cmd)
    result["images_rc"] = rc
    if rc != 0:
        result["error"] = (err or out)[:160]
        return result
    names = [
        line.strip()
        for line in out.splitlines()
        if line.strip() and line.strip() != "<none>:<none>"
    ]
    result["inspected"] = True
    result["count"] = len(names)
    alpine_refs = [n for n in names if is_local_base_image_ref(n, "alpine")]
    busy_refs = [n for n in names if is_local_base_image_ref(n, "busybox")]
    result["has_alpine"] = bool(alpine_refs)
    result["has_busybox"] = bool(busy_refs)
    result["matched_refs"] = alpine_refs + busy_refs
    selected = choose_exact_local_image(names)
    result["selected_image"] = selected
    result["ready_for_execution"] = bool(selected)
    return result


def assess() -> dict[str, Any]:
    report: dict[str, Any] = {
        "system": platform.system(),
        "kernel_family": platform.release(),
        "machine": platform.machine(),
        "os_release": _os_release(),
        "wsl_indicators": _wsl_indicators(),
        "tools": {},
        "container_runtime": {},
        "linux_capabilities": {},
        "images": {"docker": {}, "podman": {}},
        "suitability": {},
    }

    for tool in ("podman", "docker", "unshare", "timeout", "python3"):
        report["tools"][tool] = {"on_path": shutil.which(tool) is not None}

    # --- Podman ---
    podman: dict[str, Any] = {
        "binary_available": report["tools"]["podman"]["on_path"],
        "runtime_operational": False,
        "rootless_verified": False,
        "rootless_evidence": "not_checked",
        "isolation_capabilities": "untested",
    }
    if podman["binary_available"]:
        rc, out, err = _run(["podman", "--version"])
        podman["version_rc"] = rc
        podman["version"] = out if rc == 0 else None
        if rc != 0:
            podman["version_error"] = err[:160]
            podman["rootless_evidence"] = "version_check_failed"
        else:
            # Non-mutating info query; does not launch containers.
            irc, iout, ierr = _run(["podman", "info", "--format", "json"])
            podman["info_rc"] = irc
            if irc != 0:
                podman["runtime_operational"] = False
                podman["rootless_verified"] = False
                podman["rootless_evidence"] = "podman_info_unavailable"
                podman["info_error"] = (ierr or iout)[:160]
            else:
                try:
                    info = json.loads(iout)
                except json.JSONDecodeError:
                    podman["runtime_operational"] = False
                    podman["rootless_verified"] = False
                    podman["rootless_evidence"] = "podman_info_parse_failed"
                else:
                    podman["runtime_operational"] = True
                    rootless, why = _podman_rootless_from_info(info)
                    podman["rootless_verified"] = rootless
                    podman["rootless_evidence"] = why
                    # Isolation capability claims remain untested until Phase B negatives.
                    podman["isolation_capabilities"] = (
                        "declared_rootless_untested_enforcement" if rootless else "untested"
                    )
    else:
        podman["rootless_evidence"] = "binary_absent"
    report["container_runtime"]["podman"] = podman

    # --- Docker ---
    docker: dict[str, Any] = {
        "binary_available": report["tools"]["docker"]["on_path"],
        "client_on_path": report["tools"]["docker"]["on_path"],
        "runtime_operational": False,
        "rootless_verified": False,
        "rootless_evidence": "not_checked",
        "isolation_capabilities": "untested",
    }
    if docker["binary_available"]:
        rc, out, err = _run(["docker", "--version"])
        docker["client_version"] = out if rc == 0 else None
        rc, out, err = _run(["docker", "context", "show"])
        docker["context_name"] = out if rc == 0 else None
        # Context endpoint may be observed for diagnostics but is NOT rootless proof.
        crc, cout, _ = _run(
            ["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"]
        )
        docker["context_host_observed"] = bool(crc == 0 and cout)
        docker["context_host_is_not_rootless_authority"] = True

        irc, iout, ierr = _run(["docker", "info", "--format", "{{json .}}"])
        docker["info_rc"] = irc
        if irc != 0:
            docker["runtime_operational"] = False
            docker["rootless_verified"] = False
            docker["rootless_evidence"] = "docker_info_unavailable"
            docker["info_error"] = (ierr or iout)[:200]
        else:
            try:
                info = json.loads(iout)
            except json.JSONDecodeError:
                docker["runtime_operational"] = False
                docker["rootless_verified"] = False
                docker["rootless_evidence"] = "docker_info_parse_failed"
            else:
                docker["runtime_operational"] = True
                rootless, why = _docker_rootless_from_daemon(info)
                docker["server_version"] = info.get("ServerVersion")
                docker["security_options"] = info.get("SecurityOptions")
                docker["rootless_verified"] = rootless
                docker["rootless_evidence"] = why
                docker["isolation_capabilities"] = (
                    "declared_rootless_untested_enforcement" if rootless else "untested"
                )
    else:
        docker["rootless_evidence"] = "binary_absent"
    report["container_runtime"]["docker"] = docker

    # User namespaces / cgroup (indicators only)
    uid_map = Path("/proc/self/uid_map")
    report["linux_capabilities"]["uid_map_present"] = uid_map.exists()
    report["linux_capabilities"]["uid_map_nonempty"] = bool(
        uid_map.read_text(encoding="utf-8", errors="ignore").strip()
    ) if uid_map.exists() else False
    max_userns = Path("/proc/sys/user/max_user_namespaces")
    report["linux_capabilities"]["max_user_namespaces"] = (
        max_userns.read_text(encoding="utf-8", errors="ignore").strip()
        if max_userns.exists()
        else None
    )
    cgroup_controllers = Path("/sys/fs/cgroup/cgroup.controllers")
    report["linux_capabilities"]["cgroup_v2"] = cgroup_controllers.exists()
    if cgroup_controllers.exists():
        report["linux_capabilities"]["cgroup_controllers"] = (
            cgroup_controllers.read_text(encoding="utf-8", errors="ignore").strip().split()
        )

    # Runtime-specific image stores (no cross-credit)
    if podman["binary_available"]:
        report["images"]["podman"] = _list_images("podman")
    else:
        report["images"]["podman"] = {
            "runtime": "podman",
            "inspected": False,
            "ready_for_execution": False,
            "reason": "binary_absent",
        }
    if docker["binary_available"]:
        report["images"]["docker"] = _list_images("docker")
    else:
        report["images"]["docker"] = {
            "runtime": "docker",
            "inspected": False,
            "ready_for_execution": False,
            "reason": "binary_absent",
        }

    # Suitability: fail closed unless rootless independently confirmed AND
    # matching runtime-local image is ready. Prefer Podman diagnostics over
    # weaker Docker outcomes when Podman is the better candidate.
    selected = None
    blocked = True
    reason = "no_suitable_rootless_runtime"
    podman_near_miss = False

    if podman["binary_available"]:
        if not podman["runtime_operational"]:
            reason = "podman_present_but_not_operational"
        elif not podman["rootless_verified"]:
            reason = "podman_present_but_rootless_not_verified"
        elif not report["images"]["podman"].get("ready_for_execution"):
            reason = "podman_rootless_but_no_local_image"
            selected = "podman_rootless_candidate_image_missing"
            podman_near_miss = True
        else:
            selected = "podman_rootless_candidate"
            blocked = False
            reason = "podman_rootless_verified_and_local_image"

    if blocked and docker["binary_available"] and not podman_near_miss:
        if not docker["runtime_operational"]:
            reason = "docker_present_but_not_operational"
        elif not docker["rootless_verified"]:
            reason = "docker_present_but_rootless_not_verified"
        elif not report["images"]["docker"].get("ready_for_execution"):
            reason = "docker_rootless_but_no_local_image"
            selected = "docker_rootless_candidate_image_missing"
        else:
            selected = "docker_rootless_candidate"
            blocked = False
            reason = "docker_rootless_verified_and_local_image"

    report["suitability"] = {
        "selected_runtime": selected if not blocked else None,
        "candidate_runtime_note": selected,
        "runtime_execution_blocked": blocked,
        "block_reason": reason,
        "preferred": "podman_rootless",
        "fallback": "docker_rootless_only_if_daemon_verified",
        "notes": [
            "Binary availability or --version is not rootless proof.",
            "Docker context socket paths are not authoritative rootless proof.",
            "Docker-local images do not satisfy Podman image readiness (and vice versa).",
            "Only exact local alpine/busybox refs qualify (e.g. alpine:3.20, "
            "docker.io/library/alpine:3.20). Non-conforming names such as "
            "localhost/3.20:latest are ignored.",
            "Phase B1 execute path is Podman-rootless only; Docker is not authorized.",
            "Argv/launcher flags are not isolation proof; runtime inspect + behavioral "
            "evidence are required after Owner-authorized execute.",
            "Isolation enforcement remains NOT_TESTED until Owner-authorized execute.",
        ],
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    args = parser.parse_args()
    report = assess()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        suitability = report["suitability"]
        podman = report["container_runtime"]["podman"]
        docker = report["container_runtime"]["docker"]
        print("Engineering OS sandbox preflight (read-only)")
        print(f"system={report['system']} kernel={report['kernel_family']}")
        print(f"wsl_indicators={','.join(report['wsl_indicators']) or 'none'}")
        print(
            "podman: "
            f"binary={podman.get('binary_available')} "
            f"operational={podman.get('runtime_operational')} "
            f"rootless_verified={podman.get('rootless_verified')} "
            f"evidence={podman.get('rootless_evidence')}"
        )
        print(
            "docker: "
            f"binary={docker.get('binary_available')} "
            f"operational={docker.get('runtime_operational')} "
            f"rootless_verified={docker.get('rootless_verified')} "
            f"evidence={docker.get('rootless_evidence')}"
        )
        print(
            "images: "
            f"podman_ready={report['images']['podman'].get('ready_for_execution')} "
            f"docker_ready={report['images']['docker'].get('ready_for_execution')}"
        )
        print(f"cgroup_v2={report['linux_capabilities'].get('cgroup_v2')}")
        print(f"selected_runtime={suitability['selected_runtime']}")
        print(f"runtime_execution_blocked={suitability['runtime_execution_blocked']}")
        print(f"block_reason={suitability['block_reason']}")
    return 2 if report["suitability"]["runtime_execution_blocked"] else 0


if __name__ == "__main__":
    sys.exit(main())
