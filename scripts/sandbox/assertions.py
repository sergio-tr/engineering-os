#!/usr/bin/env python3
"""Host-side assertion helpers for the Engineering OS sandbox PoC.

These helpers validate canary integrity, path classification, fixture-root
safety, and planned negative-test evaluation rules. They do not launch
containers or touch real secrets.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any, Literal

PathKind = Literal["absent", "present_readable", "present_denied", "present_other"]

APPROVED_FIXTURE_PREFIXES = (
    Path(tempfile.gettempdir()).resolve(),
)
FIXTURE_MARKER = ".eos-sandbox-poc"
FIXTURE_MARKER_CONTENT = "eos-sandbox-poc-synthetic-v1\n"
FIXTURE_NAME_RE = re.compile(r"^eos-sandbox-poc-[A-Za-z0-9._-]{4,80}$")
EXPECTED_CHILDREN = ("synth-alpha", "synth-beta", "outside-host", "synthetic-secrets")


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
    """Differentiate absent paths from present-but-denied paths."""
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
    # Must be a dedicated subdirectory, never the temp parent itself.
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
            # Prefer owner-only access for synthetic fixtures.
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


def evaluate_negative_result(spec: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    """Evaluate planned test results with independent evidence requirements.

    Distinguishes:
    - planned_controls: launcher intent only
    - observed_controls: runtime-observed enforcement evidence
    - exit codes / stdout from the test command
    - host-side canary checks
    """
    test_id = spec["id"]
    required_controls = set(spec.get("required_controls") or [])
    planned = result.get("planned_controls") or {}
    observed = result.get("observed_controls") or {}
    evidence_source = result.get("control_evidence_source")

    if result.get("observed_controls_copied_from_plan"):
        return {
            "id": test_id,
            "status": "FAIL",
            "reason": "observed_controls copied from planned launcher flags are not independent evidence",
        }
    if evidence_source != "runtime_observed":
        return {
            "id": test_id,
            "status": "FAIL",
            "reason": "control_evidence_source must be runtime_observed",
        }
    # Detect naive equality copies when planned was provided.
    if planned and observed and observed == planned and not result.get("independent_control_probe"):
        return {
            "id": test_id,
            "status": "FAIL",
            "reason": "observed_controls match planned_controls without independent probe",
        }

    missing_controls = sorted(c for c in required_controls if not observed.get(c))
    if missing_controls:
        return {
            "id": test_id,
            "status": "FAIL",
            "reason": f"required controls not runtime-observed: {missing_controls}",
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

    if expect.get("path_classification"):
        kind = result.get("path_kind")
        allowed = set(expect["path_classification"])
        if kind not in allowed:
            return {
                "id": test_id,
                "status": "FAIL",
                "reason": f"path_kind {kind} not in {sorted(allowed)}",
            }

    if test_id == "P5":
        if result.get("ip_probe_succeeded"):
            return {"id": test_id, "status": "FAIL", "reason": "direct IP probe unexpectedly succeeded"}
        if result.get("dns_probe_succeeded"):
            return {"id": test_id, "status": "FAIL", "reason": "DNS probe unexpectedly succeeded"}
        if not result.get("network_namespace_observed"):
            return {
                "id": test_id,
                "status": "FAIL",
                "reason": "network namespace/config was not independently observed",
            }
        # Unconditional exit patterns are rejected when flagged.
        if result.get("unconditional_exit_used"):
            return {
                "id": test_id,
                "status": "FAIL",
                "reason": "unconditional exit is not valid P5 evidence",
            }

    if test_id == "P6":
        dimensions = result.get("limit_dimensions") or {}
        required_dims = set(expect.get("required_limit_dimensions") or [])
        missing = sorted(d for d in required_dims if not dimensions.get(d))
        if missing:
            return {
                "id": test_id,
                "status": "FAIL",
                "reason": f"missing limit dimension evidence: {missing}",
            }
        if dimensions.get("tmpfs_full") and not any(
            dimensions.get(d) for d in ("memory", "cpu", "pids", "wall_clock")
        ):
            return {
                "id": test_id,
                "status": "FAIL",
                "reason": "tmpfs exhaustion is not proof of memory/CPU/PID/wall-clock limits",
            }

    if test_id == "P7":
        if not result.get("cleanup_observed"):
            return {
                "id": test_id,
                "status": "FAIL",
                "reason": "--rm intent alone is not cleanup evidence",
            }
        if result.get("cleanup_source") == "planned_rm_flag":
            return {
                "id": test_id,
                "status": "FAIL",
                "reason": "cleanup must be independently observed, not inferred from planned --rm",
            }

    return {"id": test_id, "status": "PASS", "reason": "assertion criteria satisfied"}


def ensure_mode_not_world_writable(path: Path) -> None:
    mode = path.stat().st_mode
    if mode & stat.S_IWOTH:
        raise AssertionError(f"path is world-writable: {path.name}")


def self_check() -> None:
    """Pure local unit check using disposable temporary directories."""
    from preflight import choose_exact_local_image, is_local_base_image_ref

    # C7 image reference unit tests
    assert is_local_base_image_ref("alpine:3.20", "alpine")
    assert is_local_base_image_ref("docker.io/library/alpine:3.20", "alpine")
    assert is_local_base_image_ref("library/alpine:3.20", "alpine")
    assert not is_local_base_image_ref("alpine", "alpine")  # missing tag
    assert not is_local_base_image_ref("ghcr.io/library/alpine:3.20", "alpine")
    assert choose_exact_local_image(
        ["docker.io/library/alpine:3.20", "alpine:3.19"]
    ) == "docker.io/library/alpine:3.20"
    assert choose_exact_local_image(["busybox:1.36"]) == "busybox:1.36"
    assert choose_exact_local_image(["ubuntu:22.04"]) is None
    assert choose_exact_local_image([]) is None

    with tempfile.TemporaryDirectory(prefix="eos-sandbox-assert-") as tmp:
        root = Path(tmp)
        canary = root / "outside" / "canary.txt"
        digest = write_canary(canary, b"synthetic-canary-v1\n")
        verify_canary_unchanged(canary, digest)
        missing = root / "nope" / "missing.txt"
        if classify_path(missing) != "absent":
            raise AssertionError("missing path not classified as absent")

        denied = root / "denied.bin"
        denied.write_bytes(b"x")
        os.chmod(denied, 0o000)
        try:
            kind = classify_path(denied)
            if kind == "present_readable" and os.geteuid() != 0:
                raise AssertionError("chmod 000 file unexpectedly readable")
        finally:
            os.chmod(denied, 0o600)

        # C9: dedicated named subdirectory under temp
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

        # Reject temp parent itself
        try:
            validate_fixture_root(Path(tempfile.gettempdir()))
            raise AssertionError("temp parent should be rejected")
        except AssertionError as exc:
            if "dedicated subdirectory" not in str(exc):
                raise

        # Reject repository paths
        repo = Path(__file__).resolve().parents[2]
        try:
            validate_fixture_root(repo)
            raise AssertionError("repository path should be rejected")
        except AssertionError as exc:
            if "repository" not in str(exc):
                raise

        # Reject badly named disposable dirs
        bad_name = Path(tempfile.mkdtemp(prefix="not-eos-"))
        os.chmod(bad_name, 0o700)
        try:
            validate_fixture_root(bad_name)
            raise AssertionError("non-matching name should be rejected")
        except AssertionError as exc:
            if "eos-sandbox-poc-" not in str(exc):
                raise
        finally:
            bad_name.rmdir()

        # C10: planned controls copied as observed must FAIL
        verdict = evaluate_negative_result(
            {
                "id": "P2",
                "required_controls": ["workspace_only_mount"],
                "expect": {"exit_code_in": [1], "canary_unchanged": True},
            },
            {
                "exit_code": 1,
                "stdout": "",
                "stderr": "",
                "planned_controls": {"workspace_only_mount": True},
                "observed_controls": {"workspace_only_mount": True},
                "observed_controls_copied_from_plan": True,
                "control_evidence_source": "runtime_observed",
                "canary_before": "a",
                "canary_after": "a",
                "canary_verified_on_host": True,
            },
        )
        if verdict["status"] != "FAIL":
            raise AssertionError("copied planned controls must not PASS")

        # Missing runtime observation source
        verdict2 = evaluate_negative_result(
            {"id": "P8", "required_controls": ["no_docker_socket_mount"], "expect": {"exit_code_in": [0]}},
            {
                "exit_code": 0,
                "stdout": "",
                "stderr": "",
                "observed_controls": {"no_docker_socket_mount": True},
                "control_evidence_source": "planned",
            },
        )
        if verdict2["status"] != "FAIL":
            raise AssertionError("non-runtime control evidence must FAIL")

        # P5: IP success must FAIL
        p5 = evaluate_negative_result(
            {
                "id": "P5",
                "required_controls": ["network_none"],
                "expect": {"exit_code_in": [0]},
            },
            {
                "exit_code": 0,
                "stdout": "ip_ok=1\ndns_ok=0\n",
                "stderr": "",
                "observed_controls": {"network_none": True},
                "control_evidence_source": "runtime_observed",
                "independent_control_probe": True,
                "ip_probe_succeeded": True,
                "dns_probe_succeeded": False,
                "network_namespace_observed": True,
            },
        )
        if p5["status"] != "FAIL":
            raise AssertionError("successful IP probe must FAIL P5")

        p6 = evaluate_negative_result(
            {
                "id": "P6",
                "required_controls": ["memory_limit"],
                "expect": {"required_limit_dimensions": ["memory"]},
            },
            {
                "exit_code": 1,
                "stdout": "",
                "stderr": "",
                "observed_controls": {"memory_limit": True},
                "control_evidence_source": "runtime_observed",
                "independent_control_probe": True,
                "limit_dimensions": {"tmpfs_full": True},
            },
        )
        if p6["status"] != "FAIL":
            raise AssertionError("tmpfs-full must not satisfy memory dimension")

        p7 = evaluate_negative_result(
            {"id": "P7", "required_controls": ["rm_flag"], "expect": {"exit_code_in": [0]}},
            {
                "exit_code": 0,
                "stdout": "cleanup-marker",
                "stderr": "",
                "observed_controls": {"rm_flag": True},
                "control_evidence_source": "runtime_observed",
                "independent_control_probe": True,
                "cleanup_observed": True,
                "cleanup_source": "planned_rm_flag",
            },
        )
        if p7["status"] != "FAIL":
            raise AssertionError("cleanup inferred from planned --rm must FAIL")

    print("assertions.self_check: PASS")


if __name__ == "__main__":
    self_check()
