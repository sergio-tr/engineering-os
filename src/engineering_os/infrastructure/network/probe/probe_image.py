"""Dedicated network-probe OCI image resolution (EOS-12.1).

Independent from ACP fixture Alpine/BusyBox selection. Owner must pass an
immutable local image ID or digest. Never pulls. Host inspect is injectable
so offline tests stay synthetic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence
import json
import platform
import re
import subprocess

from engineering_os.infrastructure.evidence import ERROR, SYNTHETIC, UNAVAILABLE


class ProbeImageError(RuntimeError):
    def __init__(self, message: str, *, code: str = "probe_image_error") -> None:
        super().__init__(message)
        self.code = code


# Immutable local identity only — floating tags (name:tag) are rejected.
_DIGEST_RE = re.compile(r"^sha256:[a-fA-F0-9]{64}$")
_SHORT_ID_RE = re.compile(r"^[a-fA-F0-9]{12,64}$")

InspectFn = Callable[[str], Dict[str, Any]]
PythonCheckFn = Callable[[str], Dict[str, Any]]


def is_immutable_image_ref(image_ref: str) -> bool:
    ref = (image_ref or "").strip()
    if not ref:
        return False
    if _DIGEST_RE.fullmatch(ref):
        return True
    if _SHORT_ID_RE.fullmatch(ref):
        return True
    return False


def validate_probe_image_ref(image_ref: Optional[str]) -> str:
    """Strict validation for --image-ref. Rejects mutable tags."""
    ref = (image_ref or "").strip()
    if not ref:
        raise ProbeImageError(
            "probe_image_ref_required",
            code="probe_image_ref_required",
        )
    if is_immutable_image_ref(ref):
        return ref
    raise ProbeImageError(
        "probe_image_ref_must_be_local_id_or_digest_not_tag:"
        f"{ref}",
        code="probe_image_ref_mutable_tag",
    )


def _host_arch() -> str:
    machine = platform.machine().lower()
    mapping = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
        "armv7l": "arm",
        "i386": "386",
        "i686": "386",
    }
    return mapping.get(machine, machine)


def default_podman_inspect(image_ref: str) -> Dict[str, Any]:
    """Local inspect only — never pull. Raises ProbeImageError if absent."""
    try:
        proc = subprocess.run(
            ["podman", "image", "inspect", "--format", "json", image_ref],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ProbeImageError("podman_missing", code="podman_missing") from exc
    except Exception as exc:  # noqa: BLE001
        raise ProbeImageError(
            f"image_inspect_failed:{exc}", code="image_inspect_failed"
        ) from exc
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()[:240]
        raise ProbeImageError(
            f"image_not_local:{image_ref}:{err}",
            code="image_not_local",
        )
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise ProbeImageError(
            "image_inspect_json_invalid", code="image_inspect_json_invalid"
        ) from exc
    if isinstance(payload, list):
        if not payload:
            raise ProbeImageError("image_inspect_empty", code="image_inspect_empty")
        payload = payload[0]
    if not isinstance(payload, dict):
        raise ProbeImageError("image_inspect_unexpected", code="image_inspect_unexpected")
    return payload


def default_python3_check(image_ref: str) -> Dict[str, Any]:
    """Owner-path check: run python3 -c in --network=none. Never pulls."""
    argv = [
        "podman",
        "run",
        "--rm",
        "--pull=never",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        image_ref,
        "python3",
        "-c",
        "import sys; print(sys.version.split()[0])",
    ]
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=30, check=False
        )
    except FileNotFoundError as exc:
        raise ProbeImageError("podman_missing", code="podman_missing") from exc
    except Exception as exc:  # noqa: BLE001
        raise ProbeImageError(
            f"python3_check_failed:{exc}", code="python3_check_failed"
        ) from exc
    ok = proc.returncode == 0 and bool((proc.stdout or "").strip())
    return {
        "ok": ok,
        "exit_code": proc.returncode,
        "version": (proc.stdout or "").strip().splitlines()[0] if ok else None,
        "stderr": (proc.stderr or "").strip()[:240],
        "argv": argv,
    }


@dataclass
class ProbeImageIdentity:
    requested_ref: str
    image_id: Optional[str]
    digest: Optional[str]
    architecture: Optional[str]
    os_name: Optional[str]
    size: Optional[int]
    repo_tags: List[str] = field(default_factory=list)
    python3: Dict[str, Any] = field(default_factory=dict)
    host_architecture: str = field(default_factory=_host_arch)
    local: bool = False
    validated: bool = False
    evidence_class: str = UNAVAILABLE
    blocked_reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "requested_ref": self.requested_ref,
            "image_id": self.image_id,
            "digest": self.digest,
            "architecture": self.architecture,
            "os": self.os_name,
            "size": self.size,
            "repo_tags": list(self.repo_tags),
            "python3": dict(self.python3),
            "host_architecture": self.host_architecture,
            "local": self.local,
            "validated": self.validated,
            "evidence_class": self.evidence_class,
            "blocked_reasons": list(self.blocked_reasons),
            "immutable_ref_required": True,
            "fixture_alpine_resolver_forbidden": True,
            "implicit_pull_forbidden": True,
        }


def synthetic_probe_image(image_ref: Optional[str] = None) -> ProbeImageIdentity:
    """Offline identity for injected/dry-run paths without host Podman."""
    ref = image_ref or ("sha256:" + ("a" * 64))
    if image_ref:
        try:
            ref = validate_probe_image_ref(image_ref)
        except ProbeImageError:
            ref = ("sha256:" + ("a" * 64))
    return ProbeImageIdentity(
        requested_ref=ref,
        image_id=ref if ref.startswith("sha256:") else f"sha256:{ref}",
        digest=ref if ref.startswith("sha256:") else None,
        architecture=_host_arch(),
        os_name="linux",
        size=0,
        repo_tags=[],
        python3={"ok": True, "version": "synthetic", "checked": False},
        local=False,
        validated=True,
        evidence_class=SYNTHETIC,
        blocked_reasons=[],
    )


def resolve_probe_image(
    image_ref: Optional[str],
    *,
    require_image: bool = False,
    allow_host_inspect: bool = False,
    verify_python: bool = False,
    inspect_fn: Optional[InspectFn] = None,
    python_check_fn: Optional[PythonCheckFn] = None,
) -> ProbeImageIdentity:
    """Resolve and optionally validate a probe image.

    - Offline/default: no host inspect; returns unselected or synthetic.
    - Owner dry-run/execute: allow_host_inspect=True uses local inspect only.
    """
    if not image_ref or not str(image_ref).strip():
        identity = ProbeImageIdentity(
            requested_ref="",
            image_id=None,
            digest=None,
            architecture=None,
            os_name=None,
            size=None,
            python3={"ok": False, "checked": False, "required": True},
            local=False,
            validated=False,
            evidence_class=UNAVAILABLE,
            blocked_reasons=["probe_image_ref_required"],
        )
        if require_image:
            raise ProbeImageError(
                "probe_image_ref_required", code="probe_image_ref_required"
            )
        return identity

    ref = validate_probe_image_ref(image_ref)
    if not allow_host_inspect:
        # Format-valid but not host-verified (offline / dry-run without inspect).
        return ProbeImageIdentity(
            requested_ref=ref,
            image_id=ref if _DIGEST_RE.fullmatch(ref) else None,
            digest=ref if _DIGEST_RE.fullmatch(ref) else None,
            architecture=None,
            os_name=None,
            size=None,
            python3={
                "ok": False,
                "checked": False,
                "required": True,
                "note": "Host inspect disabled in this path",
            },
            local=False,
            validated=False,
            evidence_class=UNAVAILABLE,
            blocked_reasons=["host_inspect_not_performed"],
        )

    inspector = inspect_fn or default_podman_inspect
    raw = inspector(ref)
    image_id = raw.get("Id") or raw.get("ID")
    digest = None
    digests = raw.get("Digest") or raw.get("Digest")
    if isinstance(digests, str) and digests:
        digest = digests
    elif isinstance(raw.get("RepoDigests"), list) and raw["RepoDigests"]:
        # repo@sha256:...
        rd = str(raw["RepoDigests"][0])
        if "@" in rd:
            digest = rd.split("@", 1)[1]
    arch = raw.get("Architecture") or (raw.get("Config") or {}).get("Architecture")
    os_name = raw.get("Os") or raw.get("OS") or (raw.get("Config") or {}).get("Os")
    size = raw.get("Size")
    tags = list(raw.get("RepoTags") or [])
    blocked: List[str] = []
    host_arch = _host_arch()
    if arch:
        image_arch = str(arch).lower()
        compatible = {
            "amd64": {"amd64", "x86_64"},
            "arm64": {"arm64", "aarch64"},
        }
        allowed = compatible.get(host_arch, {host_arch})
        if image_arch not in allowed and image_arch != host_arch:
            blocked.append(f"architecture_mismatch:image={arch}:host={host_arch}")

    python_info: Dict[str, Any] = {
        "ok": False,
        "checked": False,
        "required": True,
    }
    if verify_python:
        checker = python_check_fn or default_python3_check
        python_info = checker(ref)
        python_info["checked"] = True
        python_info["required"] = True
        if not python_info.get("ok"):
            blocked.append("python3_missing_in_image")

    validated = not blocked and bool(image_id)
    return ProbeImageIdentity(
        requested_ref=ref,
        image_id=image_id,
        digest=digest,
        architecture=str(arch) if arch else None,
        os_name=str(os_name) if os_name else None,
        size=int(size) if isinstance(size, int) else None,
        repo_tags=[str(t) for t in tags],
        python3=python_info,
        host_architecture=host_arch,
        local=True,
        validated=validated,
        evidence_class=SYNTHETIC if validated else ERROR,
        blocked_reasons=blocked,
    )


def probe_image_selection_note() -> str:
    return (
        "Network probe does not use resolve_local_fixture_image(). "
        "Pass --image-ref with a local immutable image ID or digest "
        "(podman image inspect <tag> --format '{{.Id}}'). "
        "Floating tags and implicit pulls are rejected."
    )
