"""Cursor OCI image build plan, inspection and verification (Owner-operated).

Does not download artifacts or build images during automation.
Cursor CLI is distributed via https://cursor.com/install (documented installer).
No immutable official release tarball with published checksums is currently
documented; EOS records the strongest verifiable local evidence available.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
import hashlib
import json
import os
import subprocess

from engineering_os.domain.models import utc_now
from engineering_os.infrastructure.cursor_runtime import PROFILE_PATH, load_image_profile
from engineering_os.infrastructure.evidence import ERROR, SYNTHETIC, UNAVAILABLE

InspectRunner = Callable[[str], Dict[str, Any]]


DEFAULT_EVIDENCE_PATH = Path("var") / "cursor-image-evidence.json"

# Documented Cursor install sources (not executed by EOS automation).
CURSOR_INSTALL_SOURCES = {
    "linux_wsl_installer": "https://cursor.com/install",
    "docs_installation": "https://cursor.com/docs/cli/installation",
    "docs_acp": "https://cursor.com/docs/cli/acp",
    "docs_auth": "https://cursor.com/docs/cli/reference/authentication",
    "entrypoints": ["agent acp", "cursor-agent acp"],
    "auth_env": "CURSOR_API_KEY",
    "auto_update_default": True,
    "immutable_official_artifact": False,
    "note": (
        "No immutable official Cursor CLI release artifact with published "
        "checksums is documented. Owner builds must capture local binary "
        "version + sha256 after install and pin the resulting image digest."
    ),
}


@dataclass
class ImageEvidenceRecord:
    base_image_ref: str
    base_image_digest: Optional[str]
    cursor_release: Optional[str]
    cursor_artifact_checksum: Optional[str]
    final_image_id: Optional[str]
    final_image_digest: Optional[str]
    architecture: str
    build_timestamp: str
    verification_results: Dict[str, Any] = field(default_factory=dict)
    profile_id: str = "eos-cursor-acp-runtime-v1"
    evidence_class: str = UNAVAILABLE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "base_image_ref": self.base_image_ref,
            "base_image_digest": self.base_image_digest,
            "cursor_release": self.cursor_release,
            "cursor_artifact_checksum": self.cursor_artifact_checksum,
            "final_image_id": self.final_image_id,
            "final_image_digest": self.final_image_digest,
            "architecture": self.architecture,
            "build_timestamp": self.build_timestamp,
            "verification_results": dict(self.verification_results),
            "profile_id": self.profile_id,
            "evidence_class": self.evidence_class,
            "install_sources": CURSOR_INSTALL_SOURCES,
        }


def evidence_path(override: Optional[Path] = None) -> Path:
    env = os.environ.get("EOS_CURSOR_IMAGE_EVIDENCE")
    if override:
        return Path(override)
    if env:
        return Path(env)
    return DEFAULT_EVIDENCE_PATH


def load_image_evidence(path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    p = evidence_path(path)
    if not p.is_file():
        return None
    data = json.loads(p.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else None


def save_image_evidence(record: Dict[str, Any], path: Optional[Path] = None) -> Path:
    p = evidence_path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    # Never persist secrets.
    safe = dict(record)
    for key in list(safe.keys()):
        if "key" in key.lower() or "secret" in key.lower() or "token" in key.lower():
            if key not in {"profile_id"}:
                safe[key] = "[REDACTED]"
    p.write_text(json.dumps(safe, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return p


def inspect_image_definition() -> Dict[str, Any]:
    profile = load_image_profile()
    containerfile = Path(profile.get("containerfile") or "containers/cursor-acp/Containerfile")
    root = PROFILE_PATH.resolve().parents[2]
    cf_path = root / containerfile if not containerfile.is_absolute() else containerfile
    text = cf_path.read_text(encoding="utf-8") if cf_path.is_file() else ""
    evidence = load_image_evidence()
    return {
        "profile": profile,
        "containerfile_path": str(cf_path),
        "containerfile_present": cf_path.is_file(),
        "containerfile_sha256": (
            hashlib.sha256(text.encode("utf-8")).hexdigest() if text else None
        ),
        "expected_image_ref": profile.get("expected_image_ref"),
        "expected_image_digest": profile.get("expected_image_digest"),
        "local_evidence": evidence,
        "install_sources": CURSOR_INSTALL_SOURCES,
        "build_authorized_in_automation": False,
        "note": "Inspect only; Owner must build and record evidence",
    }


def build_plan(*, base_image_digest: Optional[str] = None) -> Dict[str, Any]:
    """Machine-readable Owner build plan. Does not execute builds."""
    profile = load_image_profile()
    base_ref = "docker.io/library/debian:bookworm-slim"
    steps = [
        {
            "step": 1,
            "action": "pin_base_image",
            "command": (
                "podman pull docker.io/library/debian:bookworm-slim && "
                "podman image inspect --format '{{.Digest}}' "
                "docker.io/library/debian:bookworm-slim"
            ),
            "record": "base_image_digest",
            "note": "Reject floating tags at runtime; store digest",
        },
        {
            "step": 2,
            "action": "install_cursor_cli_in_build_context",
            "documented_source": CURSOR_INSTALL_SOURCES["linux_wsl_installer"],
            "constraints": [
                "Disable auto-update in the image (CURSOR_DISABLE_AUTO_UPDATE or equivalent)",
                "Do not embed CURSOR_API_KEY",
                "Install as non-root compatible binary under /usr/local/bin",
                "Capture `agent --version` and sha256sum of the binary",
            ],
            "record": ["cursor_release", "cursor_artifact_checksum"],
            "note": CURSOR_INSTALL_SOURCES["note"],
        },
        {
            "step": 3,
            "action": "build_image",
            "command": (
                "podman build "
                f"--build-arg BASE_IMAGE=debian@sha256:${{BASE_DIGEST}} "
                f"-t {profile.get('expected_image_ref')} "
                "-f containers/cursor-acp/Containerfile "
                "containers/cursor-acp"
            ),
            "record": ["final_image_id", "final_image_digest"],
        },
        {
            "step": 4,
            "action": "verify_entrypoint",
            "command": (
                f"podman run --rm --network none --read-only "
                f"--tmpfs /runtime/tmp:rw,size=32m "
                f"--user 65534:65534 "
                f"{profile.get('expected_image_ref')} "
                "agent --version"
            ),
            "record": "verification_results.entrypoint",
        },
        {
            "step": 5,
            "action": "write_evidence",
            "command": (
                "python3 scripts/eos.py cursor image verify --write-evidence "
                "--image-digest sha256:... --cursor-version ... "
                "--artifact-checksum sha256:... --base-digest sha256:..."
            ),
            "record": str(DEFAULT_EVIDENCE_PATH),
        },
    ]
    return {
        "profile_id": profile.get("profile_id"),
        "increment": profile.get("increment"),
        "expected_image_ref": profile.get("expected_image_ref"),
        "platform": profile.get("platform"),
        "base_image_ref": base_ref,
        "base_image_digest_required": True,
        "provided_base_digest": base_image_digest,
        "non_root_uid": profile.get("non_root_uid"),
        "read_only_rootfs": profile.get("read_only_rootfs"),
        "writable_paths": profile.get("writable_paths"),
        "embedded_credentials": False,
        "automatic_updates": False,
        "floating_latest_forbidden": True,
        "alpine_fixture_forbidden": True,
        "build_authorized_in_automation": False,
        "steps": steps,
        "install_sources": CURSOR_INSTALL_SOURCES,
        "evidence_schema": list(ImageEvidenceRecord(
            base_image_ref=base_ref,
            base_image_digest=None,
            cursor_release=None,
            cursor_artifact_checksum=None,
            final_image_id=None,
            final_image_digest=None,
            architecture=str(profile.get("platform") or "linux/amd64"),
            build_timestamp=utc_now(),
        ).to_dict().keys()),
    }


def inspect_local_image(
    image_ref: Optional[str] = None,
    *,
    inspect_runner: Optional[InspectRunner] = None,
) -> Dict[str, Any]:
    """Inspect a local OCI image. Does not pull. Distinguishes Id vs Digest."""
    profile = load_image_profile()
    ref = image_ref or str(profile.get("expected_image_ref") or "")
    if inspect_runner is not None:
        info = inspect_runner(ref)
        # Allow either already-normalized or raw podman inspect-shaped payloads.
        if info.get("local_image_id") or info.get("inspected") is True and "Id" not in info and "ID" not in info:
            info.setdefault("image_ref", ref)
            info.setdefault("inspected", True)
            info.setdefault("pulled", False)
            info.setdefault("evidence_class", "HOST_VERIFIED")
            return info
        image_id = info.get("local_image_id") or info.get("Id") or info.get("ID")
        digest = info.get("registry_digest") or info.get("Digest")
        if not digest:
            digests = info.get("RepoDigests") or []
            if isinstance(digests, list) and digests:
                first = str(digests[0])
                digest = first.split("@", 1)[-1] if "@" in first else first
        return {
            "image_ref": ref,
            "inspected": True,
            "pulled": False,
            "local_image_id": image_id,
            "registry_digest": digest if digest and str(digest).startswith("sha256:") else None,
            "repo_digests": info.get("RepoDigests") or [],
            "architecture": info.get("Architecture") or info.get("architecture"),
            "os": info.get("Os") or info.get("os"),
            "created": info.get("Created"),
            "size": info.get("Size"),
            "labels": info.get("Labels") or {},
            "identity_note": (
                "local_image_id is an immutable local store identity; "
                "registry_digest may be absent for locally-built images without push"
            ),
            "evidence_class": "HOST_VERIFIED",
            "user_supplied_checksum_trusted": False,
        }
    try:
        proc = subprocess.run(
            ["podman", "image", "inspect", "--format", "json", ref],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except Exception as exc:  # noqa: BLE001
        return {
            "image_ref": ref,
            "inspected": False,
            "pulled": False,
            "error": str(exc),
            "evidence_class": UNAVAILABLE,
        }
    if proc.returncode != 0:
        return {
            "image_ref": ref,
            "inspected": False,
            "pulled": False,
            "error": (proc.stderr or proc.stdout or "inspect_failed").strip()[:500],
            "evidence_class": UNAVAILABLE,
        }
    try:
        payload = json.loads(proc.stdout)
        info = payload[0] if isinstance(payload, list) and payload else payload
    except json.JSONDecodeError as exc:
        return {
            "image_ref": ref,
            "inspected": False,
            "pulled": False,
            "error": f"bad_json:{exc}",
            "evidence_class": ERROR,
        }
    image_id = info.get("Id") or info.get("ID")
    digest = info.get("Digest")
    if not digest:
        digests = info.get("Digest") or info.get("RepoDigests") or []
        if isinstance(digests, list) and digests:
            # RepoDigests look like localhost/name@sha256:...
            first = str(digests[0])
            digest = first.split("@", 1)[-1] if "@" in first else first
    arch = info.get("Architecture") or (info.get("Os") and None)
    return {
        "image_ref": ref,
        "inspected": True,
        "pulled": False,
        "local_image_id": image_id,
        "registry_digest": digest if digest and str(digest).startswith("sha256:") else None,
        "repo_digests": info.get("RepoDigests") or [],
        "architecture": info.get("Architecture"),
        "os": info.get("Os"),
        "created": info.get("Created"),
        "size": info.get("Size"),
        "labels": info.get("Labels") or {},
        "identity_note": (
            "local_image_id is an immutable local store identity; "
            "registry_digest may be absent for locally-built images without push"
        ),
        "evidence_class": "HOST_VERIFIED",
        "user_supplied_checksum_trusted": False,
    }


def compute_file_sha256(path: Path) -> Optional[str]:
    if not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def verify_image_identity(
    *,
    image_digest: Optional[str] = None,
    image_id: Optional[str] = None,
    cursor_version: Optional[str] = None,
    artifact_checksum: Optional[str] = None,
    artifact_path: Optional[str] = None,
    base_digest: Optional[str] = None,
    architecture: str = "linux/amd64",
    write_evidence: bool = False,
    evidence_file: Optional[Path] = None,
    observed_image_present: bool = False,
    trust_user_supplied_checksums: bool = False,
    inspect_runner: Optional[InspectRunner] = None,
    use_local_inspect: bool = False,
) -> Dict[str, Any]:
    """Verify image identity.

    User-supplied checksum strings alone are NOT trusted evidence unless the
    Owner also provides a local artifact path whose bytes hash matches, or a
    successful local OCI inspect result is supplied via use_local_inspect.
    """
    profile = load_image_profile()
    expected = profile.get("expected_image_digest")
    checks: List[Dict[str, Any]] = []
    local: Dict[str, Any] = {}

    def add(key: str, ok: bool, status: str, detail: Any = None) -> None:
        checks.append({"key": key, "ok": ok, "status": status, "detail": detail})

    if use_local_inspect:
        local = inspect_local_image(
            str(profile.get("expected_image_ref") or ""),
            inspect_runner=inspect_runner,
        )
        if local.get("inspected"):
            image_id = image_id or local.get("local_image_id")
            image_digest = image_digest or local.get("registry_digest")
            observed_image_present = True
            if local.get("architecture"):
                architecture = str(local.get("architecture"))

    computed_checksum = None
    if artifact_path:
        computed_checksum = compute_file_sha256(Path(artifact_path))
        if computed_checksum:
            if artifact_checksum and artifact_checksum != computed_checksum:
                add(
                    "artifact_checksum_mismatch",
                    False,
                    "BLOCKED",
                    {"supplied": artifact_checksum, "computed": computed_checksum},
                )
            artifact_checksum = computed_checksum

    digest = image_digest
    add(
        "local_image_id_present",
        bool(image_id),
        "HOST_VERIFIED" if image_id and use_local_inspect else (
            "OK" if image_id else "NOT_TESTED"
        ),
        image_id,
    )
    add(
        "digest_present",
        bool(digest and str(digest).startswith("sha256:")),
        "OK" if digest and str(digest).startswith("sha256:") else "BLOCKED",
        digest,
    )
    if expected:
        add(
            "digest_matches_profile",
            digest == expected,
            "OK" if digest == expected else "BLOCKED",
            {"expected": expected, "observed": digest},
        )
    else:
        add(
            "profile_digest_configured",
            False,
            "BLOCKED",
            "expected_image_digest is null until Owner pins it",
        )
    add(
        "not_floating_latest",
        "latest" not in str(profile.get("expected_image_ref") or "").lower(),
        "OK",
        profile.get("expected_image_ref"),
    )
    add(
        "cursor_version_recorded",
        bool(cursor_version),
        "OK" if cursor_version else "NOT_TESTED",
        cursor_version,
    )
    checksum_ok = bool(
        artifact_checksum
        and str(artifact_checksum).startswith("sha256:")
        and (computed_checksum is not None or trust_user_supplied_checksums)
    )
    add(
        "artifact_checksum_verified_from_bytes",
        bool(computed_checksum),
        "OK" if computed_checksum else "NOT_TESTED",
        computed_checksum or artifact_checksum,
    )
    if artifact_checksum and not computed_checksum and not trust_user_supplied_checksums:
        add(
            "user_supplied_checksum_untrusted_alone",
            False,
            "BLOCKED",
            "Provide --artifact-path so checksum is computed from bytes",
        )
    add(
        "base_digest_recorded",
        bool(base_digest and str(base_digest).startswith("sha256:")),
        "OK" if base_digest and str(base_digest).startswith("sha256:") else "NOT_TESTED",
        base_digest,
    )
    add(
        "image_present_host",
        observed_image_present,
        "HOST_VERIFIED" if observed_image_present else "NOT_TESTED",
        profile.get("expected_image_ref"),
    )
    add(
        "local_inspect_used",
        bool(use_local_inspect and local.get("inspected")),
        "HOST_VERIFIED" if local.get("inspected") else "NOT_TESTED",
        local.get("identity_note"),
    )

    blocked = [c for c in checks if not c["ok"] and c["status"] == "BLOCKED"]
    overall = "BLOCKED" if blocked else (
        "READY_FOR_AUTHORIZATION" if (digest and image_id) else "UNAVAILABLE"
    )
    record = ImageEvidenceRecord(
        base_image_ref="docker.io/library/debian:bookworm-slim",
        base_image_digest=base_digest,
        cursor_release=cursor_version,
        cursor_artifact_checksum=artifact_checksum if checksum_ok or computed_checksum else None,
        final_image_id=image_id,
        final_image_digest=digest,
        architecture=architecture,
        build_timestamp=utc_now(),
        verification_results={
            "checks": checks,
            "overall": overall,
            "local_inspect": local,
            "user_supplied_checksum_trusted": bool(
                trust_user_supplied_checksums or computed_checksum
            ),
        },
        profile_id=str(profile.get("profile_id")),
        evidence_class=ERROR if blocked else (SYNTHETIC if digest else UNAVAILABLE),
    )
    written = None
    if write_evidence:
        if blocked or not (computed_checksum or local.get("inspected")):
            written = None
            add(
                "evidence_write_refused_without_host_proof",
                False,
                "BLOCKED",
                "Refuse writing trusted evidence from user-supplied strings alone",
            )
            overall = "BLOCKED"
        else:
            written = str(save_image_evidence(record.to_dict(), evidence_file))
    return {
        "overall_status": overall,
        "checks": checks,
        "missing": [c["key"] for c in checks if not c["ok"]],
        "evidence": record.to_dict(),
        "evidence_written": written,
        "local_inspect": local,
        "live_cursor_acp": False,
        "build_executed": False,
    }
