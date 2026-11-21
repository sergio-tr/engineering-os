"""Cursor OCI image build plan, inspection and verification (Owner-operated).

Does not download artifacts or build images during automation.
Cursor CLI is distributed via https://cursor.com/install (documented installer).
No immutable official release tarball with published checksums is currently
documented; EOS records the strongest verifiable local evidence available.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
import hashlib
import json
import os
import time

from engineering_os.domain.models import utc_now
from engineering_os.infrastructure.cursor_runtime import PROFILE_PATH, load_image_profile
from engineering_os.infrastructure.evidence import ERROR, SYNTHETIC, UNAVAILABLE


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


def verify_image_identity(
    *,
    image_digest: Optional[str] = None,
    image_id: Optional[str] = None,
    cursor_version: Optional[str] = None,
    artifact_checksum: Optional[str] = None,
    base_digest: Optional[str] = None,
    architecture: str = "linux/amd64",
    write_evidence: bool = False,
    evidence_file: Optional[Path] = None,
    observed_image_present: bool = False,
) -> Dict[str, Any]:
    profile = load_image_profile()
    expected = profile.get("expected_image_digest")
    checks: List[Dict[str, Any]] = []

    def add(key: str, ok: bool, status: str, detail: Any = None) -> None:
        checks.append({"key": key, "ok": ok, "status": status, "detail": detail})

    digest = image_digest
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
    add(
        "artifact_checksum_recorded",
        bool(artifact_checksum and str(artifact_checksum).startswith("sha256:")),
        "OK"
        if artifact_checksum and str(artifact_checksum).startswith("sha256:")
        else "NOT_TESTED",
        artifact_checksum,
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

    blocked = [c for c in checks if not c["ok"] and c["status"] == "BLOCKED"]
    overall = "BLOCKED" if blocked else ("READY_FOR_AUTHORIZATION" if digest else "UNAVAILABLE")
    record = ImageEvidenceRecord(
        base_image_ref="docker.io/library/debian:bookworm-slim",
        base_image_digest=base_digest,
        cursor_release=cursor_version,
        cursor_artifact_checksum=artifact_checksum,
        final_image_id=image_id,
        final_image_digest=digest,
        architecture=architecture,
        build_timestamp=utc_now(),
        verification_results={"checks": checks, "overall": overall},
        profile_id=str(profile.get("profile_id")),
        evidence_class=ERROR if blocked else (SYNTHETIC if digest else UNAVAILABLE),
    )
    written = None
    if write_evidence:
        written = str(save_image_evidence(record.to_dict(), evidence_file))
    return {
        "overall_status": overall,
        "checks": checks,
        "missing": [c["key"] for c in checks if not c["ok"]],
        "evidence": record.to_dict(),
        "evidence_written": written,
        "live_cursor_acp": False,
        "build_executed": False,
    }
