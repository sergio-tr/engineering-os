"""Cursor ACP runtime image profile, command discovery and readiness."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
import json

from engineering_os.infrastructure.evidence import ERROR, SYNTHETIC, UNAVAILABLE


PROFILE_PATH = (
    Path(__file__).resolve().parents[3] / "containers" / "cursor-acp" / "image-profile.json"
)


def load_image_profile(path: Optional[Path] = None) -> Dict[str, Any]:
    p = path or PROFILE_PATH
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("invalid_image_profile")
    return data


@dataclass
class CursorCommandProfile:
    argv: Tuple[str, ...]
    source: str

    def to_dict(self) -> Dict[str, Any]:
        return {"argv": list(self.argv), "source": self.source}


def resolve_cursor_acp_command(
    *,
    image_profile: Optional[Dict[str, Any]] = None,
    available_binaries: Optional[Sequence[str]] = None,
) -> CursorCommandProfile:
    """Resolve Cursor ACP argv from verified image profile — not user strings."""
    profile = image_profile or load_image_profile()
    candidates = profile.get("command_candidates") or [["agent", "acp"], ["cursor-agent", "acp"]]
    available = set(available_binaries or [])
    for cand in candidates:
        if not cand or not isinstance(cand, list):
            continue
        binary = cand[0]
        if available and binary not in available:
            continue
        if available or not available_binaries:
            # When availability is unknown (image not built), return first profile candidate.
            return CursorCommandProfile(argv=tuple(str(x) for x in cand), source="image_profile")
    raise RuntimeError("cursor_acp_command_unresolved")


@dataclass
class CursorRuntimeReadiness:
    items: List[Dict[str, Any]] = field(default_factory=list)
    overall_status: str = "BLOCKED"
    evidence_class: str = UNAVAILABLE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "items": list(self.items),
            "overall_status": self.overall_status,
            "evidence_class": self.evidence_class,
            "missing": [i["key"] for i in self.items if not i.get("ok")],
            "live_cursor_acp": False,
        }


class CursorRuntimePlanner:
    def __init__(
        self,
        *,
        image_digest: Optional[str] = None,
        image_present: bool = False,
        cursor_version: Optional[str] = None,
        available_binaries: Optional[Sequence[str]] = None,
    ) -> None:
        self.profile = load_image_profile()
        self.image_digest = image_digest
        self.image_present = image_present
        self.cursor_version = cursor_version
        self.available_binaries = list(available_binaries or [])

    def image_plan(self) -> Dict[str, Any]:
        return {
            "profile": self.profile,
            "containerfile": self.profile.get("containerfile"),
            "expected_image_ref": self.profile.get("expected_image_ref"),
            "expected_image_digest": self.profile.get("expected_image_digest"),
            "build_authorized_in_eos09": False,
            "alpine_fixture_suitable": False,
            "note": "Image definition only; do not build during EOS-09 automation",
        }

    def command(self) -> CursorCommandProfile:
        return resolve_cursor_acp_command(
            image_profile=self.profile,
            available_binaries=self.available_binaries or None,
        )

    def readiness(self) -> CursorRuntimeReadiness:
        digest_ok = bool(
            self.image_digest and str(self.image_digest).startswith("sha256:")
        )
        expected = self.profile.get("expected_image_digest")
        digest_matches = True
        if expected:
            digest_matches = self.image_digest == expected
            digest_ok = digest_ok and digest_matches
        try:
            cmd = self.command()
            cmd_ok = True
            cmd_detail = " ".join(cmd.argv)
        except Exception as exc:  # noqa: BLE001
            cmd_ok = False
            cmd_detail = str(exc)
        items = [
            {
                "key": "image_definition_present",
                "ok": PROFILE_PATH.is_file(),
                "status": "OK" if PROFILE_PATH.is_file() else "BLOCKED",
            },
            {
                "key": "image_present",
                "ok": self.image_present,
                "status": "OK" if self.image_present else "BLOCKED",
                "detail": self.profile.get("expected_image_ref"),
            },
            {
                "key": "image_digest_verified",
                "ok": digest_ok,
                "status": "OK" if digest_ok else "BLOCKED",
                "detail": self.image_digest,
            },
            {
                "key": "cursor_executable_mapped",
                "ok": cmd_ok,
                "status": "OK" if cmd_ok else "BLOCKED",
                "detail": cmd_detail,
            },
            {
                "key": "cursor_version_known",
                "ok": bool(self.cursor_version),
                "status": "OK" if self.cursor_version else "UNAVAILABLE",
                "detail": self.cursor_version,
            },
            {
                "key": "not_alpine_fixture_image",
                "ok": True,
                "status": "OK",
                "detail": "cursor runtime profile distinct from eos08 fixture",
            },
            {
                "key": "live_execution_disabled",
                "ok": True,
                "status": "OK",
                "detail": "EOS-09 does not enable live Cursor ACP",
            },
        ]
        missing = [i for i in items if not i["ok"]]
        if not missing:
            overall = "READY_FOR_AUTHORIZATION"
            evidence = SYNTHETIC
        elif any(i["key"].startswith("image") and not i["ok"] for i in items):
            overall = "BLOCKED"
            evidence = ERROR
        else:
            overall = "UNAVAILABLE"
            evidence = UNAVAILABLE
        return CursorRuntimeReadiness(
            items=items, overall_status=overall, evidence_class=evidence
        )
