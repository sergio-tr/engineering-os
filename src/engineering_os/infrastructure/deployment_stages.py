"""Owner-operated deployment stages A–F for first Cursor ACP smoke (EOS-12)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def deployment_stages(
    *,
    sandbox_gate: str = "NOT_TESTED",
    podman_version: Optional[str] = None,
) -> Dict[str, Any]:
    stages: List[Dict[str, Any]] = [
        {
            "stage": "A",
            "title": "Environment diagnostics",
            "commands": [
                "podman --version",
                "podman info --format '{{.Host.Security.Rootless}}'",
                "python3 scripts/eos.py network broker status",
                "python3 scripts/eos.py cursor live-preflight",
            ],
            "produces": ["podman_capabilities", "egress_enforcement_status"],
            "stops_when": ["podman_missing", "not_rootless"],
        },
        {
            "stage": "B",
            "title": "Cursor OCI image build and identity verification",
            "commands": [
                "python3 scripts/eos.py cursor image build-plan",
                "python3 scripts/eos.py cursor image build --print-only",
                "# Owner runs printed podman build commands manually",
                "python3 scripts/eos.py cursor image verify --use-local-inspect "
                "--artifact-path containers/cursor-acp/vendor/cursor-agent "
                "--cursor-version <VER> --base-digest sha256:<BASE> --write-evidence",
            ],
            "produces": ["local_image_id", "artifact_checksum", "image_evidence"],
            "stops_when": ["image_absent", "checksum_unverified"],
            "note": "Do not invent checksums; hash actual artifact bytes",
        },
        {
            "stage": "C",
            "title": "Real broker enforcement probe (disposable container)",
            "commands": [
                "python3 scripts/eos.py network broker probe --dry-run",
                "python3 scripts/eos.py network broker probe --execute "
                "--allow-phase-b --owner-authorize-runtime-execution",
            ],
            "produces": ["probe_cases", "broker_observations", "cleanup_evidence"],
            "stops_when": ["probe_case_failed", "direct_route_leak", "cleanup_failed"],
            "note": "May open authorized HTTPS from the host broker process",
        },
        {
            "stage": "D",
            "title": "Credential provider configuration",
            "commands": [
                "install -d -m 700 \"$HOME/.config/eos\"",
                "install -m 600 /dev/null \"$HOME/.config/eos/cursor_api_key\"",
                "# Place CURSOR_API_KEY value (Owner only); never commit",
                "export EOS_CURSOR_API_KEY_FILE=\"$HOME/.config/eos/cursor_api_key\"",
                "# Enable OwnerEnvFileCredentialProvider only after Stage C PASS",
            ],
            "produces": ["credential_provider_ready"],
            "stops_when": ["secret_file_missing", "provider_disabled"],
            "note": "Env injection does not isolate peers in the same container",
        },
        {
            "stage": "E",
            "title": "Full live readiness verification",
            "commands": [
                "python3 scripts/eos.py cursor live-preflight",
                "python3 scripts/eos.py runtime requirements",
                "python3 scripts/eos.py cursor smoke --dry-run",
            ],
            "produces": ["live_preflight_report"],
            "stops_when": ["launch_eligible_false", "sandbox_gate_not_pass"],
        },
        {
            "stage": "F",
            "title": "First authorized Cursor ACP smoke execution",
            "commands": [
                "python3 scripts/eos.py cursor smoke --execute "
                "--allow-phase-b --owner-authorize-runtime-execution",
                "python3 scripts/eos.py cursor smoke evidence <EXECUTION_ID>",
            ],
            "produces": ["acp_session", "lifecycle", "evidence_integrity_hash"],
            "stops_when": [
                "sandbox_gate_not_pass",
                "authorization_missing",
                "image_unverified",
                "broker_not_enforced",
            ],
            "note": (
                "Requires canonical SANDBOX PASS + fresh host authorization. "
                "ACP completion is not a merged GitHub PR."
            ),
        },
    ]
    return {
        "increment": "EOS-12",
        "sandbox_gate": sandbox_gate,
        "podman_version": podman_version,
        "stages": stages,
        "auto_advance_forbidden": True,
        "live_cursor_acp": False,
        "note": (
            "Each stage must produce evidence and stop when its own prerequisites "
            "are missing. Later stages must not run because an earlier stage passed."
        ),
    }


def evaluate_stage_gate(
    stage: str,
    *,
    facts: Dict[str, Any],
) -> Dict[str, Any]:
    """Offline gate evaluator — does not invent PASS for unproven facts."""
    missing: List[str] = []
    if stage == "A":
        if not facts.get("podman_present"):
            missing.append("podman_missing")
        if facts.get("rootless") is not True:
            missing.append("not_rootless")
    elif stage == "B":
        if not facts.get("image_present"):
            missing.append("image_absent")
        if not facts.get("artifact_checksum_verified"):
            missing.append("checksum_unverified")
    elif stage == "C":
        if not facts.get("probe_executed"):
            missing.append("probe_not_executed")
        if facts.get("probe_status") != "COMPLETED":
            missing.append("probe_case_failed")
    elif stage == "D":
        if not facts.get("credential_provider_available"):
            missing.append("provider_disabled")
    elif stage == "E":
        if facts.get("sandbox_gate") != "PASS":
            missing.append("sandbox_gate_not_pass")
        if not facts.get("launch_eligible"):
            missing.append("launch_eligible_false")
    elif stage == "F":
        if facts.get("sandbox_gate") != "PASS":
            missing.append("sandbox_gate_not_pass")
        if not facts.get("authorization_present"):
            missing.append("authorization_missing")
        if not facts.get("broker_enforced"):
            missing.append("broker_not_enforced")
    return {
        "stage": stage,
        "ok": not missing,
        "missing": missing,
        "advanced": False,
        "note": "Gate evaluation only; does not execute the stage",
    }
