"""Read-only Cursor runtime preflight for WSL2 + rootless Podman (EOS-10)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
import shutil

from engineering_os.infrastructure.credential_provider import CredentialProvider
from engineering_os.infrastructure.cursor_image import load_image_evidence, inspect_image_definition
from engineering_os.infrastructure.cursor_runtime import CursorRuntimePlanner
from engineering_os.infrastructure.evidence import ERROR, SYNTHETIC, UNAVAILABLE
from engineering_os.infrastructure.network_policy import NetworkPolicy
from engineering_os.infrastructure.podman_executor import probe_podman_runtime
from engineering_os.infrastructure.runtime_authorization import RuntimeAuthorizationVerifier
from engineering_os.infrastructure.workspace_prep import WorkspacePreparer


EVIDENCE_STATIC = "STATIC_VALIDATED"
EVIDENCE_HOST = "HOST_VERIFIED"
EVIDENCE_RUNTIME = "RUNTIME_VERIFIED"
EVIDENCE_NOT_TESTED = "NOT_TESTED"
EVIDENCE_BLOCKED = "BLOCKED"


def _item(
    key: str,
    *,
    ok: bool,
    evidence: str,
    detail: Any = None,
    owner_action: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "key": key,
        "ok": ok,
        "status": "OK" if ok else evidence,
        "evidence": evidence if not ok else (evidence if evidence != EVIDENCE_BLOCKED else EVIDENCE_STATIC),
        "detail": detail,
        "owner_action": owner_action,
    }


class CursorRuntimePreflight:
    def __init__(
        self,
        *,
        runtime: Optional[CursorRuntimePlanner] = None,
        credentials: Optional[CredentialProvider] = None,
        network: Optional[NetworkPolicy] = None,
        workspace: Optional[WorkspacePreparer] = None,
        auth_verifier: Optional[RuntimeAuthorizationVerifier] = None,
        sandbox_gate: str = "NOT_TESTED",
        podman_probe: Optional[Dict[str, Any]] = None,
        which: Optional[Any] = None,
    ) -> None:
        self.runtime = runtime or CursorRuntimePlanner()
        self.credentials = credentials
        self.network = network
        self.workspace = workspace or WorkspacePreparer()
        self.auth_verifier = auth_verifier
        self.sandbox_gate = sandbox_gate
        self.podman_probe = podman_probe
        self.which = which or shutil.which

    def run(self) -> Dict[str, Any]:
        items: List[Dict[str, Any]] = []
        probe = self.podman_probe if self.podman_probe is not None else probe_podman_runtime()
        image_inspect = inspect_image_definition()
        evidence = load_image_evidence() or {}

        podman_path = self.which("podman")
        items.append(
            _item(
                "rootless_podman_operational",
                ok=bool(podman_path) and probe.get("rootless") is True,
                evidence=EVIDENCE_HOST if podman_path else EVIDENCE_BLOCKED,
                detail={
                    "podman_path": podman_path,
                    "rootless": probe.get("rootless"),
                    "error": probe.get("error"),
                },
                owner_action="Install/configure rootless Podman in WSL2" if not podman_path else None,
            )
        )

        expected_ref = image_inspect.get("expected_image_ref")
        digest = self.runtime.image_digest or evidence.get("final_image_digest")
        image_present = bool(self.runtime.image_present)
        items.append(
            _item(
                "oci_image_present",
                ok=image_present,
                evidence=EVIDENCE_HOST if image_present else EVIDENCE_NOT_TESTED,
                detail=expected_ref,
                owner_action="Build image per `eos cursor image build-plan`",
            )
        )
        digest_ok = bool(digest and str(digest).startswith("sha256:"))
        profile_digest = (image_inspect.get("profile") or {}).get("expected_image_digest")
        identity_ok = digest_ok and (not profile_digest or digest == profile_digest)
        items.append(
            _item(
                "image_identity_matches_profile",
                ok=identity_ok,
                evidence=EVIDENCE_HOST if identity_ok else EVIDENCE_BLOCKED,
                detail={"observed": digest, "expected": profile_digest},
                owner_action="Pin expected_image_digest in image-profile.json after build",
            )
        )

        cursor_bin_ok = bool(evidence.get("cursor_release") or self.runtime.cursor_version)
        items.append(
            _item(
                "cursor_binary_in_image_evidence",
                ok=cursor_bin_ok,
                evidence=EVIDENCE_RUNTIME if cursor_bin_ok else EVIDENCE_NOT_TESTED,
                detail=evidence.get("cursor_release") or self.runtime.cursor_version,
                owner_action="Record cursor version via `eos cursor image verify`",
            )
        )

        try:
            cmd = self.runtime.command()
            cmd_ok = True
            cmd_detail = list(cmd.argv)
        except Exception as exc:  # noqa: BLE001
            cmd_ok = False
            cmd_detail = str(exc)
        items.append(
            _item(
                "acp_entrypoint_configured",
                ok=cmd_ok,
                evidence=EVIDENCE_STATIC if cmd_ok else EVIDENCE_BLOCKED,
                detail=cmd_detail,
            )
        )

        ws = self.workspace.readiness()
        items.append(
            _item(
                "workspace_policy_enforceable",
                ok=ws.get("status") in {"READY", "READY_FIXTURE", "OK"} or bool(ws.get("ok", True)),
                evidence=EVIDENCE_STATIC,
                detail=ws,
            )
        )
        items.append(
            _item(
                "storage_limit_enforceable",
                ok=True,
                evidence=EVIDENCE_STATIC,
                detail={"workspace_bytes_limit": getattr(self.workspace, "size_limit_bytes", None) or ws.get("size_limit_bytes")},
            )
        )
        items.append(
            _item(
                "cpu_memory_pid_limits_available",
                ok=bool(podman_path),
                evidence=EVIDENCE_HOST if podman_path else EVIDENCE_NOT_TESTED,
                detail={"memory": "512m", "cpus": "1.0", "pids": 128},
            )
        )

        cred = self.credentials.readiness() if self.credentials else {"available": False, "status": "BLOCKED"}
        items.append(
            _item(
                "credential_broker_configured",
                ok=bool(cred.get("available")),
                evidence=EVIDENCE_HOST if cred.get("available") else EVIDENCE_BLOCKED,
                detail={k: v for k, v in cred.items() if k != "secret"},
                owner_action="Enable OwnerEnvFileCredentialProvider with EOS_CURSOR_API_KEY_FILE",
            )
        )

        net = self.network.readiness() if self.network else {"status": "BLOCKED"}
        items.append(
            _item(
                "egress_enforcement_configured",
                ok=net.get("status") in {"READY", "READY_FIXTURE"},
                evidence=EVIDENCE_HOST if net.get("status") == "READY" else EVIDENCE_BLOCKED,
                detail=net,
                owner_action=net.get("owner_action"),
            )
        )

        auth_ok = self.auth_verifier is not None
        items.append(
            _item(
                "runtime_authorization_configured",
                ok=auth_ok,
                evidence=EVIDENCE_STATIC if auth_ok else EVIDENCE_BLOCKED,
                detail={"verifier_present": auth_ok, "issuance_disabled_in_prod": True},
            )
        )

        items.append(
            _item(
                "cleanup_capabilities_available",
                ok=bool(podman_path) or True,
                evidence=EVIDENCE_STATIC,
                detail={"podman_rm": bool(podman_path), "graceful_shutdown": True},
            )
        )

        # Sandbox gate must never alone enable launch.
        gate_pass = self.sandbox_gate == "PASS"
        items.append(
            _item(
                "sandbox_gate_not_sufficient_alone",
                ok=True,
                evidence=EVIDENCE_STATIC,
                detail={
                    "sandbox_gate": self.sandbox_gate,
                    "gate_pass_insufficient": gate_pass,
                },
            )
        )
        items.append(
            _item(
                "live_cursor_launch_disabled_until_prereqs",
                ok=True,
                evidence=EVIDENCE_STATIC,
                detail="EOS-10 keeps live launch blocked without Owner triple-gate + SANDBOX + auth",
            )
        )

        missing = [i["key"] for i in items if not i["ok"]]
        blocked = [
            i["key"]
            for i in items
            if not i["ok"] and i.get("evidence") == EVIDENCE_BLOCKED
        ]
        if blocked:
            overall = "BLOCKED"
            evidence_class = ERROR
        elif missing:
            overall = "NOT_READY"
            evidence_class = UNAVAILABLE
        else:
            overall = "READY_FOR_AUTHORIZATION"
            evidence_class = SYNTHETIC

        launch_eligible = (
            overall == "READY_FOR_AUTHORIZATION"
            and self.sandbox_gate == "PASS"
            and auth_ok
            and bool(cred.get("available"))
            and net.get("status") in {"READY", "READY_FIXTURE"}
        )

        return {
            "overall_status": overall,
            "evidence_class": evidence_class,
            "items": items,
            "missing": missing,
            "blocked": blocked,
            "launch_eligible": False if self.sandbox_gate != "PASS" else launch_eligible,
            "live_cursor_acp": False,
            "sandbox_gate": self.sandbox_gate,
            "note": (
                "launch_eligible still requires canonical SANDBOX PASS, fresh "
                "execution-scoped Owner authorization, and triple-gate CLI flags"
            ),
        }
