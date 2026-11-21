"""Unified Cursor live-preflight report (EOS-11)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from engineering_os.infrastructure.credential_provider import CredentialProvider
from engineering_os.infrastructure.cursor_image import inspect_local_image, verify_image_identity
from engineering_os.infrastructure.cursor_runtime import CursorRuntimePlanner
from engineering_os.infrastructure.egress_broker import (
    TrustedEgressBroker,
    cursor_proxy_compatibility,
)
from engineering_os.infrastructure.evidence import ERROR, SYNTHETIC, UNAVAILABLE
from engineering_os.infrastructure.network_policy import NetworkPolicy
from engineering_os.infrastructure.podman_capabilities import probe_podman_capabilities
from engineering_os.infrastructure.runtime_authorization import RuntimeAuthorizationVerifier
from engineering_os.infrastructure.runtime_preflight import (
    EVIDENCE_BLOCKED,
    EVIDENCE_HOST,
    EVIDENCE_NOT_TESTED,
    EVIDENCE_STATIC,
    CursorRuntimePreflight,
)
from engineering_os.infrastructure.workspace_prep import WorkspacePreparer


def _item(key: str, *, ok: bool, evidence: str, detail: Any = None) -> Dict[str, Any]:
    return {
        "key": key,
        "ok": ok,
        "status": "OK" if ok else evidence,
        "evidence": evidence if ok else evidence,
        "detail": detail,
    }


class CursorLivePreflight:
    def __init__(
        self,
        *,
        runtime: Optional[CursorRuntimePlanner] = None,
        credentials: Optional[CredentialProvider] = None,
        network: Optional[NetworkPolicy] = None,
        workspace: Optional[WorkspacePreparer] = None,
        auth_verifier: Optional[RuntimeAuthorizationVerifier] = None,
        sandbox_gate: str = "NOT_TESTED",
        broker: Optional[TrustedEgressBroker] = None,
    ) -> None:
        self.runtime = runtime or CursorRuntimePlanner()
        self.credentials = credentials
        self.network = network
        self.workspace = workspace or WorkspacePreparer()
        self.auth_verifier = auth_verifier
        self.sandbox_gate = sandbox_gate
        self.broker = broker or TrustedEgressBroker()

    def run(self) -> Dict[str, Any]:
        caps = probe_podman_capabilities()
        base = CursorRuntimePreflight(
            runtime=self.runtime,
            credentials=self.credentials,
            network=self.network,
            workspace=self.workspace,
            auth_verifier=self.auth_verifier,
            sandbox_gate=self.sandbox_gate,
            podman_probe={
                "rootless": caps.rootless,
                "error": caps.error,
            },
        ).run()

        items: List[Dict[str, Any]] = list(base.get("items") or [])
        items.append(
            _item(
                "oci_runtime_compatibility",
                ok=bool(caps.podman_path) and caps.network_none_supported,
                evidence=EVIDENCE_HOST if caps.podman_path else EVIDENCE_BLOCKED,
                detail=caps.to_dict(),
            )
        )
        items.append(
            _item(
                "pasta_not_required_for_enforcement",
                ok=True,
                evidence=EVIDENCE_STATIC,
                detail={
                    "pasta_network_mode_supported": caps.pasta_network_mode_supported,
                    "recommended": "uds_broker_network_none",
                },
            )
        )

        local = inspect_local_image(
            str(self.runtime.profile.get("expected_image_ref") or "")
        )
        items.append(
            _item(
                "image_identity_from_local_oci",
                ok=bool(local.get("inspected")),
                evidence=EVIDENCE_HOST if local.get("inspected") else EVIDENCE_NOT_TESTED,
                detail=local,
            )
        )
        verify = verify_image_identity(
            image_digest=self.runtime.image_digest,
            cursor_version=self.runtime.cursor_version,
            observed_image_present=bool(self.runtime.image_present),
            use_local_inspect=False,
        )
        items.append(
            _item(
                "image_profile_consistency",
                ok=verify["overall_status"] != "BLOCKED"
                or "profile_digest_configured" in verify.get("missing", []),
                evidence=EVIDENCE_STATIC,
                detail={"overall": verify["overall_status"], "missing": verify["missing"]},
            )
        )

        proxy = cursor_proxy_compatibility()
        items.append(
            _item(
                "acp_protocol_compatibility",
                ok=True,
                evidence=EVIDENCE_STATIC,
                detail={"transport": "stdio NDJSON", "command": "agent acp"},
            )
        )
        items.append(
            _item(
                "cursor_proxy_compatibility",
                ok=False,
                evidence=EVIDENCE_NOT_TESTED,
                detail=proxy,
            )
        )

        broker_ready = self.broker.readiness()
        items.append(
            _item(
                "broker_enforcement_configured",
                ok=broker_ready.get("status") == "READY",
                evidence=EVIDENCE_STATIC if broker_ready.get("status") == "READY" else EVIDENCE_BLOCKED,
                detail=broker_ready,
            )
        )
        net = self.network.readiness() if self.network else {"status": "BLOCKED", "enforcement": "NOT_ENFORCED"}
        items.append(
            _item(
                "egress_enforcement_status",
                ok=net.get("enforcement") not in {None, "NOT_ENFORCED"}
                or net.get("status") == "READY_FIXTURE",
                evidence=EVIDENCE_HOST if net.get("status") == "READY_FOR_OWNER_PROBE" else EVIDENCE_BLOCKED,
                detail=net,
            )
        )

        cred = self.credentials.readiness() if self.credentials else {"available": False}
        items.append(
            _item(
                "credential_isolation_boundaries_explicit",
                ok=True,
                evidence=EVIDENCE_STATIC,
                detail={
                    "env_injection_isolates_peers": False,
                    "smoke_denies_untrusted_tools": True,
                    "provider": cred,
                },
            )
        )
        items.append(
            _item(
                "trusted_authorization_bound",
                ok=self.auth_verifier is not None,
                evidence=EVIDENCE_STATIC if self.auth_verifier else EVIDENCE_BLOCKED,
                detail={"verifier_present": self.auth_verifier is not None},
            )
        )
        items.append(
            _item(
                "session_lifecycle_graceful_shutdown",
                ok=True,
                evidence=EVIDENCE_STATIC,
                detail={"order": ["stdin_eof", "sigterm", "sigkill_fallback"]},
            )
        )
        items.append(
            _item(
                "cleanup_capability",
                ok=True,
                evidence=EVIDENCE_STATIC,
                detail={"podman_rm": bool(caps.podman_path)},
            )
        )
        items.append(
            _item(
                "sandbox_gate_not_authorizing_alone",
                ok=True,
                evidence=EVIDENCE_STATIC,
                detail={"sandbox_gate": self.sandbox_gate},
            )
        )

        missing = [i["key"] for i in items if not i["ok"]]
        blocked = [
            i["key"]
            for i in items
            if not i["ok"] and i.get("evidence") == EVIDENCE_BLOCKED
        ]
        # Never READY from mocked/offline alone.
        if blocked:
            overall = "BLOCKED"
            evidence_class = ERROR
        else:
            overall = "NOT_READY"
            evidence_class = UNAVAILABLE

        return {
            "overall_status": overall,
            "evidence_class": evidence_class,
            "items": items,
            "missing": missing,
            "blocked": blocked,
            "launch_eligible": False,
            "live_cursor_acp": False,
            "sandbox_gate": self.sandbox_gate,
            "podman": caps.to_dict(),
            "proxy_compatibility": proxy,
            "broker": broker_ready,
            "network": net,
            "note": (
                "live-preflight never declares READY from offline mocks; "
                "Owner network probe + image inspect + SANDBOX PASS required"
            ),
        }
