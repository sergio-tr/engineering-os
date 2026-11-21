"""OpenClaw ACPX / Cursor / sandbox readiness observations (itemized)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from engineering_os.domain.models import utc_now
from engineering_os.infrastructure.evidence import ERROR, SYNTHETIC, UNAVAILABLE
from engineering_os.infrastructure.integrations.openclaw.gateway_client import OpenClawGatewayClient
from engineering_os.infrastructure.runtime.sandbox.sandbox_launcher import SandboxLauncher


@dataclass
class ReadinessItem:
    key: str
    ok: bool
    status: str
    detail: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "ok": self.ok,
            "status": self.status,
            "detail": self.detail,
        }


@dataclass
class AcpxReadinessReport:
    items: List[ReadinessItem] = field(default_factory=list)
    observed_at: str = field(default_factory=utc_now)
    overall_status: str = "UNAVAILABLE"
    evidence_class: str = UNAVAILABLE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "items": [i.to_dict() for i in self.items],
            "observed_at": self.observed_at,
            "overall_status": self.overall_status,
            "evidence_class": self.evidence_class,
            "missing": [i.key for i in self.items if not i.ok],
            "note": (
                "ACPX health is not sandbox evidence; OpenClaw ACP runs on host "
                "unless routed through an external sandbox launcher"
            ),
        }


class AcpxReadinessProbe:
    def __init__(
        self,
        gateway: OpenClawGatewayClient,
        sandbox: SandboxLauncher,
        *,
        acp_feature_enabled: bool = False,
        acpx_backend_present: bool = False,
        acpx_backend_healthy: bool = False,
        cursor_agent_allowed: bool = True,
        cursor_harness_available: bool = False,
        run_authorized: bool = False,
    ) -> None:
        self.gateway = gateway
        self.sandbox = sandbox
        self.acp_feature_enabled = acp_feature_enabled
        self.acpx_backend_present = acpx_backend_present
        self.acpx_backend_healthy = acpx_backend_healthy
        self.cursor_agent_allowed = cursor_agent_allowed
        self.cursor_harness_available = cursor_harness_available
        self.run_authorized = run_authorized

    def observe(self) -> AcpxReadinessReport:
        gw = self.gateway.status()
        sb = self.sandbox.readiness()
        items = [
            ReadinessItem(
                "gateway_reachable",
                bool(gw.get("transport_available")),
                "OK" if gw.get("transport_available") else "UNAVAILABLE",
                gw.get("last_error"),
            ),
            ReadinessItem(
                "gateway_authenticated",
                bool(gw.get("authenticated")),
                "OK" if gw.get("authenticated") else "BLOCKED",
                gw.get("last_error"),
            ),
            ReadinessItem(
                "protocol_version_compatible",
                gw.get("connection_lifecycle") not in {"protocol_mismatch"},
                "OK"
                if gw.get("connection_lifecycle") not in {"protocol_mismatch", "unavailable"}
                else "ERROR",
                gw.get("last_error"),
            ),
            ReadinessItem(
                "operator_scopes_granted",
                bool(gw.get("authenticated")) and "operator.read" in (gw.get("scopes") or []),
                "OK"
                if bool(gw.get("authenticated"))
                and "operator.read" in (gw.get("scopes") or [])
                else "BLOCKED",
                gw.get("last_error"),
            ),
            ReadinessItem(
                "acp_feature_enabled",
                self.acp_feature_enabled,
                "OK" if self.acp_feature_enabled else "UNAVAILABLE",
            ),
            ReadinessItem(
                "acpx_backend_present",
                self.acpx_backend_present,
                "OK" if self.acpx_backend_present else "UNAVAILABLE",
            ),
            ReadinessItem(
                "acpx_backend_healthy",
                self.acpx_backend_healthy,
                "OK" if self.acpx_backend_healthy else "UNAVAILABLE",
                "not_sandbox_evidence",
            ),
            ReadinessItem(
                "cursor_agent_id_allowed",
                self.cursor_agent_allowed,
                "OK" if self.cursor_agent_allowed else "BLOCKED",
                "agent_id=cursor",
            ),
            ReadinessItem(
                "cursor_harness_available",
                self.cursor_harness_available,
                "OK" if self.cursor_harness_available else "UNAVAILABLE",
            ),
            ReadinessItem(
                "sandbox_launcher_configured",
                sb.get("status") != "UNAVAILABLE",
                sb.get("status", "UNAVAILABLE"),
            ),
            ReadinessItem(
                "sandbox_enforcement_verified",
                sb.get("status") == "READY_FOR_AUTHORIZATION",
                sb.get("status", "BLOCKED"),
                ",".join(sb.get("blocked") or []),
            ),
            ReadinessItem(
                "current_run_authorized",
                self.run_authorized,
                "OK" if self.run_authorized else "BLOCKED",
                "ui_sandbox_gate_insufficient",
            ),
        ]
        missing = [i for i in items if not i.ok]
        if not missing:
            overall = "READY_FOR_AUTHORIZATION"
            evidence = SYNTHETIC  # still not live until authorized launch
        elif any(i.status == "ERROR" for i in items):
            overall = "ERROR"
            evidence = ERROR
        elif any(i.key.startswith("gateway") and not i.ok for i in items):
            overall = "UNAVAILABLE"
            evidence = UNAVAILABLE
        else:
            overall = "BLOCKED"
            evidence = ERROR
        return AcpxReadinessReport(
            items=items,
            overall_status=overall,
            evidence_class=evidence,
        )
