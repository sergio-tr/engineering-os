"""OpenClaw coordinator adapter — read-only CLI observation path."""

from __future__ import annotations

from typing import Any, Dict, Optional

from engineering_os.domain.models import utc_now
from engineering_os.infrastructure.adapters import CoordinatorAdapter
from engineering_os.infrastructure.evidence import ERROR, LIVE_READ_ONLY, UNAVAILABLE
from engineering_os.infrastructure.gateway_transport import (
    GatewayTransport,
    UnavailableGatewayTransport,
)
from engineering_os.infrastructure.openclaw_client import (
    OpenClawCliClient,
    OpenClawClientError,
)


class OpenClawCoordinatorAdapter(CoordinatorAdapter):
    """Observes OpenClaw availability; never starts agents or Gateway sessions."""

    name = "openclaw"

    def __init__(
        self,
        client: Optional[OpenClawCliClient] = None,
        *,
        gateway_transport: Optional[GatewayTransport] = None,
    ) -> None:
        self.client = client or OpenClawCliClient()
        self.gateway_transport = gateway_transport or UnavailableGatewayTransport()
        self.last_observation: Optional[Dict[str, Any]] = None
        self.last_refresh_at: Optional[str] = None

    def next_hint(self, project_id: str) -> Optional[str]:
        # Read-only coordinator does not schedule tasks in EOS-05.
        return None

    def refresh(self) -> Dict[str, Any]:
        try:
            status = self.client.status_json()
        except OpenClawClientError as exc:
            status = {
                "available": False,
                "evidence_class": ERROR,
                "error": {"code": exc.code, "message": str(exc)},
            }
        try:
            gateway = self.client.gateway_status()
        except OpenClawClientError as exc:
            gateway = {
                "available": False,
                "evidence_class": ERROR,
                "error": {"code": exc.code, "message": str(exc)},
                "rpc_required": True,
            }
        transport = self.gateway_transport.connect()
        self.last_refresh_at = utc_now()
        # Capability summary from status payload when present.
        capabilities = []
        parsed = status.get("status") if isinstance(status.get("status"), dict) else {}
        if parsed.get("gateway"):
            capabilities.append("gateway_status")
        if gateway.get("available"):
            capabilities.append("gateway_rpc")
        agents = parsed.get("agents") or parsed.get("sessions") or []
        observation = {
            "installation_available": self.client.binary_path() is not None,
            "status": status,
            "gateway": gateway,
            "gateway_transport": transport.to_dict(),
            "capabilities": capabilities,
            "agent_session_summary": agents if isinstance(agents, list) else [],
            "last_refresh_at": self.last_refresh_at,
            "evidence_class": status.get("evidence_class")
            or gateway.get("evidence_class")
            or UNAVAILABLE,
            "live_dispatch_permitted": False,
            "note": "EOS-05 observes OpenClaw only; does not dispatch agent work",
        }
        self.last_observation = observation
        return observation

    def status(self) -> Dict[str, Any]:
        if self.last_observation is None:
            return {
                "installation_available": self.client.binary_path() is not None,
                "evidence_class": UNAVAILABLE,
                "last_refresh_at": None,
                "note": "call refresh explicitly; dashboard load does not auto-refresh",
            }
        return dict(self.last_observation)
