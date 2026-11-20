"""OpenClaw Gateway WebSocket transport architecture (future authenticated RPC)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class GatewaySessionState:
    transport_available: bool = False
    authenticated: bool = False
    paired: bool = False
    scopes: List[str] = field(default_factory=list)
    supported_methods: List[str] = field(default_factory=list)
    connection_lifecycle: str = "unavailable"
    last_error: Optional[str] = None
    protocol_authority: str = "https://docs.openclaw.ai/gateway/protocol"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transport_available": self.transport_available,
            "authenticated": self.authenticated,
            "paired": self.paired,
            "scopes": list(self.scopes),
            "supported_methods": list(self.supported_methods),
            "connection_lifecycle": self.connection_lifecycle,
            "last_error": self.last_error,
            "protocol_authority": self.protocol_authority,
            "note": (
                "Advanced WebSocket Gateway transport is not enabled in EOS-05; "
                "read-only CLI observation is the active path"
            ),
        }


class GatewayTransport(ABC):
    """Future WebSocket RPC transport. Must not fake authenticated sessions."""

    @abstractmethod
    def connect(self) -> GatewaySessionState:
        raise NotImplementedError

    @abstractmethod
    def close(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def call(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        raise NotImplementedError


class UnavailableGatewayTransport(GatewayTransport):
    """Explicitly unavailable transport placeholder (no dependency install)."""

    def connect(self) -> GatewaySessionState:
        return GatewaySessionState(
            transport_available=False,
            authenticated=False,
            paired=False,
            connection_lifecycle="unavailable",
            last_error="websocket_transport_not_enabled",
        )

    def close(self) -> None:
        return None

    def call(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        raise RuntimeError("websocket_transport_not_enabled")
