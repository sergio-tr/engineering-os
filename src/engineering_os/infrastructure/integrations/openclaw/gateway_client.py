"""Authenticated OpenClaw Gateway client (protocol-shaped; injected transports).

Official protocol: https://docs.openclaw.ai/gateway/protocol
Does not invent RPC methods. Does not auto-pair devices. Does not install packages.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
import time
import uuid

from engineering_os.infrastructure.evidence import ERROR, LIVE_READ_ONLY, UNAVAILABLE
from engineering_os.infrastructure.integrations.openclaw.gateway_transport import (
    GatewaySessionState,
    GatewayTransport,
    UnavailableGatewayTransport,
)


SUPPORTED_GATEWAY_PROTOCOL_VERSIONS = frozenset({3})
DEFAULT_OPERATOR_SCOPES = ("operator.read",)


class GatewayClientError(RuntimeError):
    def __init__(self, message: str, *, code: str = "gateway_client_error") -> None:
        super().__init__(message)
        self.code = code


@dataclass
class GatewayHelloOk:
    protocol_version: int
    server_name: str
    scopes_granted: List[str]
    methods: List[str]
    device_paired: bool
    challenge: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol_version": self.protocol_version,
            "server_name": self.server_name,
            "scopes_granted": list(self.scopes_granted),
            "methods": list(self.methods),
            "device_paired": self.device_paired,
            "challenge": self.challenge,
        }


@dataclass
class OpenClawGatewayClient:
    """Gateway WS client over an injected transport.

    When no authenticated transport is configured, reports unavailable precisely.
    """

    transport: GatewayTransport
    requested_scopes: tuple[str, ...] = DEFAULT_OPERATOR_SCOPES
    role: str = "operator"
    connect_deadline_seconds: float = 5.0
    auto_pair: bool = False
    _state: GatewaySessionState = field(default_factory=GatewaySessionState)
    _hello: Optional[GatewayHelloOk] = None
    _pending: Dict[str, str] = field(default_factory=dict)
    _events: List[Dict[str, Any]] = field(default_factory=list)
    _seq: int = 0

    def connect(self) -> GatewaySessionState:
        if self.auto_pair:
            raise GatewayClientError(
                "silent_device_pairing_forbidden",
                code="pairing_forbidden",
            )
        state = self.transport.connect()
        self._state = state
        if not state.transport_available:
            return state
        # Handshake-shaped connect frame (documented Gateway protocol).
        connect_id = self._next_id()
        frame = {
            "type": "req",
            "id": connect_id,
            "method": "connect",
            "params": {
                "minProtocol": min(SUPPORTED_GATEWAY_PROTOCOL_VERSIONS),
                "maxProtocol": max(SUPPORTED_GATEWAY_PROTOCOL_VERSIONS),
                "client": {
                    "id": "engineering-os",
                    "version": "0.1.0-eos07",
                    "platform": "linux",
                    "mode": "operator",
                },
                "role": self.role,
                "scopes": list(self.requested_scopes),
            },
        }
        try:
            response = self.transport.call("connect", frame["params"])
        except Exception as exc:  # noqa: BLE001
            self._state = GatewaySessionState(
                transport_available=True,
                authenticated=False,
                connection_lifecycle="error",
                last_error=str(exc),
            )
            return self._state
        return self._apply_hello(response)

    def _apply_hello(self, response: Dict[str, Any]) -> GatewaySessionState:
        if response.get("error"):
            err = response["error"]
            code = err.get("code") if isinstance(err, dict) else "connect_failed"
            if code in {"pairing_required", "DEVICE_PAIRING_REQUIRED"}:
                self._state = GatewaySessionState(
                    transport_available=True,
                    authenticated=False,
                    paired=False,
                    connection_lifecycle="pairing_required",
                    last_error="pairing_required",
                )
                return self._state
            self._state = GatewaySessionState(
                transport_available=True,
                authenticated=False,
                connection_lifecycle="error",
                last_error=str(err),
            )
            return self._state
        result = response.get("result") or response.get("payload") or response
        version = int(result.get("protocol") or result.get("protocolVersion") or 0)
        if version not in SUPPORTED_GATEWAY_PROTOCOL_VERSIONS:
            self._state = GatewaySessionState(
                transport_available=True,
                authenticated=False,
                connection_lifecycle="protocol_mismatch",
                last_error=f"unsupported_protocol_version:{version}",
            )
            return self._state
        scopes = list(result.get("scopes") or result.get("scopesGranted") or [])
        missing = [s for s in self.requested_scopes if s not in scopes]
        if missing:
            self._state = GatewaySessionState(
                transport_available=True,
                authenticated=False,
                paired=bool(result.get("devicePaired", result.get("paired"))),
                scopes=scopes,
                connection_lifecycle="scope_denied",
                last_error=f"missing_scopes:{','.join(missing)}",
            )
            return self._state
        methods = list(result.get("methods") or result.get("supportedMethods") or [])
        self._hello = GatewayHelloOk(
            protocol_version=version,
            server_name=str(result.get("serverName") or "openclaw-gateway"),
            scopes_granted=scopes,
            methods=methods,
            device_paired=bool(result.get("devicePaired", result.get("paired", True))),
            challenge=result.get("challenge"),
        )
        self._state = GatewaySessionState(
            transport_available=True,
            authenticated=True,
            paired=self._hello.device_paired,
            scopes=scopes,
            supported_methods=methods,
            connection_lifecycle="connected",
            last_error=None,
        )
        return self._state

    def call(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not self._state.authenticated:
            raise GatewayClientError(
                self._state.last_error or "not_authenticated",
                code="not_authenticated",
            )
        # Refuse write/admin methods unless explicitly in granted scopes.
        if method.startswith(("config.", "device.", "admin.", "approvals.")) and (
            "operator.admin" not in self._state.scopes
            and "operator.write" not in self._state.scopes
        ):
            raise GatewayClientError("scope_insufficient", code="missing_scope")
        req_id = self._next_id()
        self._pending[req_id] = method
        try:
            response = self.transport.call(method, params or {})
        except Exception as exc:  # noqa: BLE001
            raise GatewayClientError(str(exc), code="transport_error") from exc
        finally:
            self._pending.pop(req_id, None)
        if response.get("error"):
            raise GatewayClientError(str(response["error"]), code="rpc_error")
        return response

    def subscribe_events(self) -> List[Dict[str, Any]]:
        if hasattr(self.transport, "drain_events"):
            events = list(self.transport.drain_events())  # type: ignore[attr-defined]
            self._events.extend(events)
            return events
        return []

    def close(self) -> None:
        self.transport.close()
        self._state.connection_lifecycle = "closed"
        self._state.authenticated = False

    def status(self) -> Dict[str, Any]:
        return {
            **self._state.to_dict(),
            "hello": self._hello.to_dict() if self._hello else None,
            "requested_scopes": list(self.requested_scopes),
            "pending_requests": dict(self._pending),
            "evidence_class": (
                LIVE_READ_ONLY
                if self._state.authenticated
                else (ERROR if self._state.last_error else UNAVAILABLE)
            ),
        }

    def _next_id(self) -> str:
        self._seq += 1
        return f"eos-gw-{self._seq}-{uuid.uuid4().hex[:8]}"


class InMemoryGatewayTransport(GatewayTransport):
    """Deterministic Gateway peer for offline protocol tests."""

    def __init__(
        self,
        *,
        scenario: str = "success",
        protocol_version: int = 3,
        scopes: Optional[List[str]] = None,
        methods: Optional[List[str]] = None,
    ) -> None:
        self.scenario = scenario
        self.protocol_version = protocol_version
        self.scopes = scopes or ["operator.read"]
        self.methods = methods or [
            "connect",
            "system.status",
            "sessions.list",
            "agent.list",
        ]
        self._connected = False
        self._events: List[Dict[str, Any]] = []
        self.calls: List[Dict[str, Any]] = []

    def connect(self) -> GatewaySessionState:
        if self.scenario == "unavailable":
            return GatewaySessionState(
                transport_available=False,
                connection_lifecycle="unavailable",
                last_error="websocket_transport_not_enabled",
            )
        self._connected = True
        return GatewaySessionState(
            transport_available=True,
            connection_lifecycle="connecting",
        )

    def close(self) -> None:
        self._connected = False

    def call(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        self.calls.append({"method": method, "params": params or {}})
        if not self._connected and method != "connect":
            raise GatewayClientError("connection_interrupted", code="interrupted")
        if method == "connect":
            if self.scenario == "auth_failure":
                return {"error": {"code": "auth_failed", "message": "invalid_token"}}
            if self.scenario == "pairing_required":
                return {"error": {"code": "pairing_required", "message": "device unpaired"}}
            if self.scenario == "unsupported_protocol":
                return {
                    "result": {
                        "protocol": 99,
                        "scopes": self.scopes,
                        "methods": self.methods,
                        "devicePaired": True,
                    }
                }
            if self.scenario == "missing_scope":
                return {
                    "result": {
                        "protocol": self.protocol_version,
                        "scopes": [],
                        "methods": self.methods,
                        "devicePaired": True,
                    }
                }
            if self.scenario == "interrupt":
                self._connected = False
                raise GatewayClientError("connection_interrupted", code="interrupted")
            return {
                "result": {
                    "protocol": self.protocol_version,
                    "serverName": "fixture-gateway",
                    "scopes": self.scopes,
                    "methods": self.methods,
                    "devicePaired": True,
                    "challenge": None,
                }
            }
        if self.scenario == "interrupt":
            raise GatewayClientError("connection_interrupted", code="interrupted")
        return {"result": {"ok": True, "method": method, "params": params or {}}}

    def drain_events(self) -> List[Dict[str, Any]]:
        items = list(self._events)
        self._events.clear()
        return items

    def push_event(self, event: Dict[str, Any]) -> None:
        self._events.append(event)


def default_gateway_client() -> OpenClawGatewayClient:
    """Production default: unavailable until an authenticated transport is injected."""
    return OpenClawGatewayClient(transport=UnavailableGatewayTransport())
