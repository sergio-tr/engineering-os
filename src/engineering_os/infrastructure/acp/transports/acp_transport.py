"""ACP transports: in-memory synthetic, disabled live, OpenClaw/ACPX and Cursor stubs."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
import uuid

from engineering_os.domain.models import utc_now
from engineering_os.infrastructure.acp.protocol.acp_protocol import (
    SUPPORTED_PROTOCOL_VERSION,
    AcpProtocolError,
    initialize_params,
    make_error_response,
    make_notification,
    make_request,
    make_response,
    parse_message,
    permission_deny_result,
)
from engineering_os.infrastructure.evidence import ERROR, LIVE_READ_ONLY, SYNTHETIC, UNAVAILABLE


class AcpTransportError(RuntimeError):
    def __init__(self, message: str, *, code: str = "acp_transport_error") -> None:
        super().__init__(message)
        self.code = code


@dataclass
class AcpRuntimeAvailability:
    backend: str
    available: bool
    evidence_class: str
    agent_id: str = "cursor"
    protocol_version: Optional[int] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "backend": self.backend,
            "available": self.available,
            "evidence_class": self.evidence_class,
            "agent_id": self.agent_id,
            "protocol_version": self.protocol_version,
            "details": dict(self.details),
        }


class AcpTransport(ABC):
    name: str

    @abstractmethod
    def availability(self) -> AcpRuntimeAvailability:
        raise NotImplementedError

    @abstractmethod
    def send(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Send a JSON-RPC message. May return an immediate response."""
        raise NotImplementedError

    @abstractmethod
    def poll(self) -> List[Dict[str, Any]]:
        """Drain pending notifications/responses from the peer."""
        raise NotImplementedError

    def close(self) -> None:
        return None


class AcpPermissionPolicy:
    """Never auto-approve permission requests."""

    def decide(self, request_params: Dict[str, Any]) -> Dict[str, Any]:
        return permission_deny_result()


class InMemoryAcpTransport(AcpTransport):
    """Deterministic synthetic ACP peer that speaks real JSON-RPC messages."""

    name = "in-memory-synthetic"

    def __init__(
        self,
        *,
        scenario: str = "success",
        permission_policy: Optional[AcpPermissionPolicy] = None,
    ) -> None:
        self.scenario = scenario
        self.permission_policy = permission_policy or AcpPermissionPolicy()
        self._session_id: Optional[str] = None
        self._initialized = False
        self._inbox: List[Dict[str, Any]] = []
        self._closed = False
        self.sent: List[Dict[str, Any]] = []

    def availability(self) -> AcpRuntimeAvailability:
        return AcpRuntimeAvailability(
            backend="synthetic-acp",
            available=True,
            evidence_class=SYNTHETIC,
            protocol_version=SUPPORTED_PROTOCOL_VERSION,
            details={"scenario": self.scenario},
        )

    def send(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if self._closed:
            raise AcpTransportError("transport_closed", code="closed")
        msg = parse_message(message)
        self.sent.append(message)
        if msg.is_response:
            return None
        method = message.get("method")
        req_id = message.get("id")
        params = message.get("params") or {}
        if method == "initialize":
            version = params.get("protocolVersion")
            if version not in {1, SUPPORTED_PROTOCOL_VERSION}:
                return make_error_response(req_id, -32602, "unsupported_protocol_version")
            if self.scenario == "init_fail":
                return make_error_response(req_id, -32000, "initialize_failed")
            self._initialized = True
            return make_response(
                req_id,
                {
                    "protocolVersion": SUPPORTED_PROTOCOL_VERSION,
                    "agentCapabilities": {"loadSession": True},
                    "agentInfo": {"name": "synthetic-cursor-acp", "version": "fixture"},
                },
            )
        if method == "authenticate":
            if not self._initialized:
                return make_error_response(req_id, -32001, "not_initialized")
            return make_response(req_id, {"ok": True})
        if method == "session/new":
            if self.scenario == "session_fail":
                return make_error_response(req_id, -32002, "session_create_failed")
            self._session_id = f"acp-sess-{uuid.uuid4().hex[:12]}"
            return make_response(req_id, {"sessionId": self._session_id})
        if method == "session/prompt":
            session_id = params.get("sessionId")
            if session_id != self._session_id:
                return make_error_response(req_id, -32602, "unknown_session")
            if self.scenario == "permission_denied":
                perm_id = new_local_id()
                self._inbox.append(
                    make_request(
                        "session/request_permission",
                        {"toolCallId": "tool-1", "title": "Write file"},
                        id=perm_id,
                    )
                )
                # Client must respond; session manager denies by policy.
                return None
            if self.scenario == "timeout":
                self._inbox.append(
                    make_notification(
                        "session/update",
                        {
                            "sessionId": session_id,
                            "update": {
                                "sessionUpdate": "agent_message_chunk",
                                "content": {"text": "still working..."},
                            },
                        },
                    )
                )
                return None
            if self.scenario == "interrupt":
                self._inbox.append(
                    make_notification(
                        "session/update",
                        {
                            "sessionId": session_id,
                            "update": {"sessionUpdate": "interrupted"},
                        },
                    )
                )
                return make_error_response(req_id, -32003, "transport_interrupted")
            # Stream progress then complete.
            self._inbox.append(
                make_notification(
                    "session/update",
                    {
                        "sessionId": session_id,
                        "update": {
                            "sessionUpdate": "agent_message_chunk",
                            "content": {"text": "Working on task..."},
                        },
                    },
                )
            )
            self._inbox.append(
                make_notification(
                    "session/update",
                    {
                        "sessionId": session_id,
                        "update": {
                            "sessionUpdate": "agent_message_chunk",
                            "content": {"text": "Done."},
                        },
                    },
                )
            )
            return make_response(
                req_id,
                {
                    "stopReason": "end_turn",
                    "evidence": [f"synth-acp-evidence-{session_id[-8:]}"],
                    "completedAt": utc_now(),
                },
            )
        if method == "session/cancel":
            return make_response(req_id, {"cancelled": True})
        return make_error_response(req_id, -32601, f"method_not_found:{method}")

    def poll(self) -> List[Dict[str, Any]]:
        items = list(self._inbox)
        self._inbox.clear()
        return items

    def close(self) -> None:
        self._closed = True


def new_local_id() -> int:
    return int(uuid.uuid4().int % 1_000_000_000) + 1


class DisabledLiveAcpTransport(AcpTransport):
    """Rejects live ACP at the transport boundary while SANDBOX is unapproved."""

    name = "live-acp-disabled"

    def __init__(self, *, sandbox_gate: str = "NOT_TESTED") -> None:
        self.sandbox_gate = sandbox_gate

    def availability(self) -> AcpRuntimeAvailability:
        return AcpRuntimeAvailability(
            backend="live-disabled",
            available=False,
            evidence_class=ERROR,
            details={
                "sandbox_gate": self.sandbox_gate,
                "reason": "live_acp_disabled_sandbox_not_pass",
            },
        )

    def send(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        raise AcpTransportError(
            "live_acp_disabled_sandbox_not_pass",
            code="sandbox_blocked",
        )

    def poll(self) -> List[Dict[str, Any]]:
        return []


class OpenClawAcpxExecutionTransport(AcpTransport):
    """OpenClaw → ACPX → Cursor integration contract (unavailable without live deps)."""

    name = "openclaw-acpx"

    def __init__(
        self,
        *,
        agent_id: str = "cursor",
        enabled: bool = False,
        sandbox_authorized: bool = False,
    ) -> None:
        self.agent_id = agent_id
        self.enabled = enabled
        self.sandbox_authorized = sandbox_authorized

    def availability(self) -> AcpRuntimeAvailability:
        if not self.enabled:
            return AcpRuntimeAvailability(
                backend="openclaw-acpx",
                available=False,
                evidence_class=UNAVAILABLE,
                agent_id=self.agent_id,
                details={
                    "note": (
                        "OpenClaw ACPX transport prepared; authenticated Gateway/ACPX "
                        "dispatch is not enabled in EOS-06"
                    ),
                    "docs": "https://docs.openclaw.ai/tools/acp-agents",
                },
            )
        if not self.sandbox_authorized:
            return AcpRuntimeAvailability(
                backend="openclaw-acpx",
                available=False,
                evidence_class=ERROR,
                agent_id=self.agent_id,
                details={"reason": "sandbox_not_authorized"},
            )
        return AcpRuntimeAvailability(
            backend="openclaw-acpx",
            available=True,
            evidence_class=LIVE_READ_ONLY,
            agent_id=self.agent_id,
        )

    def send(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        avail = self.availability()
        if not avail.available:
            raise AcpTransportError(
                avail.details.get("reason") or "openclaw_acpx_unavailable",
                code="unavailable",
            )
        raise AcpTransportError(
            "openclaw_acpx_live_dispatch_not_implemented_in_eos06",
            code="not_implemented",
        )

    def poll(self) -> List[Dict[str, Any]]:
        return []


class CursorAcpAdapter(AcpTransport):
    """Cursor ACP protocol adapter over an injected peer transport.

    Understands initialize / session/new / session/prompt / cancel / permissions.
    Does not spawn Cursor processes. A direct stdio launcher remains disabled.
    """

    name = "cursor-acp-adapter"

    def __init__(
        self,
        peer: AcpTransport,
        *,
        allow_direct_process: bool = False,
        sandbox_authorized: bool = False,
    ) -> None:
        self.peer = peer
        self.allow_direct_process = allow_direct_process
        self.sandbox_authorized = sandbox_authorized
        if allow_direct_process and not sandbox_authorized:
            # Hard reject unguarded direct-process bypass configuration.
            raise AcpTransportError(
                "direct_process_bypass_rejected",
                code="sandbox_blocked",
            )

    def availability(self) -> AcpRuntimeAvailability:
        peer_av = self.peer.availability()
        return AcpRuntimeAvailability(
            backend=f"cursor-over:{peer_av.backend}",
            available=peer_av.available,
            evidence_class=peer_av.evidence_class,
            agent_id="cursor",
            protocol_version=SUPPORTED_PROTOCOL_VERSION,
            details={
                **peer_av.details,
                "direct_process_enabled": False,
                "command_candidates": ["cursor-agent acp", "agent acp"],
                "docs": "https://cursor.com/docs/cli/acp",
            },
        )

    def send(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return self.peer.send(message)

    def poll(self) -> List[Dict[str, Any]]:
        return self.peer.poll()

    def close(self) -> None:
        self.peer.close()
