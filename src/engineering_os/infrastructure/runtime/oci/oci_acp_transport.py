"""ACP NDJSON stdio transport over an OCI process handle."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
import json

from engineering_os.infrastructure.acp_protocol import (
    AcpProtocolError,
    MAX_MESSAGE_BYTES,
    parse_message,
)
from engineering_os.infrastructure.acp_transport import (
    AcpRuntimeAvailability,
    AcpTransport,
    AcpTransportError,
)
from engineering_os.infrastructure.evidence import SYNTHETIC_IN_MEMORY, SYNTHETIC_OCI_EXECUTED
from engineering_os.infrastructure.oci_process import OciProcessHandle, OciProcessError


class OciAcpStdioTransport(AcpTransport):
    """Communicates with a containerized ACP peer via NDJSON stdin/stdout.

    Stderr is never parsed as ACP. Message bodies are never used as shell input.
    Protocol completion is tracked independently from process exit cleanliness.
    """

    name = "oci-acp-stdio"

    def __init__(
        self,
        handle: OciProcessHandle,
        *,
        evidence_class: str = SYNTHETIC_OCI_EXECUTED,
        read_timeout: float = 5.0,
        max_inbox: int = 256,
        grace_seconds: float = 2.0,
        backend_label: str = "oci-acp-fixture",
        agent_id: str = "eos-acp-fixture",
        live_cursor: bool = False,
    ) -> None:
        self.handle = handle
        self.evidence_class = evidence_class
        self.read_timeout = read_timeout
        self.max_inbox = max_inbox
        self.grace_seconds = grace_seconds
        self.backend_label = backend_label
        self.agent_id = agent_id
        self.live_cursor = live_cursor
        self._inbox: List[Dict[str, Any]] = []
        self._closed = False
        self.exchange_count = 0
        self.stderr_bytes = 0
        self.protocol_completed = False
        self.process_exited_cleanly: Optional[bool] = None
        self.exit_code: Optional[int] = None
        self.termination_reason: Optional[str] = None
        self.cleanup_verified = False
        self._close_outcome: Dict[str, Any] = {}

    def availability(self) -> AcpRuntimeAvailability:
        return AcpRuntimeAvailability(
            backend=self.backend_label,
            available=not self._closed,
            evidence_class=self.evidence_class,
            agent_id=self.agent_id,
            protocol_version=1,
            details={
                "container_id": self.handle.container_id,
                "framing": "ndjson",
                "live_cursor": self.live_cursor,
                "note": (
                    "Cursor ACP live path"
                    if self.live_cursor
                    else "fixture subset only; not Cursor ACP live"
                ),
            },
        )

    def mark_protocol_completed(self, completed: bool = True) -> None:
        self.protocol_completed = bool(completed)

    def send(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if self._closed:
            raise AcpTransportError("transport_closed", code="closed")
        parse_message(message)
        encoded = json.dumps(message, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > MAX_MESSAGE_BYTES:
            raise AcpTransportError("message_too_large", code="size_limit")
        try:
            self.handle.write_line(encoded)
        except OciProcessError as exc:
            raise AcpTransportError(str(exc), code=exc.code) from exc
        self.exchange_count += 1
        deadline_reads = 32
        response: Optional[Dict[str, Any]] = None
        for _ in range(deadline_reads):
            line = self.handle.read_line(self.read_timeout)
            if line is None:
                break
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as exc:
                raise AcpTransportError("invalid_json_from_peer", code="bad_json") from exc
            msg = parse_message(raw)
            if msg.is_response and raw.get("id") == message.get("id"):
                response = raw
                break
            if len(self._inbox) >= self.max_inbox:
                raise AcpTransportError("inbox_overflow", code="resource")
            self._inbox.append(raw)
        self.stderr_bytes = len(self.handle.stderr_text.encode("utf-8"))
        if response is None and message.get("method") == "session/prompt":
            for _ in range(8):
                line = self.handle.read_line(self.read_timeout)
                if line is None:
                    break
                raw = json.loads(line)
                parse_message(raw)
                if "id" in raw and ("result" in raw or "error" in raw):
                    if raw.get("id") == message.get("id"):
                        return raw
                self._inbox.append(raw)
        return response

    def poll(self) -> List[Dict[str, Any]]:
        for _ in range(16):
            line = self.handle.read_line(0.01)
            if line is None:
                break
            try:
                raw = json.loads(line)
                parse_message(raw)
                self._inbox.append(raw)
            except (json.JSONDecodeError, AcpProtocolError):
                continue
        items = list(self._inbox)
        self._inbox.clear()
        return items

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        cleanup: Dict[str, Any] = {}
        try:
            cleanup = self.handle.cleanup(grace_seconds=self.grace_seconds)
        except Exception as exc:  # noqa: BLE001
            cleanup = {"cleaned_up": False, "cleanup_verified": False, "error": str(exc)}
        self.exit_code = cleanup.get("exit_code")
        if self.exit_code is None:
            try:
                waited = self.handle.wait(timeout=0.1)
                self.exit_code = waited.returncode
                self.process_exited_cleanly = waited.process_exited_cleanly
                self.termination_reason = waited.termination_reason
            except Exception:
                self.process_exited_cleanly = False
        else:
            self.process_exited_cleanly = bool(cleanup.get("process_exited_cleanly"))
            self.termination_reason = cleanup.get("termination_reason")
        self.cleanup_verified = bool(cleanup.get("cleanup_verified") or cleanup.get("cleaned_up"))
        self._close_outcome = {
            "protocol_completed": self.protocol_completed,
            "process_exited_cleanly": self.process_exited_cleanly,
            "exit_code": self.exit_code,
            "termination_reason": self.termination_reason,
            "cleanup_verified": self.cleanup_verified,
            "sigkill_used": bool(cleanup.get("sigkill_used")),
            "cleanup": cleanup,
        }

    def close_outcome(self) -> Dict[str, Any]:
        return dict(self._close_outcome)

    def summary(self) -> Dict[str, Any]:
        return {
            "exchange_count": self.exchange_count,
            "stderr_bytes": self.stderr_bytes,
            "container_id": self.handle.container_id,
            "evidence_class": self.evidence_class,
            "closed": self._closed,
            "protocol_completed": self.protocol_completed,
            "process_exited_cleanly": self.process_exited_cleanly,
            "exit_code": self.exit_code,
            "termination_reason": self.termination_reason,
            "cleanup_verified": self.cleanup_verified,
            "live_cursor": self.live_cursor,
            "close_outcome": dict(self._close_outcome),
        }
