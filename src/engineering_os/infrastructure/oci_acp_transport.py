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
    """Communicates with a containerized ACP fixture via NDJSON stdin/stdout.

    Stderr is never parsed as ACP. Message bodies are never used as shell input.
    """

    name = "oci-acp-stdio"

    def __init__(
        self,
        handle: OciProcessHandle,
        *,
        evidence_class: str = SYNTHETIC_OCI_EXECUTED,
        read_timeout: float = 5.0,
        max_inbox: int = 256,
    ) -> None:
        self.handle = handle
        self.evidence_class = evidence_class
        self.read_timeout = read_timeout
        self.max_inbox = max_inbox
        self._inbox: List[Dict[str, Any]] = []
        self._closed = False
        self.exchange_count = 0
        self.stderr_bytes = 0

    def availability(self) -> AcpRuntimeAvailability:
        return AcpRuntimeAvailability(
            backend="oci-acp-fixture",
            available=not self._closed,
            evidence_class=self.evidence_class,
            agent_id="eos-acp-fixture",
            protocol_version=1,
            details={
                "container_id": self.handle.container_id,
                "framing": "ndjson",
                "note": "fixture subset only; not Cursor ACP live",
            },
        )

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
        # Drain immediate responses/notifications until matching response or empty.
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
        # Capture stderr size (not parsed).
        self.stderr_bytes = len(self.handle.stderr_text.encode("utf-8"))
        if response is None and message.get("method") == "session/prompt":
            # Some fixtures stream notifications first; try a few more reads.
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
        # Non-blocking drain of any leftover lines.
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
        self._closed = True
        try:
            self.handle.terminate()
        except Exception:
            pass
        try:
            self.handle.cleanup()
        except Exception:
            pass

    def summary(self) -> Dict[str, Any]:
        return {
            "exchange_count": self.exchange_count,
            "stderr_bytes": self.stderr_bytes,
            "container_id": self.handle.container_id,
            "evidence_class": self.evidence_class,
            "closed": self._closed,
        }
