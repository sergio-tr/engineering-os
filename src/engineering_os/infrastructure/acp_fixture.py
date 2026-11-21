"""Deterministic ACP fixture peer (EOS-08) — NDJSON subset, not Cursor ACP."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
import json
import uuid

from engineering_os.infrastructure.acp_protocol import (
    SUPPORTED_PROTOCOL_VERSION,
    make_error_response,
    make_notification,
    make_response,
    parse_message,
)
from engineering_os.domain.models import utc_now


FIXTURE_PROTOCOL_SUBSET = (
    "initialize",
    "authenticate",
    "session/new",
    "session/prompt",
    "session/cancel",
    "session/update",  # outbound notification only
)

FIXTURE_AGENT_NAME = "eos-acp-fixture"


class AcpFixturePeer:
    """In-process ACP fixture used by injected OCI processes and unit tests."""

    def __init__(self) -> None:
        self.initialized = False
        self.session_id: Optional[str] = None
        self.cancelled = False

    def handle_line(self, line: str) -> List[str]:
        line = line.strip()
        if not line:
            return []
        raw = json.loads(line)
        parse_message(raw)
        return [json.dumps(msg, separators=(",", ":")) for msg in self.handle(raw)]

    def handle(self, message: Dict[str, Any]) -> List[Dict[str, Any]]:
        method = message.get("method")
        req_id = message.get("id")
        if method == "initialize":
            self.initialized = True
            return [
                make_response(
                    req_id,
                    {
                        "protocolVersion": SUPPORTED_PROTOCOL_VERSION,
                        "agentCapabilities": {"loadSession": True},
                        "agentInfo": {"name": FIXTURE_AGENT_NAME, "version": "eos08"},
                    },
                )
            ]
        if method == "authenticate":
            if not self.initialized:
                return [make_error_response(req_id, -32001, "not_initialized")]
            return [make_response(req_id, {"ok": True})]
        if method == "session/new":
            self.session_id = f"fix-sess-{uuid.uuid4().hex[:12]}"
            return [make_response(req_id, {"sessionId": self.session_id})]
        if method == "session/prompt":
            if self.cancelled:
                return [make_error_response(req_id, -32004, "cancelled")]
            note = make_notification(
                "session/update",
                {
                    "sessionId": self.session_id,
                    "update": {
                        "sessionUpdate": "agent_message_chunk",
                        "content": {"text": "fixture working"},
                    },
                },
            )
            result = make_response(
                req_id,
                {
                    "stopReason": "end_turn",
                    "evidence": [f"oci-fixture-{self.session_id}"],
                    "completedAt": utc_now(),
                },
            )
            return [note, result]
        if method == "session/cancel":
            self.cancelled = True
            return [make_response(req_id, {"cancelled": True})]
        return [make_error_response(req_id, -32601, f"method_not_found_fixture:{method}")]


def fixture_script_path() -> str:
    from pathlib import Path

    return str(Path(__file__).resolve().parent / "fixtures" / "acp_fixture.sh")
