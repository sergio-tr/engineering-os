"""ACP JSON-RPC 2.0 envelopes and Cursor ACP method helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional
import uuid


SUPPORTED_PROTOCOL_VERSION = 1
MAX_MESSAGE_BYTES = 256_000


class AcpProtocolError(ValueError):
    def __init__(self, message: str, *, code: str = "acp_protocol_error") -> None:
        super().__init__(message)
        self.code = code


@dataclass
class JsonRpcMessage:
    payload: Dict[str, Any]

    @property
    def is_request(self) -> bool:
        return "method" in self.payload and "id" in self.payload

    @property
    def is_notification(self) -> bool:
        return "method" in self.payload and "id" not in self.payload

    @property
    def is_response(self) -> bool:
        return "id" in self.payload and ("result" in self.payload or "error" in self.payload)


def new_request_id() -> int:
    return int(uuid.uuid4().int % 1_000_000_000) + 1


def make_request(method: str, params: Optional[Dict[str, Any]] = None, *, id: Optional[int] = None) -> Dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": id if id is not None else new_request_id(),
        "method": method,
        "params": params or {},
    }


def make_notification(method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "method": method, "params": params or {}}


def make_response(id: Any, result: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": id, "result": result}


def make_error_response(id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}


def parse_message(raw: Dict[str, Any]) -> JsonRpcMessage:
    if not isinstance(raw, dict):
        raise AcpProtocolError("message_not_object", code="malformed")
    if raw.get("jsonrpc") != "2.0":
        raise AcpProtocolError("invalid_jsonrpc_version", code="malformed")
    encoded = str(raw)
    if len(encoded.encode("utf-8")) > MAX_MESSAGE_BYTES:
        raise AcpProtocolError("message_too_large", code="size_limit")
    has_method = "method" in raw
    has_id = "id" in raw
    has_result = "result" in raw
    has_error = "error" in raw
    if has_method and (has_result or has_error):
        raise AcpProtocolError("ambiguous_message", code="malformed")
    if not has_method and not (has_result or has_error):
        raise AcpProtocolError("empty_message", code="malformed")
    if (has_result or has_error) and not has_id:
        raise AcpProtocolError("response_missing_id", code="malformed")
    return JsonRpcMessage(payload=raw)


def initialize_params(*, client_name: str = "engineering-os") -> Dict[str, Any]:
    return {
        "protocolVersion": SUPPORTED_PROTOCOL_VERSION,
        "clientCapabilities": {
            "fs": {"readTextFile": False, "writeTextFile": False},
            "terminal": False,
        },
        "clientInfo": {"name": client_name, "version": "0.1.0-eos06"},
    }


def permission_deny_result() -> Dict[str, Any]:
    # Cursor docs: allow-once | allow-always | reject-once
    return {"outcome": {"outcome": "selected", "optionId": "reject-once"}}


@dataclass
class PendingRequest:
    request_id: int
    method: str
    meta: Dict[str, Any] = field(default_factory=dict)
