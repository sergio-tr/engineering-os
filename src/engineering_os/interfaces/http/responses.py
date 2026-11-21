"""Shared HTTP response helpers."""

from __future__ import annotations

import json
from typing import Any, Dict, Tuple


def json_bytes(payload: Dict[str, Any], status: int = 200) -> Tuple[int, bytes, str]:
    body = json.dumps(payload, indent=2, sort_keys=True, default=str).encode("utf-8")
    return status, body, "application/json; charset=utf-8"


def error_json(message: str, status: int = 400) -> Tuple[int, bytes, str]:
    return json_bytes({"ok": False, "error": message}, status=status)
