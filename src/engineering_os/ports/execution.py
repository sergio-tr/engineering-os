"""Execution adapter ports."""

from __future__ import annotations

from typing import Any, Dict, Protocol, runtime_checkable


@runtime_checkable
class ExecutionPort(Protocol):
    def dispatch(self, request: Any) -> Dict[str, Any]: ...
