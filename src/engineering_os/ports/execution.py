"""Execution adapter ports."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ExecutionPort(Protocol):
    def dispatch(self, request: Any) -> Any: ...
