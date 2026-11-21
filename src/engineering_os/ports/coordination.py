"""OpenClaw / coordinator ports (extension point)."""

from __future__ import annotations

from typing import Any, Dict, Protocol, runtime_checkable


@runtime_checkable
class CoordinatorPort(Protocol):
    def status(self) -> Dict[str, Any]: ...
