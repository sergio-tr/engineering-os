"""External repository integration ports (GitHub read-only, etc.)."""

from __future__ import annotations

from typing import Any, Dict, Protocol, runtime_checkable


@runtime_checkable
class RepositoryIntegrationPort(Protocol):
    def readiness(self) -> Dict[str, Any]: ...
