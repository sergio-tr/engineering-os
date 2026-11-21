"""External repository integration ports (GitHub read-only / synthetic)."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class RepositoryIntegrationPort(Protocol):
    def observe(self, project_id: str, execution_id: str) -> Any: ...

    def simulate_pr(self, project_id: str, execution_id: str) -> Any: ...
