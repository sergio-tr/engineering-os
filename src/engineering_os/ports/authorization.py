"""Owner decision / approval ports."""

from __future__ import annotations

from typing import Any, Dict, Protocol, runtime_checkable


@runtime_checkable
class OwnerDecisionPort(Protocol):
    def decide(self, approval: Any) -> Dict[str, Any]: ...
