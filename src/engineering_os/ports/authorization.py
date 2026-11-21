"""Owner decision / approval ports."""

from __future__ import annotations

from typing import Any, Dict, Protocol, runtime_checkable


@runtime_checkable
class OwnerDecisionPort(Protocol):
    def decide(
        self, *, action: str, scope: str, approver: str, approve: bool
    ) -> Dict[str, Any]: ...
