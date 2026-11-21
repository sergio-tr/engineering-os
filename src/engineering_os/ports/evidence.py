"""Evidence storage port."""

from __future__ import annotations

from typing import Any, Dict, List, Protocol, runtime_checkable


@runtime_checkable
class EvidencePort(Protocol):
    def store(
        self,
        execution_id: str,
        refs: List[str],
        payload: Dict[str, Any],
    ) -> Dict[str, Any]: ...
