"""Organization / Paperclip coordination ports (extension point)."""

from __future__ import annotations

from typing import Any, Dict, Protocol, runtime_checkable


@runtime_checkable
class OrganizationPort(Protocol):
    def readiness(self) -> Dict[str, Any]: ...
