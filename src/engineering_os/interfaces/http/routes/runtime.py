"""Runtime readiness HTTP routes."""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional, Tuple

RouteResult = Tuple[int, bytes, str]


def handle_get(
    path: str,
    *,
    qs: Dict[str, list],
    plane: Any,
    helpers: Dict[str, Callable[..., RouteResult]],
) -> Optional[RouteResult]:
    del qs
    json_bytes = helpers["json_bytes"]
    if path == "/api/runtime/status":
        return json_bytes(plane.runtime_status())
    if path == "/api/runtime/requirements":
        return json_bytes(plane.runtime_requirements())
    if path == "/api/runtime/inspect":
        return json_bytes(plane.runtime_inspect())
    return None
