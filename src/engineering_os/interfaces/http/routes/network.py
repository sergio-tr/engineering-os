"""Network / broker HTTP routes (diagnostics and dry-run only)."""

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
    del qs  # unused
    json_bytes = helpers["json_bytes"]
    if path == "/api/network/status":
        return json_bytes(plane.network_status())
    if path == "/api/network/probe":
        return json_bytes(plane.network_probe(dry_run=True))
    return None
