"""Cursor / smoke / deployment HTTP routes (read-only / dry-run)."""

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
    json_bytes = helpers["json_bytes"]
    if path == "/api/cursor/status":
        return json_bytes(plane.cursor_status())
    if path == "/api/cursor/readiness":
        return json_bytes(plane.cursor_readiness())
    if path == "/api/cursor/live-preflight":
        return json_bytes(plane.cursor_live_preflight())
    if path == "/api/cursor/deployment-sequence":
        return json_bytes(plane.owner_deployment_sequence())
    if path == "/api/cursor/smoke":
        return json_bytes(plane.cursor_smoke(dry_run=True))
    if path == "/api/cursor/sessions":
        project_id = (qs.get("project_id") or [None])[0]
        return json_bytes({"sessions": plane.cursor_sessions(project_id=project_id)})
    if path.startswith("/api/cursor/evidence/"):
        execution_id = path.rsplit("/", 1)[-1]
        return json_bytes(plane.cursor_evidence(execution_id))
    if path == "/api/cursor/integration-check":
        return json_bytes(plane.cursor_integration_check())
    return None
