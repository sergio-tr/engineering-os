"""HTTP route groups. Handlers receive the ControlPlane facade."""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional, Tuple

RouteResult = Tuple[int, bytes, str]
PlaneFactory = Callable[[], Any]


def dispatch_get(
    path: str,
    *,
    qs: Dict[str, list],
    plane: Any,
    helpers: Dict[str, Callable[..., RouteResult]],
) -> Optional[RouteResult]:
    """Try capability-oriented GET handlers. Return None to fall through."""
    from engineering_os.interfaces.http.routes import cursor as cursor_routes
    from engineering_os.interfaces.http.routes import network as network_routes
    from engineering_os.interfaces.http.routes import runtime as runtime_routes

    for mod in (cursor_routes, network_routes, runtime_routes):
        result = mod.handle_get(path, qs=qs, plane=plane, helpers=helpers)
        if result is not None:
            return result
    return None
