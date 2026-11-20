"""Localhost-only HTTP API and static dashboard for Engineering OS."""

from __future__ import annotations

import json
import secrets
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from engineering_os.application.orchestrator import SequentialOrchestrator
from engineering_os.application.services import ControlPlane, PolicyError
from engineering_os.domain.states import IllegalTransitionError

WEB_ROOT = Path(__file__).resolve().parents[3] / "web"
CSRF_COOKIE = "eos_csrf"


def _json_bytes(data: Any, status: int = 200) -> Tuple[int, bytes, str]:
    body = json.dumps(data, indent=2, sort_keys=True, default=str).encode("utf-8")
    return status, body, "application/json; charset=utf-8"


class AppState:
    def __init__(self, plane: ControlPlane) -> None:
        self.plane = plane
        self.orchestrator = SequentialOrchestrator(plane)
        self.lock = __import__("threading").RLock()


def make_handler(state: AppState) -> Callable[..., BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: Any) -> None:  # quieter tests
            if getattr(self.server, "quiet", False):
                return
            super().log_message(fmt, *args)

        def _origin_ok(self) -> bool:
            origin = self.headers.get("Origin")
            if not origin:
                # Non-browser or same-origin navigations without Origin are allowed
                # for GET; mutations still require CSRF token.
                return True
            host = self.headers.get("Host", "")
            parsed = urllib.parse.urlparse(origin)
            expected = f"{parsed.scheme}://{host}"
            # Origin host must match request Host (localhost-only binding).
            return parsed.netloc == host or origin in {
                f"http://{host}",
                f"https://{host}",
                expected,
            }

        def _csrf_token(self) -> Optional[str]:
            cookie = self.headers.get("Cookie", "")
            for part in cookie.split(";"):
                part = part.strip()
                if part.startswith(CSRF_COOKIE + "="):
                    return part.split("=", 1)[1]
            return None

        def _ensure_csrf_cookie(self) -> str:
            token = self._csrf_token()
            if not token:
                token = secrets.token_urlsafe(24)
            self._set_csrf = token
            return token

        def _check_mutation_guards(self) -> Optional[Tuple[int, Dict[str, Any]]]:
            if not self._origin_ok():
                return 403, {"ok": False, "error": "origin_rejected"}
            header = self.headers.get("X-CSRF-Token")
            cookie = self._csrf_token()
            if not header or not cookie or not secrets.compare_digest(header, cookie):
                return 403, {"ok": False, "error": "csrf_rejected"}
            return None

        def _read_json(self) -> Dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length <= 0:
                return {}
            raw = self.rfile.read(length)
            if not raw:
                return {}
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict):
                raise ValueError("JSON body must be an object")
            return data

        def _send(
            self,
            status: int,
            body: bytes,
            content_type: str,
            *,
            extra_headers: Optional[Dict[str, str]] = None,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            token = getattr(self, "_set_csrf", None)
            if token:
                self.send_header(
                    "Set-Cookie",
                    f"{CSRF_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict",
                )
            if extra_headers:
                for k, v in extra_headers.items():
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _serve_static(self, rel: str) -> None:
            if ".." in rel or rel.startswith("/"):
                self._send(404, b"not found", "text/plain")
                return
            path = (WEB_ROOT / rel).resolve()
            if not str(path).startswith(str(WEB_ROOT.resolve())) or not path.is_file():
                self._send(404, b"not found", "text/plain")
                return
            data = path.read_bytes()
            ctype = {
                ".html": "text/html; charset=utf-8",
                ".css": "text/css; charset=utf-8",
                ".js": "application/javascript; charset=utf-8",
                ".svg": "image/svg+xml",
                ".json": "application/json",
            }.get(path.suffix, "application/octet-stream")
            self._ensure_csrf_cookie()
            self._send(200, data, ctype)

        def do_GET(self) -> None:  # noqa: N802
            with state.lock:
                self._do_GET_locked()

        def _do_GET_locked(self) -> None:
            self._ensure_csrf_cookie()
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            qs = urllib.parse.parse_qs(parsed.query)
            try:
                if path == "/api/health":
                    from engineering_os.application.services import DEMO_PROJECT_ID

                    demo = state.plane.repo.get_project(DEMO_PROJECT_ID)
                    status, body, ctype = _json_bytes(
                        {
                            "ok": True,
                            "sandbox_gate": state.plane.sandbox_gate,
                            "live_execution_enabled": False,
                            "bind": "127.0.0.1",
                            "demo_seeded": demo is not None,
                            "demo_project_id": DEMO_PROJECT_ID if demo else None,
                            "mode": "SYNTHETIC",
                        }
                    )
                    self._send(status, body, ctype)
                    return
                if path == "/api/demo/status":
                    status, body, ctype = _json_bytes(state.plane.demo_snapshot())
                    self._send(status, body, ctype)
                    return
                if path == "/api/overview":
                    status, body, ctype = _json_bytes(state.plane.overview())
                    self._send(status, body, ctype)
                    return
                if path == "/api/projects":
                    status, body, ctype = _json_bytes(
                        [p.to_dict() for p in state.plane.list_projects()]
                    )
                    self._send(status, body, ctype)
                    return
                if path.startswith("/api/projects/") and path.count("/") == 3:
                    project_id = path.rsplit("/", 1)[-1]
                    project = state.plane.get_project(project_id)
                    goals = [
                        g.to_dict()
                        for g in state.plane.repo.list_goals(project_id=project_id)
                    ]
                    tasks = [
                        t.to_dict()
                        for t in state.plane.repo.list_tasks(project_id=project_id)
                    ]
                    executions = [
                        e.to_dict()
                        for e in state.plane.repo.list_executions(project_id=project_id)
                    ]
                    queue = state.orchestrator.queue_snapshot(project_id)
                    status, body, ctype = _json_bytes(
                        {
                            "project": project.to_dict(),
                            "goals": goals,
                            "tasks": tasks,
                            "executions": executions,
                            "orchestration": queue,
                        }
                    )
                    self._send(status, body, ctype)
                    return
                if path == "/api/goals":
                    project_id = (qs.get("project_id") or [None])[0]
                    status, body, ctype = _json_bytes(
                        [
                            g.to_dict()
                            for g in state.plane.repo.list_goals(project_id=project_id)
                        ]
                    )
                    self._send(status, body, ctype)
                    return
                if path == "/api/tasks":
                    project_id = (qs.get("project_id") or [None])[0]
                    state_filter = (qs.get("state") or [None])[0]
                    tasks = state.plane.repo.list_tasks(
                        project_id=project_id, state=state_filter
                    )
                    enriched = []
                    for t in tasks:
                        d = t.to_dict()
                        d["ineligibility_reason"] = state.plane.task_ineligibility_reason(
                            t.task_id
                        )
                        enriched.append(d)
                    status, body, ctype = _json_bytes(enriched)
                    self._send(status, body, ctype)
                    return
                if path == "/api/executions":
                    project_id = (qs.get("project_id") or [None])[0]
                    status, body, ctype = _json_bytes(
                        [
                            e.to_dict()
                            for e in state.plane.repo.list_executions(
                                project_id=project_id
                            )
                        ]
                    )
                    self._send(status, body, ctype)
                    return
                if path.startswith("/api/executions/") and path.count("/") == 3:
                    execution_id = path.rsplit("/", 1)[-1]
                    execution = state.plane._require_execution(execution_id)
                    events = state.plane.repo.list_events(
                        aggregate_type="execution", aggregate_id=execution_id
                    )
                    status, body, ctype = _json_bytes(
                        {
                            "execution": execution.to_dict(),
                            "events": [e.to_dict() for e in events],
                            "mode": "SYNTHETIC" if execution.synthetic else "LIVE",
                        }
                    )
                    self._send(status, body, ctype)
                    return
                if path == "/api/events":
                    limit = int((qs.get("limit") or ["50"])[0])
                    status, body, ctype = _json_bytes(
                        [e.to_dict() for e in state.plane.repo.list_events(limit=limit)]
                    )
                    self._send(status, body, ctype)
                    return
                if path == "/api/orchestration":
                    project_id = (qs.get("project_id") or [None])[0]
                    if not project_id:
                        status, body, ctype = _json_bytes(
                            {"ok": False, "error": "project_id required"}, 400
                        )
                        self._send(status, body, ctype)
                        return
                    status, body, ctype = _json_bytes(
                        state.orchestrator.queue_snapshot(project_id)
                    )
                    self._send(status, body, ctype)
                    return
                if path == "/api/csrf":
                    token = self._ensure_csrf_cookie()
                    status, body, ctype = _json_bytes({"csrf_token": token})
                    self._send(status, body, ctype)
                    return
                if path in {"/", "/index.html"}:
                    self._serve_static("index.html")
                    return
                if path.startswith("/static/"):
                    self._serve_static(path[len("/static/") :])
                    return
                # Direct asset paths
                if path.lstrip("/") in {"app.css", "app.js"}:
                    self._serve_static(path.lstrip("/"))
                    return
                status, body, ctype = _json_bytes(
                    {"ok": False, "error": "not_found"}, 404
                )
                self._send(status, body, ctype)
            except KeyError as exc:
                status, body, ctype = _json_bytes(
                    {"ok": False, "error": str(exc)}, 404
                )
                self._send(status, body, ctype)
            except Exception as exc:  # noqa: BLE001
                status, body, ctype = _json_bytes(
                    {"ok": False, "error": str(exc)}, 500
                )
                self._send(status, body, ctype)

        def do_POST(self) -> None:  # noqa: N802
            with state.lock:
                self._do_POST_locked()

        def _do_POST_locked(self) -> None:
            self._ensure_csrf_cookie()
            guard = self._check_mutation_guards()
            if guard:
                status_code, payload = guard
                status, body, ctype = _json_bytes(payload, status_code)
                self._send(status, body, ctype)
                return
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            try:
                data = self._read_json()
                if path == "/api/projects":
                    project = state.plane.create_project(
                        data["name"], data["repository_identity"]
                    )
                    status, body, ctype = _json_bytes(project.to_dict(), 201)
                    self._send(status, body, ctype)
                    return
                if path == "/api/goals":
                    goal = state.plane.create_goal(
                        data["project_id"],
                        data["title"],
                        data.get("description", ""),
                        priority=int(data.get("priority", 100)),
                    )
                    status, body, ctype = _json_bytes(goal.to_dict(), 201)
                    self._send(status, body, ctype)
                    return
                if path == "/api/goals/approve":
                    goal, approval = state.plane.approve_goal(
                        data["goal_id"],
                        approver=data.get("approver", "owner-synthetic"),
                    )
                    status, body, ctype = _json_bytes(
                        {"goal": goal.to_dict(), "approval": approval.to_dict()}
                    )
                    self._send(status, body, ctype)
                    return
                if path == "/api/tasks":
                    deps = data.get("depends_on") or []
                    task = state.plane.create_task(
                        data["goal_id"], data["description"], depends_on=deps
                    )
                    status, body, ctype = _json_bytes(task.to_dict(), 201)
                    self._send(status, body, ctype)
                    return
                if path == "/api/synthetic-executions":
                    if data.get("live"):
                        status, body, ctype = _json_bytes(
                            {
                                "ok": False,
                                "error": "live_acp_disabled",
                                "sandbox_gate": state.plane.sandbox_gate,
                            },
                            403,
                        )
                        self._send(status, body, ctype)
                        return
                    execution = state.plane.simulate_task(data["task_id"])
                    status, body, ctype = _json_bytes(
                        {"execution": execution.to_dict(), "mode": "SYNTHETIC"}
                    )
                    self._send(status, body, ctype)
                    return
                if path == "/api/demo":
                    # Always seed the stable persistent demo (idempotent).
                    result = state.plane.ensure_persistent_demo()
                    status, body, ctype = _json_bytes(result)
                    self._send(status, body, ctype)
                    return
                if path == "/api/orchestrate/tick":
                    result = state.orchestrator.tick(
                        data["project_id"],
                        auto_integration=bool(data.get("auto_integration", True)),
                        approve_merge=bool(data.get("approve_merge", True)),
                    )
                    status, body, ctype = _json_bytes(result)
                    self._send(status, body, ctype)
                    return
                if path == "/api/orchestrate/full":
                    result = state.orchestrator.run_full_synthetic_lifecycle(
                        data["project_id"]
                    )
                    status, body, ctype = _json_bytes(result)
                    self._send(status, body, ctype)
                    return
                if path == "/api/orchestrate/recover":
                    result = state.orchestrator.recover(data["project_id"])
                    status, body, ctype = _json_bytes(result)
                    self._send(status, body, ctype)
                    return
                if path == "/api/integration/decide":
                    result = state.orchestrator.complete_integration(
                        data["execution_id"],
                        approve_merge=bool(data.get("approve_merge", True)),
                    )
                    status, body, ctype = _json_bytes(result)
                    self._send(status, body, ctype)
                    return
                status, body, ctype = _json_bytes(
                    {"ok": False, "error": "not_found"}, 404
                )
                self._send(status, body, ctype)
            except (PolicyError, IllegalTransitionError, KeyError, ValueError) as exc:
                status, body, ctype = _json_bytes(
                    {"ok": False, "error": str(exc)}, 400
                )
                self._send(status, body, ctype)
            except Exception as exc:  # noqa: BLE001
                status, body, ctype = _json_bytes(
                    {"ok": False, "error": str(exc)}, 500
                )
                self._send(status, body, ctype)

    return Handler


def serve(
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    db_path: Optional[str] = None,
) -> int:
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit("refusing to bind non-localhost host")
    plane = ControlPlane.open(db_path)
    state = AppState(plane)
    handler = make_handler(state)
    server = ThreadingHTTPServer((host, port), handler)
    print(json.dumps({"serving": f"http://{host}:{port}", "db": plane.repo.db_path}))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        plane.close()
    return 0
