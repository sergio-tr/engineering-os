"""Command-line interface for the Engineering OS control plane."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Optional

from engineering_os.application.orchestrator import SequentialOrchestrator
from engineering_os.application.services import ControlPlane, PolicyError, dumps
from engineering_os.domain.states import IllegalTransitionError
from engineering_os.infrastructure.sqlite_repo import Repository, default_db_path


def _plane(db: Optional[str]) -> ControlPlane:
    return ControlPlane.open(db)


def _print(data: Any) -> None:
    if isinstance(data, str):
        print(data)
    else:
        print(dumps(data))


def cmd_init(args: argparse.Namespace) -> int:
    path = Path(args.db) if args.db else default_db_path()
    repo = Repository(path)
    repo.close()
    _print({"ok": True, "db_path": str(path), "action": "initialized"})
    return 0


def cmd_project_create(args: argparse.Namespace) -> int:
    plane = _plane(args.db)
    try:
        project = plane.create_project(args.name, args.repository)
        _print(project.to_dict())
        return 0
    finally:
        plane.close()


def cmd_project_list(args: argparse.Namespace) -> int:
    plane = _plane(args.db)
    try:
        _print([p.to_dict() for p in plane.list_projects()])
        return 0
    finally:
        plane.close()


def cmd_goal_create(args: argparse.Namespace) -> int:
    plane = _plane(args.db)
    try:
        goal = plane.create_goal(
            args.project_id, args.title, args.description or "", priority=args.priority
        )
        _print(goal.to_dict())
        return 0
    finally:
        plane.close()


def cmd_goal_approve(args: argparse.Namespace) -> int:
    plane = _plane(args.db)
    try:
        goal, approval = plane.approve_goal(args.goal_id, approver=args.approver)
        _print({"goal": goal.to_dict(), "approval": approval.to_dict()})
        return 0
    finally:
        plane.close()


def cmd_task_create(args: argparse.Namespace) -> int:
    plane = _plane(args.db)
    try:
        deps = [d for d in (args.depends_on or "").split(",") if d]
        task = plane.create_task(args.goal_id, args.description, depends_on=deps or None)
        _print(task.to_dict())
        return 0
    finally:
        plane.close()


def cmd_task_list(args: argparse.Namespace) -> int:
    plane = _plane(args.db)
    try:
        tasks = plane.repo.list_tasks(project_id=args.project_id, state=args.state)
        _print([t.to_dict() for t in tasks])
        return 0
    finally:
        plane.close()


def cmd_task_ready(args: argparse.Namespace) -> int:
    plane = _plane(args.db)
    try:
        ready = plane.list_ready_tasks(args.project_id)
        _print([t.to_dict() for t in ready])
        return 0
    finally:
        plane.close()


def cmd_execution_simulate(args: argparse.Namespace) -> int:
    plane = _plane(args.db)
    try:
        execution = plane.simulate_task(args.task_id)
        _print(execution.to_dict())
        return 0 if execution.status == "SUCCEEDED" else 2
    finally:
        plane.close()


def cmd_execution_list(args: argparse.Namespace) -> int:
    plane = _plane(args.db)
    try:
        items = plane.repo.list_executions(
            project_id=args.project_id, task_id=args.task_id
        )
        _print([e.to_dict() for e in items])
        return 0
    finally:
        plane.close()


def cmd_execution_show(args: argparse.Namespace) -> int:
    plane = _plane(args.db)
    try:
        execution = plane._require_execution(args.execution_id)
        events = plane.repo.list_events(
            aggregate_type="execution", aggregate_id=execution.execution_id
        )
        _print(
            {
                "execution": execution.to_dict(),
                "events": [e.to_dict() for e in events],
            }
        )
        return 0
    finally:
        plane.close()


def cmd_events(args: argparse.Namespace) -> int:
    plane = _plane(args.db)
    try:
        events = plane.repo.list_events(limit=args.limit)
        _print([e.to_dict() for e in events])
        return 0
    finally:
        plane.close()


def cmd_status(args: argparse.Namespace) -> int:
    plane = _plane(args.db)
    try:
        _print(plane.status_summary())
        return 0
    finally:
        plane.close()


def cmd_demo(args: argparse.Namespace) -> int:
    import tempfile

    from engineering_os.application.services import DEMO_PROJECT_ID

    if args.temp:
        path = Path(tempfile.mkdtemp(prefix="eos-demo-")) / "demo.sqlite3"
        ephemeral = True
    else:
        # Default: persistent local DB so the dashboard can show seeded data.
        path = Path(args.db) if args.db else default_db_path()
        ephemeral = False
    plane = ControlPlane.open(path)
    try:
        result = plane.run_demo(ephemeral=ephemeral)
        project_id = (
            result.get("project_id")
            or (result.get("project") or {}).get("project_id")
            or DEMO_PROJECT_ID
        )
        task1_id = result.get("task1_id") or "task-eos-mvp-demo-1"
        plane.close()
        plane2 = ControlPlane.open(path)
        try:
            tasks = plane2.repo.list_tasks(project_id=project_id)
            ready = plane2.list_ready_tasks(project_id)
            states = {t.task_id: t.lifecycle_state for t in tasks}
            result["restart_check"] = {
                "task_states": states,
                "ready_after_restart": [t.task_id for t in ready],
                "db_path": str(path),
            }
            if task1_id not in states:
                raise RuntimeError("persistence lost after reopen")
            if states[task1_id] != "DONE":
                raise RuntimeError("task1 not DONE after reopen")
            result["db_path"] = str(path)
            result["dashboard_hint"] = (
                f"python3 scripts/eos.py serve --db {path}"
            )
            _print(result)
            return 0
        finally:
            plane2.close()
    except Exception as exc:
        _print({"ok": False, "error": str(exc)})
        return 1


def cmd_seed(args: argparse.Namespace) -> int:
    """Idempotent persistent demo seed (alias of demo without --temp)."""
    args.temp = False
    return cmd_demo(args)


def cmd_orchestrate(args: argparse.Namespace) -> int:
    plane = _plane(args.db)
    try:
        orch = SequentialOrchestrator(plane)
        if args.recover:
            _print(orch.recover(args.project_id))
            return 0
        if args.full:
            _print(orch.run_full_synthetic_lifecycle(args.project_id))
            return 0
        _print(
            orch.tick(
                args.project_id,
                auto_integration=not args.wait_integration,
                approve_merge=not args.reject_merge,
            )
        )
        return 0
    finally:
        plane.close()


def cmd_serve(args: argparse.Namespace) -> int:
    from engineering_os.interfaces.http_server import serve

    return serve(host=args.host, port=args.port, db_path=args.db)


def cmd_github(args: argparse.Namespace) -> int:
    plane = _plane(args.db)
    try:
        action = args.github_cmd
        if action == "connect":
            _print(
                plane.configure_github_connection(
                    args.project_id, args.repository, api_base=args.api_base
                )
            )
            return 0
        if action == "status":
            _print(plane.github_status(args.project_id))
            return 0
        if action == "prs":
            _print(
                plane.list_github_pull_requests(
                    args.project_id, state=args.state, use_cache=args.cache
                )
            )
            return 0
        if action == "sync":
            _print(plane.sync_github_repository(args.project_id))
            return 0
        if action == "link-pr":
            _print(
                plane.link_execution_to_pr(
                    args.execution_id,
                    int(args.pr_number),
                    expected_base_ref=args.base_ref,
                    expected_head_sha=args.head_sha,
                )
            )
            return 0
        if action == "reconcile":
            _print(
                plane.reconcile_github_merge(
                    args.execution_id, complete_task=args.complete_task
                )
            )
            return 0
        if action == "demo-fixture":
            from engineering_os.infrastructure.github_fixtures import (
                build_demo_fixture_transport,
            )

            plane.close()
            path = Path(args.db) if args.db else default_db_path()
            if args.temp:
                import tempfile

                path = Path(tempfile.mkdtemp(prefix="eos-gh-")) / "demo.sqlite3"
            from engineering_os.application.services import ControlPlane
            from engineering_os.infrastructure.sqlite_repo import Repository

            plane2 = ControlPlane(
                Repository(path), github_transport=build_demo_fixture_transport()
            )
            try:
                result = plane2.run_github_fixture_demo()
                project_id = result["project_id"]
                execution_id = result["execution_id"]
                plane2.close()
                plane3 = ControlPlane(
                    Repository(path), github_transport=build_demo_fixture_transport()
                )
                try:
                    cached = plane3.cached_github_observation(
                        project_id, execution_id=execution_id
                    )
                    reconciled = plane3.reconcile_github_merge(
                        execution_id, complete_task=False
                    )
                    result["restart_cached_observation"] = cached
                    result["reconcile"] = reconciled
                    result["db_path"] = str(path)
                    _print(result)
                    return 0
                finally:
                    plane3.close()
            except Exception:
                plane2.close()
                raise
        _print({"ok": False, "error": f"unknown github command: {action}"})
        return 2
    finally:
        try:
            plane.close()
        except Exception:
            pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="eos",
        description="Engineering OS operational control plane (local-first)",
    )
    parser.add_argument(
        "--db",
        default=None,
        help="SQLite database path (default: XDG data dir outside repo)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="Initialize the SQLite database")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("project")
    ps = p.add_subparsers(dest="project_cmd", required=True)
    c = ps.add_parser("create")
    c.add_argument("--name", required=True)
    c.add_argument("--repository", required=True)
    c.set_defaults(func=cmd_project_create)
    c = ps.add_parser("list")
    c.set_defaults(func=cmd_project_list)

    p = sub.add_parser("goal")
    gs = p.add_subparsers(dest="goal_cmd", required=True)
    c = gs.add_parser("create")
    c.add_argument("--project-id", required=True)
    c.add_argument("--title", required=True)
    c.add_argument("--description", default="")
    c.add_argument("--priority", type=int, default=100)
    c.set_defaults(func=cmd_goal_create)
    c = gs.add_parser("approve")
    c.add_argument("--goal-id", required=True)
    c.add_argument("--approver", default="owner-synthetic")
    c.set_defaults(func=cmd_goal_approve)

    p = sub.add_parser("task")
    ts = p.add_subparsers(dest="task_cmd", required=True)
    c = ts.add_parser("create")
    c.add_argument("--goal-id", required=True)
    c.add_argument("--description", required=True)
    c.add_argument("--depends-on", default="")
    c.set_defaults(func=cmd_task_create)
    c = ts.add_parser("list")
    c.add_argument("--project-id", default=None)
    c.add_argument("--state", default=None)
    c.set_defaults(func=cmd_task_list)
    c = ts.add_parser("ready")
    c.add_argument("--project-id", required=True)
    c.set_defaults(func=cmd_task_ready)

    p = sub.add_parser("execution")
    es = p.add_subparsers(dest="execution_cmd", required=True)
    c = es.add_parser("simulate")
    c.add_argument("--task-id", required=True)
    c.set_defaults(func=cmd_execution_simulate)
    c = es.add_parser("list")
    c.add_argument("--project-id", default=None)
    c.add_argument("--task-id", default=None)
    c.set_defaults(func=cmd_execution_list)
    c = es.add_parser("show")
    c.add_argument("--execution-id", required=True)
    c.set_defaults(func=cmd_execution_show)

    p = sub.add_parser("events")
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(func=cmd_events)

    p = sub.add_parser("status")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser(
        "demo",
        help="Seed/run synthetic demonstration (persistent DB by default)",
    )
    p.add_argument(
        "--temp",
        action="store_true",
        help="Use a temporary database with generated IDs (non-idempotent)",
    )
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser(
        "seed",
        help="Idempotently seed the persistent synthetic demo for the dashboard",
    )
    p.set_defaults(func=cmd_seed)

    p = sub.add_parser("orchestrate", help="Advance sequential orchestration (EOS-03)")
    p.add_argument("--project-id", required=True)
    p.add_argument("--full", action="store_true")
    p.add_argument("--recover", action="store_true")
    p.add_argument("--wait-integration", action="store_true")
    p.add_argument("--reject-merge", action="store_true")
    p.set_defaults(func=cmd_orchestrate)

    p = sub.add_parser("serve", help="Start localhost dashboard (EOS-02)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8765)
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("github", help="Read-only GitHub integration (EOS-04)")
    gs = p.add_subparsers(dest="github_cmd", required=True)
    c = gs.add_parser("connect")
    c.add_argument("repository", help="OWNER/REPO")
    c.add_argument("--project-id", required=True)
    c.add_argument("--api-base", default=None)
    c.set_defaults(func=cmd_github)
    c = gs.add_parser("status")
    c.add_argument("--project-id", required=True)
    c.set_defaults(func=cmd_github)
    c = gs.add_parser("prs")
    c.add_argument("--project-id", required=True)
    c.add_argument("--state", default="all")
    c.add_argument("--cache", action="store_true")
    c.set_defaults(func=cmd_github)
    c = gs.add_parser("sync")
    c.add_argument("--project-id", required=True)
    c.set_defaults(func=cmd_github)
    c = gs.add_parser("link-pr")
    c.add_argument("execution_id")
    c.add_argument("pr_number", type=int)
    c.add_argument("--base-ref", default=None)
    c.add_argument("--head-sha", default=None)
    c.set_defaults(func=cmd_github)
    c = gs.add_parser("reconcile")
    c.add_argument("execution_id")
    c.add_argument(
        "--complete-task",
        action="store_true",
        help="Complete AWAITING_INTEGRATION execution after verified merge",
    )
    c.set_defaults(func=cmd_github)
    c = gs.add_parser("demo-fixture", help="Offline fixture-based GitHub demo")
    c.add_argument("--temp", action="store_true")
    c.set_defaults(func=cmd_github)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (PolicyError, IllegalTransitionError, KeyError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2), file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 — CLI boundary
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
