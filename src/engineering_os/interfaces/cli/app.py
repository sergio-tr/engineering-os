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
from engineering_os.infrastructure.persistence.sqlite import Repository, default_db_path


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


def cmd_paperclip(args: argparse.Namespace) -> int:
    plane = _plane(args.db)
    try:
        cmd = args.paperclip_cmd
        if cmd == "status":
            _print(plane.paperclip_status(args.company_id))
            return 0
        if cmd == "sync":
            _print(
                plane.paperclip_sync(args.company_id, project_id=args.project_id)
            )
            return 0
        if cmd == "agents":
            _print(plane.paperclip_list_agents(args.company_id))
            return 0
        if cmd == "issues":
            _print(plane.paperclip_list_issues(args.company_id))
            return 0
        if cmd == "link-project":
            _print(
                plane.paperclip_link_project(
                    args.local_id, args.external_id, company_id=args.company_id
                )
            )
            return 0
        if cmd == "create-issue":
            apply = bool(args.apply)
            _print(
                plane.paperclip_create_issue(
                    args.company_id,
                    {"title": args.title},
                    apply=apply,
                )
            )
            return 0
        return 2
    finally:
        plane.close()


def cmd_openclaw(args: argparse.Namespace) -> int:
    plane = _plane(args.db)
    try:
        cmd = args.openclaw_cmd
        if cmd == "status":
            _print(plane.openclaw_status())
            return 0
        if cmd == "refresh":
            _print(plane.openclaw_refresh())
            return 0
        if cmd == "gateway-check":
            refreshed = plane.openclaw_refresh()
            _print(
                {
                    "gateway": refreshed["status"].get("gateway"),
                    "gateway_transport": refreshed["status"].get("gateway_transport"),
                    "evidence_class": refreshed["status"].get("evidence_class"),
                }
            )
            return 0
        return 2
    finally:
        plane.close()


def cmd_integrations(args: argparse.Namespace) -> int:
    if args.integrations_cmd == "demo-fixture":
        import tempfile

        from engineering_os.infrastructure.eos05_fixtures import (
            build_paperclip_fixture_transport,
            openclaw_fixture_runner,
        )
        from engineering_os.infrastructure.integrations.openclaw.openclaw_client import OpenClawCliClient
        from engineering_os.infrastructure.persistence.sqlite import Repository

        path = Path(args.db) if args.db else default_db_path()
        if args.temp:
            path = Path(tempfile.mkdtemp(prefix="eos05-")) / "demo.sqlite3"
        plane = ControlPlane(
            Repository(path),
            paperclip_transport=build_paperclip_fixture_transport(),
            openclaw_client=OpenClawCliClient(
                runner=openclaw_fixture_runner, which=lambda _: "/usr/bin/openclaw"
            ),
        )
        try:
            result = plane.run_eos05_fixture_demo()
            project_id = result["project_id"]
            plane.close()
            plane2 = ControlPlane(
                Repository(path),
                paperclip_transport=build_paperclip_fixture_transport(),
                openclaw_client=OpenClawCliClient(
                    runner=openclaw_fixture_runner, which=lambda _: "/usr/bin/openclaw"
                ),
            )
            try:
                result["restart"] = {
                    "mappings": plane2.repo.list_external_mappings(
                        system_name="paperclip"
                    ),
                    "paperclip_obs": plane2.repo.latest_integration_observation(
                        system_name="paperclip",
                        project_id=project_id,
                        include_stale=True,
                    ),
                    "openclaw_obs": plane2.repo.latest_integration_observation(
                        system_name="openclaw", include_stale=True
                    ),
                    "plan": plane2.orchestration_plan(project_id),
                }
                result["db_path"] = str(path)
                _print(result)
                return 0
            finally:
                plane2.close()
        except Exception:
            plane.close()
            raise

    plane = _plane(args.db)
    try:
        _print(plane.integrations_status())
        return 0
    finally:
        plane.close()


def cmd_orchestration_plan(args: argparse.Namespace) -> int:
    plane = _plane(args.db)
    try:
        _print(plane.orchestration_plan(args.project_id))
        return 0
    finally:
        plane.close()


def cmd_orchestration_simulate_acp(args: argparse.Namespace) -> int:
    plane = _plane(args.db)
    try:
        orch = SequentialOrchestrator(plane)
        _print(orch.simulate_acp(args.project_id))
        return 0
    finally:
        plane.close()


def cmd_runtime(args: argparse.Namespace) -> int:
    plane = _plane(args.db)
    try:
        if args.runtime_cmd == "status":
            _print(plane.runtime_status())
            return 0
        if args.runtime_cmd == "inspect":
            _print(plane.runtime_inspect())
            return 0
        if args.runtime_cmd == "requirements":
            _print(plane.runtime_requirements())
            return 0
        return 2
    finally:
        plane.close()


def cmd_cursor_smoke_evidence(args: argparse.Namespace) -> int:
    plane = _plane(args.db)
    try:
        _print(plane.cursor_smoke_evidence(args.execution_id))
        return 0
    finally:
        plane.close()


def cmd_network(args: argparse.Namespace) -> int:
    plane = _plane(args.db)
    try:
        cmd = args.network_cmd
        if cmd in {"status", "broker"} and getattr(args, "network_broker_cmd", None) is None:
            if cmd == "broker":
                # `eos network broker` without subcommand → status
                _print(plane.network_broker_status())
                return 0
            _print(plane.network_status())
            return 0
        if cmd == "broker":
            sub = args.network_broker_cmd
            if sub == "status":
                _print(plane.network_broker_status())
                return 0
            if sub == "probe":
                execute = bool(getattr(args, "execute", False))
                dry_run = bool(getattr(args, "dry_run", False)) or not execute
                use_injected = not execute
                image_ref = getattr(args, "image_ref", None) or None
                payload = plane.network_probe(
                    dry_run=dry_run,
                    execute=execute,
                    allow_phase_b=bool(getattr(args, "allow_phase_b", False)),
                    owner_authorize_runtime_execution=bool(
                        getattr(args, "owner_authorize_runtime_execution", False)
                    ),
                    use_injected=use_injected,
                    image_ref=image_ref,
                )
                _print(payload)
                if execute and not payload.get("cli_ok", False):
                    return 1
                return 0
            return 2
        if cmd == "probe":
            execute = bool(getattr(args, "execute", False))
            dry_run = bool(getattr(args, "dry_run", False)) or not execute
            use_injected = not execute
            image_ref = getattr(args, "image_ref", None) or None
            payload = plane.network_probe(
                dry_run=dry_run,
                execute=execute,
                allow_phase_b=bool(getattr(args, "allow_phase_b", False)),
                owner_authorize_runtime_execution=bool(
                    getattr(args, "owner_authorize_runtime_execution", False)
                ),
                use_injected=use_injected,
                image_ref=image_ref,
            )
            _print(payload)
            if execute and not payload.get("cli_ok", False):
                return 1
            return 0
        return 2
    finally:
        plane.close()


def cmd_cursor(args: argparse.Namespace) -> int:
    cmd = args.cursor_cmd
    if cmd == "demo-fixture":
        import tempfile

        path = Path(args.db) if args.db else default_db_path()
        if args.temp:
            path = Path(tempfile.mkdtemp(prefix="eos-cursor-")) / "demo.sqlite3"
        plane = ControlPlane.open(path)
        try:
            result = plane.run_cursor_fixture_demo()
            plane.close()
            plane2 = ControlPlane.open(path)
            try:
                preps = plane2.repo.list_cursor_preparations(
                    project_id=result["project_id"]
                )
                result["restart"] = {
                    "preparations": len(preps),
                    "status": preps[0]["status"] if preps else None,
                    "no_duplicate_active": len(
                        [p for p in preps if p["status"] in {"MOCK_RUNNING"}]
                    )
                    == 0,
                }
                result["db_path"] = str(path)
                _print(result)
                return 0
            finally:
                plane2.close()
        except Exception:
            plane.close()
            raise

    if cmd == "image":
        plane = _plane(args.db)
        try:
            sub = args.cursor_image_cmd
            if sub == "inspect":
                _print(plane.cursor_image_inspect())
                return 0
            if sub == "build-plan":
                _print(plane.cursor_image_plan())
                return 0
            if sub == "build":
                _print(
                    plane.cursor_image_build(
                        print_only=bool(getattr(args, "print_only", True))
                    )
                )
                return 0
            if sub == "verify":
                _print(
                    plane.cursor_image_verify(
                        image_digest=getattr(args, "image_digest", None),
                        image_id=getattr(args, "image_id", None),
                        cursor_version=getattr(args, "cursor_version", None),
                        artifact_checksum=getattr(args, "artifact_checksum", None),
                        artifact_path=getattr(args, "artifact_path", None),
                        base_digest=getattr(args, "base_digest", None),
                        write_evidence=bool(getattr(args, "write_evidence", False)),
                        use_local_inspect=bool(getattr(args, "use_local_inspect", False)),
                    )
                )
                return 0
            return 2
        finally:
            plane.close()

    if cmd == "live-preflight":
        plane = _plane(args.db)
        try:
            _print(plane.cursor_live_preflight())
            return 0
        finally:
            plane.close()

    if cmd == "smoke":
        plane = _plane(args.db)
        try:
            execute = bool(getattr(args, "execute", False))
            dry_run = bool(getattr(args, "dry_run", False)) or not execute
            _print(
                plane.cursor_smoke(
                    dry_run=dry_run,
                    execute=execute,
                    allow_phase_b=bool(getattr(args, "allow_phase_b", False)),
                    owner_authorize_runtime_execution=bool(
                        getattr(args, "owner_authorize_runtime_execution", False)
                    ),
                )
            )
            return 0
        finally:
            plane.close()

    plane = _plane(args.db)
    try:
        if cmd == "status":
            _print(plane.cursor_status())
            return 0
        if cmd == "image-plan":
            _print(plane.cursor_image_plan())
            return 0
        if cmd == "readiness":
            _print(plane.cursor_readiness())
            return 0
        if cmd == "session-plan":
            _print(plane.cursor_session_plan(args.execution_id))
            return 0
        if cmd == "integration-check":
            _print(plane.cursor_integration_check())
            return 0
        if cmd == "sessions":
            _print(
                {
                    "sessions": plane.cursor_sessions(
                        project_id=getattr(args, "project_id", None)
                    )
                }
            )
            return 0
        if cmd == "evidence":
            _print(plane.cursor_evidence(args.execution_id))
            return 0
        if cmd == "deployment-sequence":
            _print(plane.owner_deployment_sequence())
            return 0
        return 2
    finally:
        plane.close()


def cmd_sandbox(args: argparse.Namespace) -> int:
    cmd = args.sandbox_cmd
    if cmd == "demo-fixture":
        import tempfile

        path = Path(args.db) if args.db else default_db_path()
        if getattr(args, "temp", False):
            path = Path(tempfile.mkdtemp(prefix="eos-oci-")) / "demo.sqlite3"
        plane = ControlPlane.open(path)
        try:
            result = plane.run_sandbox_fixture_demo()
            result["db_path"] = str(path)
            _print(result)
            return 0
        finally:
            plane.close()

    plane = _plane(args.db)
    try:
        if cmd == "readiness":
            _print(plane.sandbox_readiness())
            return 0
        if cmd == "plan":
            _print(plane.sandbox_plan(args.execution_id))
            return 0
        if cmd == "fixture-readiness":
            _print(plane.sandbox_fixture_readiness())
            return 0
        if cmd == "fixture-plan":
            _print(
                plane.sandbox_fixture_plan(
                    execution_id=getattr(args, "execution_id", None),
                    image_ref=getattr(args, "image_ref", "localhost/alpine:eos-fixture"),
                )
            )
            return 0
        if cmd == "fixture-history":
            _print(plane.sandbox_fixture_history(getattr(args, "project_id", None)))
            return 0
        if cmd == "run-acp-fixture":
            execute = bool(getattr(args, "execute", False))
            allow_phase_b = bool(getattr(args, "allow_phase_b", False))
            owner_auth = bool(getattr(args, "owner_authorize_runtime_execution", False))
            dry_run = bool(getattr(args, "dry_run", False)) or not execute
            try:
                _print(
                    plane.run_oci_acp_fixture(
                        execute=execute,
                        allow_phase_b=allow_phase_b,
                        owner_authorize_runtime_execution=owner_auth,
                        dry_run=dry_run,
                    )
                )
                return 0
            except Exception as exc:  # noqa: BLE001
                # OwnerGateError and PolicyError surface as structured failure.
                _print({"ok": False, "error": str(exc), "code": getattr(exc, "code", None)})
                return 2
        return 2
    finally:
        plane.close()


def cmd_acpx(args: argparse.Namespace) -> int:
    cmd = args.acpx_cmd
    if cmd == "demo-fixture":
        import tempfile

        path = Path(args.db) if args.db else default_db_path()
        if args.temp:
            path = Path(tempfile.mkdtemp(prefix="eos-acpx-")) / "demo.sqlite3"
        plane = ControlPlane.open(path)
        try:
            result = plane.run_acpx_fixture_demo()
            project_id = result["project_id"]
            plane.close()
            plane2 = ControlPlane.open(path)
            try:
                preps = plane2.acpx_sessions(project_id)
                result["restart"] = {
                    "preparations": len(preps),
                    "prep_status": preps[0]["status"] if preps else None,
                    "ready": [t.task_id for t in plane2.list_ready_tasks(project_id)],
                    "no_duplicate_active": len(
                        [
                            p
                            for p in preps
                            if p["status"]
                            in {"MOCK_RUNNING", "AWAITING_AUTHORIZED_DISPATCH"}
                        ]
                    )
                    == 0,
                }
                result["db_path"] = str(path)
                _print(result)
                return 0
            finally:
                plane2.close()
        except Exception:
            plane.close()
            raise

    plane = _plane(args.db)
    try:
        if cmd == "status":
            _print(plane.acpx_status())
            return 0
        if cmd == "sessions":
            _print(plane.acpx_sessions(args.project_id))
            return 0
        if cmd == "prepare":
            _print(plane.acpx_prepare(args.execution_id))
            return 0
        return 2
    finally:
        plane.close()


def cmd_acp(args: argparse.Namespace) -> int:
    cmd = args.acp_cmd
    if cmd == "demo-fixture":
        import tempfile

        path = Path(args.db) if args.db else default_db_path()
        if args.temp:
            path = Path(tempfile.mkdtemp(prefix="eos-acp-")) / "demo.sqlite3"
        plane = ControlPlane.open(path)
        try:
            result = plane.run_acp_fixture_demo()
            project_id = result["project_id"]
            execution_id = result["simulated"]["execution"]["execution_id"]
            plane.close()
            plane2 = ControlPlane.open(path)
            try:
                sessions = plane2.list_acp_sessions(project_id)
                detail = plane2.get_acp_session_for_execution(execution_id)
                result["restart"] = {
                    "sessions": sessions,
                    "session_status": detail["session"]["status"],
                    "event_count": len(detail["events"]),
                    "ready": [t.task_id for t in plane2.list_ready_tasks(project_id)],
                    "no_duplicate_active": len(
                        [
                            s
                            for s in sessions
                            if s["status"]
                            not in {"COMPLETED", "FAILED", "CANCELLED", "TIMED_OUT"}
                        ]
                    )
                    == 0,
                }
                result["db_path"] = str(path)
                _print(result)
                return 0
            finally:
                plane2.close()
        except Exception:
            plane.close()
            raise

    plane = _plane(args.db)
    try:
        if cmd == "status":
            _print(plane.acp_status())
            return 0
        if cmd == "capabilities":
            _print(plane.acp_capabilities())
            return 0
        if cmd == "sessions":
            _print(plane.list_acp_sessions(args.project_id))
            return 0
        if cmd == "session":
            _print(plane.get_acp_session_for_execution(args.execution_id))
            return 0
        if cmd == "cancel":
            _print(plane.cancel_acp_session(args.execution_id, synthetic=True))
            return 0
        if cmd == "reject-live":
            _print(plane.request_live_acp_transport())
            return 0
        return 2
    finally:
        plane.close()


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
            from engineering_os.infrastructure.integrations.github.github_fixtures import (
                build_demo_fixture_transport,
            )

            plane.close()
            path = Path(args.db) if args.db else default_db_path()
            if args.temp:
                import tempfile

                path = Path(tempfile.mkdtemp(prefix="eos-gh-")) / "demo.sqlite3"
            from engineering_os.application.services import ControlPlane
            from engineering_os.infrastructure.persistence.sqlite import Repository

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

    p = sub.add_parser("paperclip", help="Paperclip organization integration (EOS-05)")
    ps = p.add_subparsers(dest="paperclip_cmd", required=True)
    c = ps.add_parser("status")
    c.add_argument("--company-id", default=None)
    c.set_defaults(func=cmd_paperclip)
    c = ps.add_parser("sync")
    c.add_argument("--company-id", required=True)
    c.add_argument("--project-id", default=None)
    c.set_defaults(func=cmd_paperclip)
    c = ps.add_parser("agents")
    c.add_argument("--company-id", required=True)
    c.set_defaults(func=cmd_paperclip)
    c = ps.add_parser("issues")
    c.add_argument("--company-id", required=True)
    c.set_defaults(func=cmd_paperclip)
    c = ps.add_parser("link-project")
    c.add_argument("local_id")
    c.add_argument("external_id")
    c.add_argument("--company-id", required=True)
    c.set_defaults(func=cmd_paperclip)
    c = ps.add_parser("create-issue")
    c.add_argument("--company-id", required=True)
    c.add_argument("--title", required=True)
    c.add_argument("--dry-run", action="store_true", default=True)
    c.add_argument("--apply", action="store_true")
    c.set_defaults(func=cmd_paperclip)

    p = sub.add_parser("openclaw", help="OpenClaw coordinator observation (EOS-05)")
    os_ = p.add_subparsers(dest="openclaw_cmd", required=True)
    c = os_.add_parser("status")
    c.set_defaults(func=cmd_openclaw)
    c = os_.add_parser("gateway-check")
    c.set_defaults(func=cmd_openclaw)
    c = os_.add_parser("refresh")
    c.set_defaults(func=cmd_openclaw)

    p = sub.add_parser("integrations", help="Integration overview")
    iss = p.add_subparsers(dest="integrations_cmd", required=True)
    c = iss.add_parser("status")
    c.set_defaults(func=cmd_integrations)
    c = iss.add_parser("demo-fixture")
    c.add_argument("--temp", action="store_true")
    c.set_defaults(func=cmd_integrations)

    p = sub.add_parser("orchestration")
    ors = p.add_subparsers(dest="orch_cmd", required=True)
    c = ors.add_parser("plan")
    c.add_argument("--project-id", required=True)
    c.set_defaults(func=cmd_orchestration_plan)
    c = ors.add_parser("simulate-acp")
    c.add_argument("--project-id", required=True)
    c.set_defaults(func=cmd_orchestration_simulate_acp)

    p = sub.add_parser("acp", help="ACP/Cursor execution integration (EOS-06)")
    ac = p.add_subparsers(dest="acp_cmd", required=True)
    c = ac.add_parser("status")
    c.set_defaults(func=cmd_acp)
    c = ac.add_parser("capabilities")
    c.set_defaults(func=cmd_acp)
    c = ac.add_parser("sessions")
    c.add_argument("--project-id", default=None)
    c.set_defaults(func=cmd_acp)
    c = ac.add_parser("session")
    c.add_argument("execution_id")
    c.set_defaults(func=cmd_acp)
    c = ac.add_parser("cancel")
    c.add_argument("execution_id")
    c.add_argument("--synthetic", action="store_true", default=True)
    c.set_defaults(func=cmd_acp)
    c = ac.add_parser("demo-fixture")
    c.add_argument("--temp", action="store_true")
    c.set_defaults(func=cmd_acp)
    c = ac.add_parser("reject-live")
    c.set_defaults(func=cmd_acp)

    p = sub.add_parser("runtime", help="Runtime readiness (EOS-07/09)")
    rs = p.add_subparsers(dest="runtime_cmd", required=True)
    c = rs.add_parser("status")
    c.set_defaults(func=cmd_runtime)
    c = rs.add_parser("inspect")
    c.set_defaults(func=cmd_runtime)
    c = rs.add_parser("requirements")
    c.set_defaults(func=cmd_runtime)

    p = sub.add_parser("network", help="Egress broker / Podman network enforcement (EOS-11/12)")
    ns = p.add_subparsers(dest="network_cmd", required=True)
    c = ns.add_parser("status")
    c.set_defaults(func=cmd_network)
    c = ns.add_parser("probe")
    c.add_argument("--dry-run", action="store_true", default=False)
    c.add_argument("--execute", action="store_true", default=False)
    c.add_argument("--allow-phase-b", action="store_true", default=False)
    c.add_argument(
        "--owner-authorize-runtime-execution",
        action="store_true",
        default=False,
    )
    c.add_argument(
        "--image-ref",
        default=None,
        help=(
            "Immutable local OCI image ID or digest (sha256:…). "
            "Floating tags rejected; never pulls."
        ),
    )
    c.set_defaults(func=cmd_network)
    nb = ns.add_parser("broker", help="Trusted egress broker status/probe")
    nbs = nb.add_subparsers(dest="network_broker_cmd", required=False)
    c = nbs.add_parser("status")
    c.set_defaults(func=cmd_network)
    c = nbs.add_parser("probe")
    c.add_argument("--dry-run", action="store_true", default=False)
    c.add_argument("--execute", action="store_true", default=False)
    c.add_argument("--allow-phase-b", action="store_true", default=False)
    c.add_argument(
        "--owner-authorize-runtime-execution",
        action="store_true",
        default=False,
    )
    c.add_argument(
        "--image-ref",
        default=None,
        help=(
            "Immutable local OCI image ID or digest (sha256:…). "
            "Floating tags rejected; never pulls."
        ),
    )
    c.set_defaults(func=cmd_network)
    nb.set_defaults(func=cmd_network)

    p = sub.add_parser("cursor", help="Cursor ACP runtime integration (EOS-09/10)")
    cs = p.add_subparsers(dest="cursor_cmd", required=True)
    c = cs.add_parser("status")
    c.set_defaults(func=cmd_cursor)
    c = cs.add_parser("image-plan", help="Alias for image build-plan")
    c.set_defaults(func=cmd_cursor)
    img = cs.add_parser("image", help="Cursor OCI image inspect/build-plan/verify")
    imgs = img.add_subparsers(dest="cursor_image_cmd", required=True)
    c = imgs.add_parser("inspect")
    c.set_defaults(func=cmd_cursor)
    c = imgs.add_parser("build-plan")
    c.set_defaults(func=cmd_cursor)
    c = imgs.add_parser("build")
    c.add_argument("--print-only", action="store_true", default=True)
    c.set_defaults(func=cmd_cursor)
    c = imgs.add_parser("verify")
    c.add_argument("--image-digest", default=None)
    c.add_argument("--image-id", default=None)
    c.add_argument("--cursor-version", default=None)
    c.add_argument("--artifact-checksum", default=None)
    c.add_argument("--artifact-path", default=None)
    c.add_argument("--base-digest", default=None)
    c.add_argument("--write-evidence", action="store_true")
    c.add_argument("--use-local-inspect", action="store_true")
    c.set_defaults(func=cmd_cursor)
    c = cs.add_parser("readiness")
    c.set_defaults(func=cmd_cursor)
    c = cs.add_parser("live-preflight")
    c.set_defaults(func=cmd_cursor)
    c = cs.add_parser("session-plan")
    c.add_argument("--execution-id", required=True)
    c.set_defaults(func=cmd_cursor)
    c = cs.add_parser("integration-check")
    c.set_defaults(func=cmd_cursor)
    c = cs.add_parser("sessions")
    c.add_argument("--project-id", default=None)
    c.set_defaults(func=cmd_cursor)
    c = cs.add_parser("evidence")
    c.add_argument("execution_id")
    c.set_defaults(func=cmd_cursor)
    sm = cs.add_parser("smoke", help="Cursor smoke dry-run, execute, or evidence")
    sm.add_argument("--dry-run", action="store_true", default=False)
    sm.add_argument("--execute", action="store_true", default=False)
    sm.add_argument("--allow-phase-b", action="store_true", default=False)
    sm.add_argument(
        "--owner-authorize-runtime-execution",
        action="store_true",
        default=False,
    )
    sm.set_defaults(func=cmd_cursor, cursor_smoke_cmd=None)
    sms = sm.add_subparsers(dest="cursor_smoke_cmd", required=False)
    sev = sms.add_parser("evidence", help="Show smoke evidence for EXECUTION_ID")
    sev.add_argument("execution_id")
    sev.set_defaults(func=cmd_cursor_smoke_evidence)
    # Alias kept for scripts that used smoke-evidence
    se = cs.add_parser("smoke-evidence", help="Alias for: cursor smoke evidence")
    se.add_argument("execution_id")
    se.set_defaults(func=cmd_cursor_smoke_evidence)
    c = cs.add_parser("deployment-sequence", help="Owner WSL2 deployment stages A-F")
    c.set_defaults(func=cmd_cursor)
    c = cs.add_parser("demo-fixture")
    c.add_argument("--temp", action="store_true")
    c.set_defaults(func=cmd_cursor)

    p = sub.add_parser("sandbox", help="Sandbox launcher / OCI fixture (EOS-07/08)")
    ss = p.add_subparsers(dest="sandbox_cmd", required=True)
    c = ss.add_parser("readiness")
    c.set_defaults(func=cmd_sandbox)
    c = ss.add_parser("plan")
    c.add_argument("--execution-id", required=True)
    c.set_defaults(func=cmd_sandbox)
    c = ss.add_parser("fixture-readiness", help="OCI ACP fixture readiness")
    c.set_defaults(func=cmd_sandbox)
    c = ss.add_parser("fixture-plan", help="Plan OCI ACP fixture argv")
    c.add_argument("--execution-id", default=None)
    c.add_argument("--image-ref", default="localhost/alpine:eos-fixture")
    c.set_defaults(func=cmd_sandbox)
    c = ss.add_parser("fixture-history")
    c.add_argument("--project-id", default=None)
    c.set_defaults(func=cmd_sandbox)
    c = ss.add_parser(
        "run-acp-fixture",
        help="Dry-run or Owner-gated OCI ACP fixture (not exposed via HTTP)",
    )
    c.add_argument("--dry-run", action="store_true", default=False)
    c.add_argument("--execute", action="store_true", default=False)
    c.add_argument("--allow-phase-b", action="store_true", default=False)
    c.add_argument(
        "--owner-authorize-runtime-execution",
        action="store_true",
        default=False,
    )
    c.set_defaults(func=cmd_sandbox)
    c = ss.add_parser("demo-fixture", help="Offline injected OCI ACP fixture demo")
    c.add_argument("--temp", action="store_true")
    c.set_defaults(func=cmd_sandbox)

    p = sub.add_parser("acpx", help="ACPX sandbox bridge (EOS-07)")
    xs = p.add_subparsers(dest="acpx_cmd", required=True)
    c = xs.add_parser("status")
    c.set_defaults(func=cmd_acpx)
    c = xs.add_parser("sessions")
    c.add_argument("--project-id", default=None)
    c.set_defaults(func=cmd_acpx)
    c = xs.add_parser("prepare")
    c.add_argument("--execution-id", required=True)
    c.set_defaults(func=cmd_acpx)
    c = xs.add_parser("demo-fixture")
    c.add_argument("--temp", action="store_true")
    c.set_defaults(func=cmd_acpx)

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
