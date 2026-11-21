"""CLI package — public API re-exported from app for compatibility."""

from engineering_os.interfaces.cli.app import (  # noqa: F401
    build_parser,
    cmd_acp,
    cmd_acpx,
    cmd_cursor,
    cmd_cursor_smoke_evidence,
    cmd_demo,
    cmd_github,
    cmd_integrations,
    cmd_network,
    cmd_openclaw,
    cmd_orchestration_plan,
    cmd_orchestration_simulate_acp,
    cmd_paperclip,
    cmd_runtime,
    cmd_sandbox,
    cmd_seed,
    cmd_serve,
    main,
)

__all__ = [
    "build_parser",
    "main",
    "cmd_network",
    "cmd_cursor",
    "cmd_cursor_smoke_evidence",
]
