"""OpenClaw ACPX Cursor agent command mapping — proposal + non-mutating validator."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from engineering_os.infrastructure.cursor_runtime import resolve_cursor_acp_command
from engineering_os.infrastructure.evidence import ERROR, SYNTHETIC


# Proposed ACPX per-agent command: must invoke Engineering OS sandbox launcher,
# never a raw host Cursor binary.
PROPOSED_ACPX_CURSOR_COMMAND = [
    "eos",
    "sandbox",
    "launch-cursor-acp",
    "--execution-id",
    "${EOS_EXECUTION_ID}",
]


def propose_acpx_cursor_agent_config(
    *,
    agent_id: str = "cursor",
    backend: str = "acpx",
) -> Dict[str, Any]:
    cursor_cmd = resolve_cursor_acp_command()
    return {
        "agent_id": agent_id,
        "backend": backend,
        "proposed_command": list(PROPOSED_ACPX_CURSOR_COMMAND),
        "inner_cursor_argv": list(cursor_cmd.argv),
        "host_direct_cursor_forbidden": True,
        "auto_enable_dispatch": False,
        "mutation_of_global_openclaw_config": False,
        "docs": [
            "https://docs.openclaw.ai/tools/acp-agents",
            "https://docs.openclaw.ai/tools/acp-agents-setup",
        ],
        "note": (
            "ACPX must call the trusted EOS sandbox launcher; "
            "OpenClaw must not spawn Cursor on the host"
        ),
        "evidence_class": SYNTHETIC,
    }


def validate_acpx_cursor_command(command: Optional[List[str]]) -> Dict[str, Any]:
    """Non-mutating validator for a candidate ACPX cursor command."""
    errors: List[str] = []
    if not command:
        errors.append("missing_command")
    else:
        joined = " ".join(command)
        if "cursor-agent" in command[0] or command[0] == "agent":
            # Raw Cursor on host — reject.
            errors.append("direct_host_cursor_rejected")
        if "eos" not in command[0] and "engineering-os" not in joined:
            errors.append("untrusted_launcher_command")
        if "--privileged" in command or "docker.sock" in joined:
            errors.append("sandbox_bypass_rejected")
        if any(tok in {"sh", "bash", "-c"} for tok in command):
            errors.append("shell_wrapper_rejected")
    ok = not errors
    return {
        "ok": ok,
        "errors": errors,
        "status": "OK" if ok else "BLOCKED",
        "evidence_class": SYNTHETIC if ok else ERROR,
        "applied_global_config_change": False,
    }
