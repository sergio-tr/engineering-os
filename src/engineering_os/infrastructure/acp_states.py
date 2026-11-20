"""ACP session lifecycle (separate from task/SANDBOX status)."""

from __future__ import annotations

from typing import FrozenSet, Mapping

from engineering_os.domain.states import IllegalTransitionError

ACP_SESSION_STATES = frozenset(
    {
        "CREATED",
        "INITIALIZING",
        "READY",
        "RUNNING",
        "COMPLETED",
        "FAILED",
        "CANCEL_REQUESTED",
        "CANCELLED",
        "TIMED_OUT",
        "INTERRUPTED",
        "BLOCKED",
    }
)

ACP_TRANSITIONS: Mapping[str, FrozenSet[str]] = {
    "CREATED": frozenset({"INITIALIZING", "CANCELLED", "FAILED"}),
    "INITIALIZING": frozenset({"READY", "FAILED", "CANCEL_REQUESTED", "INTERRUPTED"}),
    "READY": frozenset({"RUNNING", "CANCELLED", "FAILED", "BLOCKED"}),
    "RUNNING": frozenset(
        {
            "COMPLETED",
            "FAILED",
            "CANCEL_REQUESTED",
            "TIMED_OUT",
            "INTERRUPTED",
            "BLOCKED",
        }
    ),
    "CANCEL_REQUESTED": frozenset({"CANCELLED", "FAILED", "COMPLETED", "TIMED_OUT"}),
    "BLOCKED": frozenset({"READY", "RUNNING", "CANCELLED", "FAILED"}),
    "COMPLETED": frozenset(),
    "FAILED": frozenset(),
    "CANCELLED": frozenset(),
    "TIMED_OUT": frozenset(),
    "INTERRUPTED": frozenset({"READY", "FAILED", "CANCELLED"}),
}


def assert_acp_transition(current: str, target: str) -> None:
    allowed = ACP_TRANSITIONS.get(current, frozenset())
    if target not in allowed:
        raise IllegalTransitionError(f"illegal acp transition: {current} -> {target}")
