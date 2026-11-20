"""Operational lifecycle state machines (separate from canonical gate vocabulary)."""

from __future__ import annotations

from typing import FrozenSet, Mapping

# Canonical gate vocabulary (docs/backlog) — not operational lifecycle states.
GATE_STATUSES = frozenset(
    {"PLANNED", "READY", "RUNNING", "PASS", "FAIL", "BLOCKED", "NOT_TESTED"}
)

GOAL_STATES = frozenset(
    {"DRAFT", "PENDING_APPROVAL", "APPROVED", "ACTIVE", "DONE", "CANCELLED", "BLOCKED"}
)
TASK_STATES = frozenset(
    {
        "PLANNED",
        "READY",
        "RUNNING",
        "REVIEW",
        "DONE",
        "FAILED",
        "BLOCKED",
        "CANCELLED",
    }
)
EXECUTION_STATES = frozenset(
    {
        "PREPARED",
        "DISPATCHED",
        "RUNNING",
        "SUCCEEDED",
        "FAILED",
        "CANCELLED",
        "AWAITING_INTEGRATION",
        "INTEGRATION_FAILED",
    }
)
APPROVAL_DECISIONS = frozenset({"PENDING", "APPROVED", "REJECTED", "EXPIRED"})
PROJECT_STATUSES = frozenset({"ACTIVE", "PAUSED", "ARCHIVED"})

GOAL_TRANSITIONS: Mapping[str, FrozenSet[str]] = {
    "DRAFT": frozenset({"PENDING_APPROVAL", "CANCELLED"}),
    "PENDING_APPROVAL": frozenset({"APPROVED", "REJECTED_PENDING", "CANCELLED", "DRAFT"}),
    "APPROVED": frozenset({"ACTIVE", "CANCELLED"}),
    "ACTIVE": frozenset({"DONE", "BLOCKED", "CANCELLED"}),
    "BLOCKED": frozenset({"ACTIVE", "CANCELLED"}),
    "DONE": frozenset(),
    "CANCELLED": frozenset(),
    "REJECTED_PENDING": frozenset({"DRAFT", "CANCELLED"}),
}

# Normalize rejected into cancelable draft path without inventing UI-only states.
GOAL_TRANSITIONS = {
    **GOAL_TRANSITIONS,
    "PENDING_APPROVAL": frozenset({"APPROVED", "DRAFT", "CANCELLED"}),
}

TASK_TRANSITIONS: Mapping[str, FrozenSet[str]] = {
    "PLANNED": frozenset({"READY", "BLOCKED", "CANCELLED"}),
    "READY": frozenset({"RUNNING", "BLOCKED", "CANCELLED"}),
    "RUNNING": frozenset({"REVIEW", "FAILED", "CANCELLED", "BLOCKED"}),
    "REVIEW": frozenset({"DONE", "FAILED", "READY", "CANCELLED"}),
    "FAILED": frozenset({"READY", "BLOCKED", "CANCELLED"}),
    "BLOCKED": frozenset({"READY", "PLANNED", "CANCELLED"}),
    "DONE": frozenset(),
    "CANCELLED": frozenset(),
}

EXECUTION_TRANSITIONS: Mapping[str, FrozenSet[str]] = {
    "PREPARED": frozenset({"DISPATCHED", "CANCELLED"}),
    "DISPATCHED": frozenset({"RUNNING", "FAILED", "CANCELLED"}),
    "RUNNING": frozenset(
        {"SUCCEEDED", "FAILED", "AWAITING_INTEGRATION", "CANCELLED"}
    ),
    "AWAITING_INTEGRATION": frozenset(
        {"SUCCEEDED", "INTEGRATION_FAILED", "FAILED", "CANCELLED"}
    ),
    "INTEGRATION_FAILED": frozenset({"AWAITING_INTEGRATION", "FAILED", "CANCELLED"}),
    "SUCCEEDED": frozenset(),
    "FAILED": frozenset(),
    "CANCELLED": frozenset(),
}


class IllegalTransitionError(ValueError):
    """Raised when an aggregate transition is not allowed."""


def assert_transition(
    kind: str,
    current: str,
    target: str,
    table: Mapping[str, FrozenSet[str]],
) -> None:
    allowed = table.get(current, frozenset())
    if target not in allowed:
        raise IllegalTransitionError(
            f"illegal {kind} transition: {current} -> {target}"
        )
