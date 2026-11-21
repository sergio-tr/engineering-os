"""Offline fixtures for Paperclip REST and OpenClaw CLI (EOS-05)."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Sequence

from engineering_os.infrastructure.integrations.github.github_client import FixtureTransport, HttpResponse
from engineering_os.infrastructure.integrations.openclaw.openclaw_client import CommandResult


COMPANY_ID = "11111111-1111-1111-1111-111111111111"
PROJECT_EXT = "22222222-2222-2222-2222-222222222222"
GOAL_EXT = "33333333-3333-3333-3333-333333333333"
AGENT_EXT = "44444444-4444-4444-4444-444444444444"
ISSUE_A = "55555555-5555-5555-5555-555555555555"
ISSUE_B = "66666666-6666-6666-6666-666666666666"


def _json(data: Any, *, status: int = 200) -> HttpResponse:
    return HttpResponse(
        status=status,
        headers={"content-type": "application/json"},
        body=json.dumps(data).encode("utf-8"),
        url="fixture",
    )


def build_paperclip_fixture_transport() -> FixtureTransport:
    transport = FixtureTransport()
    transport.add(
        "GET /api/companies",
        [{"id": COMPANY_ID, "name": "Engineering OS Co", "slug": "eos"}],
    )
    transport.add(
        f"GET /api/companies/{COMPANY_ID}",
        {"id": COMPANY_ID, "name": "Engineering OS Co", "slug": "eos"},
    )
    transport.add(
        f"GET /api/companies/{COMPANY_ID}/agents",
        [
            {
                "id": AGENT_EXT,
                "name": "Engineer One",
                "role": "engineer",
                "title": "Builder",
                "status": "active",
                "lifecycleState": "ready",
                "reportsTo": None,
                "adapterType": "cursor",
                "adapterConfig": {"env": {"SECRET": "should-redact"}},
            }
        ],
    )
    transport.add(
        f"GET /api/companies/{COMPANY_ID}/org",
        {"root": AGENT_EXT, "nodes": [{"id": AGENT_EXT, "children": []}]},
    )
    transport.add(
        f"GET /api/companies/{COMPANY_ID}/projects",
        [
            {
                "id": PROJECT_EXT,
                "name": "Control Plane",
                "status": "active",
                "companyId": COMPANY_ID,
            }
        ],
    )
    transport.add(
        f"GET /api/companies/{COMPANY_ID}/goals",
        [
            {
                "id": GOAL_EXT,
                "title": "Ship MVP",
                "status": "active",
                "projectId": PROJECT_EXT,
                "companyId": COMPANY_ID,
            }
        ],
    )
    transport.add(
        f"GET /api/companies/{COMPANY_ID}/issues",
        [
            {
                "id": ISSUE_A,
                "title": "First issue",
                "status": "todo",
                "projectId": PROJECT_EXT,
                "goalId": GOAL_EXT,
                "assigneeAgentId": AGENT_EXT,
                "blockedByIssueIds": [],
                "companyId": COMPANY_ID,
                "updatedAt": "2026-11-20T00:00:00Z",
            },
            {
                "id": ISSUE_B,
                "title": "Second issue",
                "status": "todo",
                "projectId": PROJECT_EXT,
                "goalId": GOAL_EXT,
                "assigneeAgentId": AGENT_EXT,
                "blockedByIssueIds": [ISSUE_A],
                "companyId": COMPANY_ID,
                "updatedAt": "2026-11-20T00:00:00Z",
            },
        ],
    )
    transport.add(
        f"GET /api/companies/{COMPANY_ID}/approvals",
        [{"id": "appr-1", "status": "pending", "companyId": COMPANY_ID}],
    )
    transport.add(
        f"GET /api/issues/{ISSUE_A}",
        {
            "id": ISSUE_A,
            "title": "First issue",
            "status": "todo",
            "companyId": COMPANY_ID,
            "blockedByIssueIds": [],
        },
    )
    transport.routes[f"POST /api/companies/{COMPANY_ID}/issues"] = _json(
        {
            "id": "77777777-7777-7777-7777-777777777777",
            "title": "Created issue",
            "status": "todo",
            "companyId": COMPANY_ID,
        },
        status=201,
    )
    return transport


def openclaw_fixture_runner(
    argv: Sequence[str], timeout: float, env: Dict[str, str]
) -> CommandResult:
    joined = " ".join(argv)
    if "status --json" in joined or (len(argv) >= 3 and argv[-2:] == ["status", "--json"]):
        payload = {
            "gateway": {"reachable": True, "rpc": True, "version": "2026.11.0"},
            "agents": [{"id": "agent-1", "status": "idle"}],
            "sessions": [{"id": "sess-1", "agentId": "agent-1"}],
        }
        return CommandResult(0, json.dumps(payload), "", list(argv))
    if "gateway" in argv and "status" in argv:
        return CommandResult(
            0,
            json.dumps({"ok": True, "rpc": True, "requireRpc": True}),
            "",
            list(argv),
        )
    return CommandResult(1, "", "unexpected argv", list(argv))


def openclaw_absent_which(_name: str) -> None:
    return None
