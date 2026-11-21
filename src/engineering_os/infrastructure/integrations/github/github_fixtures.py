"""Recorded GitHub REST fixtures for offline tests and demos."""

from __future__ import annotations

import json
from typing import Any, Dict

from engineering_os.infrastructure.integrations.github.github_client import FixtureTransport, HttpResponse


def _json(data: Any, *, status: int = 200, extra_headers: Dict[str, str] | None = None) -> HttpResponse:
    headers = {
        "content-type": "application/json",
        "x-ratelimit-remaining": "4990",
        "x-ratelimit-limit": "5000",
        "x-ratelimit-reset": "9999999999",
    }
    if extra_headers:
        headers.update(extra_headers)
    return HttpResponse(
        status=status,
        headers=headers,
        body=json.dumps(data).encode("utf-8"),
        url="fixture",
    )


def build_demo_fixture_transport() -> FixtureTransport:
    """Deterministic merged PR fixture used by `eos github demo-fixture`."""
    transport = FixtureTransport()
    transport.add(
        "GET /repos/sergio-tr/engineering-os",
        {
            "full_name": "sergio-tr/engineering-os",
            "default_branch": "main",
            "private": False,
            "html_url": "https://github.com/sergio-tr/engineering-os",
        },
    )
    transport.add(
        "GET /repos/sergio-tr/engineering-os/branches/main",
        {"name": "main", "commit": {"sha": "abc111defaultbranchsha000"}},
    )
    transport.add(
        "GET /repos/sergio-tr/engineering-os/pulls",
        [
            {
                "number": 42,
                "title": "feat: fixture PR",
                "state": "closed",
                "merged": True,
                "merge_commit_sha": "mergecafe42deadbeef",
                "draft": False,
                "html_url": "https://github.com/sergio-tr/engineering-os/pull/42",
                "head": {"sha": "headsha42aaaaaaaa", "ref": "feat/fixture"},
                "base": {"sha": "basesha42bbbbbbbb", "ref": "main"},
            },
            {
                "number": 41,
                "title": "open fixture",
                "state": "open",
                "merged": False,
                "merge_commit_sha": None,
                "draft": False,
                "html_url": "https://github.com/sergio-tr/engineering-os/pull/41",
                "head": {"sha": "headsha41cccccccc", "ref": "feat/open"},
                "base": {"sha": "basesha41dddddddd", "ref": "main"},
            },
        ],
    )
    transport.add(
        "GET /repos/sergio-tr/engineering-os/pulls/42",
        {
            "number": 42,
            "title": "feat: fixture PR",
            "state": "closed",
            "merged": True,
            "merge_commit_sha": "mergecafe42deadbeef",
            "draft": False,
            "html_url": "https://github.com/sergio-tr/engineering-os/pull/42",
            "head": {"sha": "headsha42aaaaaaaa", "ref": "feat/fixture"},
            "base": {"sha": "basesha42bbbbbbbb", "ref": "main"},
        },
    )
    transport.add(
        "GET /repos/sergio-tr/engineering-os/commits/headsha42aaaaaaaa/status",
        {"state": "success", "statuses": [{"state": "success", "context": "ci"}]},
    )
    transport.add(
        "GET /repos/sergio-tr/engineering-os/commits/headsha42aaaaaaaa/check-runs",
        {
            "total_count": 1,
            "check_runs": [
                {"name": "tests", "status": "completed", "conclusion": "success"}
            ],
        },
    )
    transport.add(
        "GET /repos/sergio-tr/engineering-os/pulls/42/reviews",
        [{"id": 1, "state": "APPROVED", "user": {"login": "reviewer"}}],
    )
    return transport


def build_open_pr_transport() -> FixtureTransport:
    transport = FixtureTransport()
    transport.add(
        "GET /repos/acme/demo",
        {
            "full_name": "acme/demo",
            "default_branch": "main",
            "private": False,
            "html_url": "https://github.com/acme/demo",
        },
    )
    transport.add(
        "GET /repos/acme/demo/branches/main",
        {"name": "main", "commit": {"sha": "branchheadacme"}},
    )
    transport.add(
        "GET /repos/acme/demo/pulls/7",
        {
            "number": 7,
            "title": "wip",
            "state": "open",
            "merged": False,
            "merge_commit_sha": None,
            "head": {"sha": "openhead7", "ref": "feat/x"},
            "base": {"sha": "openbase7", "ref": "main"},
            "html_url": "https://github.com/acme/demo/pull/7",
            "draft": False,
        },
    )
    transport.add(
        "GET /repos/acme/demo/commits/openhead7/status",
        {"state": "pending", "statuses": []},
    )
    transport.add(
        "GET /repos/acme/demo/commits/openhead7/check-runs",
        {"total_count": 0, "check_runs": []},
    )
    transport.add("GET /repos/acme/demo/pulls/7/reviews", [])
    return transport
