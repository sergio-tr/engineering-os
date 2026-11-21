"""Paperclip organizational adapter (external source of org/issues)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from engineering_os.domain.models import utc_now
from engineering_os.infrastructure.adapters import OrganizationAdapter
from engineering_os.infrastructure.evidence import ERROR, LIVE_READ_ONLY, UNAVAILABLE
from engineering_os.infrastructure.integrations.paperclip.paperclip_client import (
    PaperclipClient,
    PaperclipClientError,
)


class PaperclipOrganizationAdapter(OrganizationAdapter):
    """Observes Paperclip company structure. Does not authorize local execution."""

    name = "paperclip"

    def __init__(self, client: PaperclipClient, *, company_id: Optional[str] = None) -> None:
        self.client = client
        self.company_id = company_id
        self.last_error: Optional[Dict[str, Any]] = None
        self.last_sync_at: Optional[str] = None

    def describe_org(self) -> Dict[str, Any]:
        if not self.company_id:
            return {
                "org": "paperclip",
                "mode": "LIVE_READ_ONLY",
                "company_id": None,
                "evidence_class": UNAVAILABLE,
                "error": {"code": "company_id_required"},
            }
        try:
            company = self.client.get_company(self.company_id)
            org = self.client.get_org(self.company_id)
            self.last_error = None
            return {
                "org": "paperclip",
                "mode": "LIVE_READ_ONLY",
                "company_id": self.company_id,
                "company": self._public_company(company),
                "hierarchy": org,
                "evidence_class": LIVE_READ_ONLY,
                "client": self.client.redact(),
            }
        except PaperclipClientError as exc:
            self.last_error = {"code": exc.code, "status": exc.status, "message": str(exc)}
            return {
                "org": "paperclip",
                "mode": "LIVE_READ_ONLY",
                "company_id": self.company_id,
                "evidence_class": ERROR,
                "error": self.last_error,
                "client": self.client.redact(),
            }

    def sync_snapshot(self) -> Dict[str, Any]:
        if not self.company_id:
            raise PaperclipClientError("company_id_required", code="company_id_required")
        cid = self.company_id
        company = self.client.get_company(cid)
        agents = self.client.list_agents(cid)
        org = self.client.get_org(cid)
        projects = self.client.list_projects(cid)
        goals = self.client.list_goals(cid)
        issues = self.client.list_issues(cid)
        try:
            approvals = self.client.list_approvals(cid)
        except PaperclipClientError:
            approvals = []
        self.last_sync_at = utc_now()
        self.last_error = None
        return {
            "company_id": cid,
            "company": self._public_company(company),
            "agents": [self._public_agent(a) for a in agents],
            "org": org,
            "projects": [self._public_project(p) for p in projects],
            "goals": [self._public_goal(g) for g in goals],
            "issues": [self._public_issue(i) for i in issues],
            "approvals": approvals,
            "synced_at": self.last_sync_at,
            "evidence_class": LIVE_READ_ONLY,
            "client": self.client.redact(),
        }

    def diagnostics(self) -> Dict[str, Any]:
        try:
            companies = self.client.list_companies()
            return {
                "available": True,
                "companies_count": len(companies),
                "company_id": self.company_id,
                "evidence_class": LIVE_READ_ONLY,
                "client": self.client.redact(),
                "last_error": self.last_error,
                "last_sync_at": self.last_sync_at,
            }
        except PaperclipClientError as exc:
            return {
                "available": False,
                "evidence_class": ERROR,
                "error": {"code": exc.code, "status": exc.status, "message": str(exc)},
                "client": self.client.redact(),
            }

    @staticmethod
    def _public_company(company: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": company.get("id"),
            "name": company.get("name"),
            "slug": company.get("slug") or company.get("shortname"),
        }

    @staticmethod
    def _public_agent(agent: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": agent.get("id"),
            "name": agent.get("name"),
            "role": agent.get("role"),
            "title": agent.get("title"),
            "status": agent.get("status"),
            "lifecycleState": agent.get("lifecycleState"),
            "reportsTo": agent.get("reportsTo"),
            "adapterType": agent.get("adapterType"),
            # Never include adapterConfig.env secrets
        }

    @staticmethod
    def _public_project(project: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": project.get("id"),
            "name": project.get("name"),
            "status": project.get("status"),
            "companyId": project.get("companyId"),
        }

    @staticmethod
    def _public_goal(goal: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": goal.get("id"),
            "title": goal.get("title") or goal.get("name"),
            "status": goal.get("status"),
            "projectId": goal.get("projectId"),
            "companyId": goal.get("companyId"),
        }

    @staticmethod
    def _public_issue(issue: Dict[str, Any]) -> Dict[str, Any]:
        blockers = issue.get("blockedByIssueIds") or issue.get("blockedBy") or []
        if not isinstance(blockers, list):
            blockers = []
        return {
            "id": issue.get("id"),
            "title": issue.get("title"),
            "status": issue.get("status"),
            "displayStatus": issue.get("displayStatus"),
            "projectId": issue.get("projectId"),
            "goalId": issue.get("goalId"),
            "assigneeAgentId": issue.get("assigneeAgentId") or issue.get("assigneeId"),
            "blockedByIssueIds": blockers,
            "companyId": issue.get("companyId"),
            "updatedAt": issue.get("updatedAt"),
        }
