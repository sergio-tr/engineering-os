"""Paperclip REST API client (stdlib, default localhost)."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence

from engineering_os.infrastructure.github_client import (
    FixtureTransport,
    HttpResponse,
    HttpTransport,
    UrllibTransport,
)

DEFAULT_PAPERCLIP_URL = "http://127.0.0.1:3100"
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


class PaperclipClientError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status: Optional[int] = None,
        code: str = "paperclip_error",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.details = details or {}


def validate_company_id(company_id: str) -> str:
    value = (company_id or "").strip()
    if not value or not SAFE_ID_RE.match(value):
        raise PaperclipClientError("invalid_company_id", code="invalid_id")
    return value


def validate_resource_id(resource_id: str, *, kind: str = "resource") -> str:
    value = (resource_id or "").strip()
    if not value or not SAFE_ID_RE.match(value):
        raise PaperclipClientError(f"invalid_{kind}_id", code="invalid_id")
    return value


@dataclass
class PaperclipClient:
    """Read-focused Paperclip REST client with optional explicit issue create."""

    base_url: str = DEFAULT_PAPERCLIP_URL
    token: Optional[str] = None
    transport: Optional[HttpTransport] = None
    timeout_seconds: float = 10.0
    user_agent: str = "engineering-os-eos05/0.1"

    def __post_init__(self) -> None:
        base = (self.base_url or DEFAULT_PAPERCLIP_URL).rstrip("/")
        parsed = urllib.parse.urlparse(base)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise PaperclipClientError("invalid_base_url", code="invalid_url")
        # Local-first default; non-loopback HTTPS allowed when Owner configures URL.
        host = parsed.hostname or ""
        if parsed.scheme == "http" and host not in {"127.0.0.1", "localhost", "::1"}:
            raise PaperclipClientError(
                "non_local_http_rejected",
                code="invalid_url",
            )
        self.base_url = base
        self._allowed_host = parsed.netloc.lower()
        self.transport = self.transport or UrllibTransport(allow_redirects=False)
        self._token_present = bool(self.token)

    def redact(self) -> Dict[str, Any]:
        return {
            "base_url": self.base_url,
            "token_configured": self._token_present,
            "timeout_seconds": self.timeout_seconds,
        }

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "User-Agent": self.user_agent,
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _validate_url(self, url: str) -> None:
        parsed = urllib.parse.urlparse(url)
        if parsed.netloc.lower() != self._allowed_host:
            raise PaperclipClientError(
                f"host_rejected:{parsed.netloc}",
                code="host_rejected",
            )
        if parsed.scheme not in {"http", "https"}:
            raise PaperclipClientError("scheme_rejected", code="url_rejected")

    def _request(
        self,
        method: str,
        path: str,
        *,
        query: Optional[Dict[str, Any]] = None,
        body: Optional[Dict[str, Any]] = None,
        allow_write: bool = False,
    ) -> HttpResponse:
        method_u = method.upper()
        if method_u != "GET" and not allow_write:
            raise PaperclipClientError(
                f"write_method_rejected:{method_u}",
                code="write_rejected",
            )
        if method_u not in {"GET", "POST"}:
            raise PaperclipClientError(
                f"unsupported_method:{method_u}",
                code="write_rejected",
            )
        q = urllib.parse.urlencode(
            {k: v for k, v in (query or {}).items() if v is not None}
        )
        url = f"{self.base_url}{path}"
        if q:
            url = f"{url}?{q}"
        self._validate_url(url)
        headers = self._headers()
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")
        assert self.transport is not None
        if isinstance(self.transport, FixtureTransport):
            if method_u == "POST":
                return self._fixture_post(url, path, headers, data)
            resp = self.transport.request(
                "GET", url, headers, timeout=self.timeout_seconds
            )
            return self._raise_for_status(resp)
        # Live local HTTP/HTTPS via urllib (Owner-authorized runtime only).
        req = urllib.request.Request(
            url, data=data, headers=headers, method=method_u
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                raw = resp.read()
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                http_resp = HttpResponse(
                    status=getattr(resp, "status", 200),
                    headers=hdrs,
                    body=raw,
                    url=resp.geturl(),
                )
        except urllib.error.HTTPError as exc:
            body_b = exc.read() if hasattr(exc, "read") else b""
            http_resp = HttpResponse(
                status=exc.code,
                headers={k.lower(): v for k, v in (exc.headers or {}).items()},
                body=body_b,
                url=url,
            )
        except urllib.error.URLError as exc:
            raise PaperclipClientError(
                f"network_error:{exc.reason}",
                code="network_timeout"
                if "timed out" in str(exc.reason).lower()
                else "network_error",
            ) from exc
        return self._raise_for_status(http_resp)

    def _fixture_post(
        self,
        url: str,
        path: str,
        headers: Mapping[str, str],
        data: Optional[bytes],
    ) -> HttpResponse:
        assert isinstance(self.transport, FixtureTransport)
        key = f"POST {urllib.parse.urlparse(url).path}"
        self.transport.calls.append(("POST", url))
        if key in self.transport.routes:
            return self._raise_for_status(self.transport.routes[key])
        path_key = f"POST {path}"
        if path_key in self.transport.routes:
            return self._raise_for_status(self.transport.routes[path_key])
        raise PaperclipClientError(f"fixture_miss:{key}", status=404, code="fixture_miss")

    def _raise_for_status(self, resp: HttpResponse) -> HttpResponse:
        if resp.status in {401, 403}:
            raise PaperclipClientError(
                "authentication_failed" if resp.status == 401 else "authorization_failed",
                status=resp.status,
                code="auth_error",
            )
        if resp.status == 404:
            raise PaperclipClientError("not_found", status=404, code="not_found")
        if resp.status == 429:
            raise PaperclipClientError("rate_limited", status=429, code="rate_limited")
        if resp.status >= 400:
            raise PaperclipClientError(
                f"http_{resp.status}",
                status=resp.status,
                code="http_error",
            )
        return resp

    def _get_json(self, path: str, *, query: Optional[Dict[str, Any]] = None) -> Any:
        resp = self._request("GET", path, query=query)
        try:
            return resp.json()
        except Exception as exc:
            raise PaperclipClientError("invalid_json", code="schema_error") from exc

    def list_companies(self) -> List[Dict[str, Any]]:
        data = self._get_json("/api/companies")
        if isinstance(data, list):
            return [i for i in data if isinstance(i, dict)]
        if isinstance(data, dict) and isinstance(data.get("items"), list):
            return [i for i in data["items"] if isinstance(i, dict)]
        raise PaperclipClientError("unexpected_companies_payload", code="schema_error")

    def get_company(self, company_id: str) -> Dict[str, Any]:
        cid = validate_company_id(company_id)
        data = self._get_json(f"/api/companies/{cid}")
        if not isinstance(data, dict):
            raise PaperclipClientError("unexpected_company_payload", code="schema_error")
        return data

    def list_agents(self, company_id: str) -> List[Dict[str, Any]]:
        cid = validate_company_id(company_id)
        data = self._get_json(f"/api/companies/{cid}/agents")
        if isinstance(data, list):
            return [i for i in data if isinstance(i, dict)]
        raise PaperclipClientError("unexpected_agents_payload", code="schema_error")

    def get_org(self, company_id: str) -> Any:
        cid = validate_company_id(company_id)
        return self._get_json(f"/api/companies/{cid}/org")

    def list_projects(self, company_id: str) -> List[Dict[str, Any]]:
        cid = validate_company_id(company_id)
        data = self._get_json(f"/api/companies/{cid}/projects")
        if isinstance(data, list):
            return [i for i in data if isinstance(i, dict)]
        raise PaperclipClientError("unexpected_projects_payload", code="schema_error")

    def list_goals(self, company_id: str) -> List[Dict[str, Any]]:
        cid = validate_company_id(company_id)
        data = self._get_json(f"/api/companies/{cid}/goals")
        if isinstance(data, list):
            return [i for i in data if isinstance(i, dict)]
        raise PaperclipClientError("unexpected_goals_payload", code="schema_error")

    def list_issues(
        self, company_id: str, *, project_id: Optional[str] = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        cid = validate_company_id(company_id)
        query: Dict[str, Any] = {"limit": limit}
        if project_id:
            query["projectId"] = validate_resource_id(project_id, kind="project")
        data = self._get_json(f"/api/companies/{cid}/issues", query=query)
        if isinstance(data, list):
            return [i for i in data if isinstance(i, dict)]
        if isinstance(data, dict) and isinstance(data.get("items"), list):
            return [i for i in data["items"] if isinstance(i, dict)]
        raise PaperclipClientError("unexpected_issues_payload", code="schema_error")

    def get_issue(self, issue_id: str) -> Dict[str, Any]:
        iid = validate_resource_id(issue_id, kind="issue")
        data = self._get_json(f"/api/issues/{iid}")
        if not isinstance(data, dict):
            raise PaperclipClientError("unexpected_issue_payload", code="schema_error")
        return data

    def list_approvals(self, company_id: str) -> List[Dict[str, Any]]:
        cid = validate_company_id(company_id)
        data = self._get_json(f"/api/companies/{cid}/approvals")
        if isinstance(data, list):
            return [i for i in data if isinstance(i, dict)]
        raise PaperclipClientError("unexpected_approvals_payload", code="schema_error")

    def create_issue(
        self,
        company_id: str,
        payload: Dict[str, Any],
        *,
        apply: bool,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Owner-operated issue creation. Default callers must pass apply=False (dry-run)."""
        cid = validate_company_id(company_id)
        body = dict(payload)
        if idempotency_key:
            body["idempotencyKey"] = idempotency_key
        if not apply:
            return {
                "dry_run": True,
                "would_post": f"/api/companies/{cid}/issues",
                "payload": body,
                "note": "no Paperclip mutation performed",
            }
        resp = self._request(
            "POST",
            f"/api/companies/{cid}/issues",
            body=body,
            allow_write=True,
        )
        resp = self._raise_for_status(resp)
        data = resp.json()
        if not isinstance(data, dict):
            raise PaperclipClientError("unexpected_create_payload", code="schema_error")
        return {"dry_run": False, "issue": data}
