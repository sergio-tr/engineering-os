"""Read-only GitHub REST API client (stdlib only)."""

from __future__ import annotations

import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple


DEFAULT_API_BASE = "https://api.github.com"
OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")


class GitHubClientError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status: Optional[int] = None,
        code: str = "github_error",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.details = details or {}


@dataclass
class HttpResponse:
    status: int
    headers: Dict[str, str]
    body: bytes
    url: str

    def json(self) -> Any:
        if not self.body:
            return None
        return json.loads(self.body.decode("utf-8"))


class HttpTransport(ABC):
    @abstractmethod
    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        *,
        timeout: float,
    ) -> HttpResponse:
        raise NotImplementedError


class UrllibTransport(HttpTransport):
    """Live urllib transport. Used only when the Owner enables real sync."""

    def __init__(self, *, allow_redirects: bool = False) -> None:
        self.allow_redirects = allow_redirects
        self._ctx = ssl.create_default_context()

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        *,
        timeout: float,
    ) -> HttpResponse:
        req = urllib.request.Request(url, method=method, headers=dict(headers))
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self._ctx)
        )
        if not self.allow_redirects:
            # Fail closed on redirects — do not follow to untrusted hosts.
            class _NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
                    raise GitHubClientError(
                        f"redirect_rejected:{code}:{newurl}",
                        status=code,
                        code="redirect_rejected",
                    )

            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=self._ctx),
                _NoRedirect,
            )
        try:
            with opener.open(req, timeout=timeout) as resp:
                raw = resp.read()
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                return HttpResponse(
                    status=getattr(resp, "status", 200),
                    headers=hdrs,
                    body=raw,
                    url=resp.geturl(),
                )
        except GitHubClientError:
            raise
        except urllib.error.HTTPError as exc:
            body = exc.read() if hasattr(exc, "read") else b""
            hdrs = {k.lower(): v for k, v in (exc.headers or {}).items()}
            return HttpResponse(status=exc.code, headers=hdrs, body=body, url=url)
        except urllib.error.URLError as exc:
            raise GitHubClientError(
                f"network_error:{exc.reason}",
                code="network_timeout" if "timed out" in str(exc.reason).lower() else "network_error",
                details={"reason": str(exc.reason)},
            ) from exc


class FixtureTransport(HttpTransport):
    """Deterministic offline transport for tests and demos."""

    def __init__(
        self,
        routes: Optional[Mapping[str, HttpResponse | Dict[str, Any]]] = None,
    ) -> None:
        self.routes: Dict[str, HttpResponse] = {}
        self.calls: List[Tuple[str, str]] = []
        if routes:
            for key, value in routes.items():
                self.add(key, value)

    def add(self, key: str, value: HttpResponse | Dict[str, Any] | List[Any]) -> None:
        if isinstance(value, HttpResponse):
            self.routes[key] = value
            return
        body = json.dumps(value).encode("utf-8")
        self.routes[key] = HttpResponse(
            status=200,
            headers={"content-type": "application/json", "x-ratelimit-remaining": "4999"},
            body=body,
            url=key,
        )

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        *,
        timeout: float,
    ) -> HttpResponse:
        parsed = urllib.parse.urlparse(url)
        key = f"{method.upper()} {parsed.path}"
        if parsed.query:
            key = f"{key}?{parsed.query}"
        self.calls.append((method.upper(), url))
        # Exact match, then path-only match
        if key in self.routes:
            return self.routes[key]
        path_key = f"{method.upper()} {parsed.path}"
        if path_key in self.routes:
            return self.routes[path_key]
        raise GitHubClientError(
            f"fixture_miss:{key}",
            status=404,
            code="fixture_miss",
        )


def parse_repository(identity: str) -> Tuple[str, str]:
    value = (identity or "").strip()
    if value.endswith(".git"):
        value = value[:-4]
    if "/" not in value:
        raise GitHubClientError("invalid_repository_identity", code="invalid_repo")
    owner, repo = value.split("/", 1)
    owner, repo = owner.strip(), repo.strip()
    if not OWNER_RE.match(owner) or not REPO_RE.match(repo):
        raise GitHubClientError(
            f"invalid_repository_identity:{identity}",
            code="invalid_repo",
        )
    if ".." in owner or ".." in repo or "/" in repo:
        raise GitHubClientError("invalid_repository_identity", code="invalid_repo")
    return owner, repo


@dataclass
class RateLimitInfo:
    remaining: Optional[int] = None
    limit: Optional[int] = None
    reset: Optional[int] = None
    used: Optional[int] = None


@dataclass
class GitHubReadOnlyClient:
    """Bounded, read-only GitHub REST client."""

    api_base: str = DEFAULT_API_BASE
    token: Optional[str] = None
    transport: Optional[HttpTransport] = None
    timeout_seconds: float = 10.0
    max_retries: int = 2
    user_agent: str = "engineering-os-eos04/0.1"
    _last_rate_limit: RateLimitInfo = field(default_factory=RateLimitInfo)

    def __post_init__(self) -> None:
        base = self.api_base.rstrip("/")
        parsed = urllib.parse.urlparse(base)
        if parsed.scheme != "https" or not parsed.netloc:
            raise GitHubClientError("api_base_must_be_https", code="invalid_api_base")
        # Restrict to configured endpoint host only.
        self.api_base = base
        self._allowed_host = parsed.netloc.lower()
        self.transport = self.transport or UrllibTransport(allow_redirects=False)
        # Never keep token printable representation beyond presence flag.
        self._token_present = bool(self.token)

    def redact(self) -> Dict[str, Any]:
        return {
            "api_base": self.api_base,
            "token_configured": self._token_present,
            "timeout_seconds": self.timeout_seconds,
            "rate_limit": {
                "remaining": self._last_rate_limit.remaining,
                "limit": self._last_rate_limit.limit,
                "reset": self._last_rate_limit.reset,
            },
        }

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": self.user_agent,
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _validate_url(self, url: str) -> None:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https":
            raise GitHubClientError("non_https_url_rejected", code="url_rejected")
        if parsed.netloc.lower() != self._allowed_host:
            raise GitHubClientError(
                f"host_rejected:{parsed.netloc}",
                code="host_rejected",
            )

    def _request(self, method: str, path: str, *, query: Optional[Dict[str, Any]] = None) -> HttpResponse:
        if method.upper() != "GET":
            raise GitHubClientError(
                f"write_method_rejected:{method}",
                code="write_rejected",
            )
        q = urllib.parse.urlencode({k: v for k, v in (query or {}).items() if v is not None})
        url = f"{self.api_base}{path}"
        if q:
            url = f"{url}?{q}"
        self._validate_url(url)
        attempt = 0
        last_exc: Optional[Exception] = None
        while attempt <= self.max_retries:
            attempt += 1
            try:
                assert self.transport is not None
                resp = self.transport.request(
                    "GET", url, self._headers(), timeout=self.timeout_seconds
                )
                self._capture_rate_limit(resp.headers)
                if resp.status == 403 and self._is_rate_limited(resp):
                    if attempt <= self.max_retries:
                        time.sleep(min(0.05 * attempt, 0.2))  # conservative, tiny in tests
                        continue
                    raise GitHubClientError(
                        "rate_limited",
                        status=403,
                        code="rate_limited",
                        details={"rate_limit": self.redact()["rate_limit"]},
                    )
                if resp.status in {401, 403}:
                    raise GitHubClientError(
                        "authentication_failed" if resp.status == 401 else "authorization_failed",
                        status=resp.status,
                        code="auth_error",
                    )
                if resp.status == 404:
                    raise GitHubClientError(
                        "not_found",
                        status=404,
                        code="not_found",
                    )
                if resp.status >= 400:
                    raise GitHubClientError(
                        f"http_{resp.status}",
                        status=resp.status,
                        code="http_error",
                    )
                return resp
            except GitHubClientError as exc:
                if exc.code in {"network_timeout", "network_error"} and attempt <= self.max_retries:
                    last_exc = exc
                    time.sleep(min(0.05 * attempt, 0.2))
                    continue
                raise
        raise GitHubClientError(
            "retries_exhausted",
            code="retries_exhausted",
            details={"last": str(last_exc)},
        )

    def _capture_rate_limit(self, headers: Mapping[str, str]) -> None:
        def _int(name: str) -> Optional[int]:
            raw = headers.get(name) or headers.get(name.title())
            if raw is None:
                return None
            try:
                return int(raw)
            except ValueError:
                return None

        self._last_rate_limit = RateLimitInfo(
            remaining=_int("x-ratelimit-remaining"),
            limit=_int("x-ratelimit-limit"),
            reset=_int("x-ratelimit-reset"),
            used=_int("x-ratelimit-used"),
        )

    def _is_rate_limited(self, resp: HttpResponse) -> bool:
        if (resp.headers.get("x-ratelimit-remaining") or "") == "0":
            return True
        try:
            payload = resp.json() or {}
        except Exception:
            payload = {}
        msg = str(payload.get("message", "")).lower()
        return "rate limit" in msg

    def _paginate(self, path: str, *, query: Optional[Dict[str, Any]] = None, max_pages: int = 5) -> List[Any]:
        page = 1
        per_page = 30
        items: List[Any] = []
        while page <= max_pages:
            q = dict(query or {})
            q.update({"per_page": per_page, "page": page})
            resp = self._request("GET", path, query=q)
            chunk = resp.json()
            if not isinstance(chunk, list):
                raise GitHubClientError("unexpected_list_payload", code="schema_error")
            items.extend(chunk)
            link = resp.headers.get("link", "")
            if 'rel="next"' not in link or len(chunk) < per_page:
                break
            page += 1
        return items

    # --- public API ---
    def get_repository(self, owner: str, repo: str) -> Dict[str, Any]:
        parse_repository(f"{owner}/{repo}")
        data = self._request("GET", f"/repos/{owner}/{repo}").json()
        if not isinstance(data, dict):
            raise GitHubClientError("unexpected_repo_payload", code="schema_error")
        return data

    def get_branch(self, owner: str, repo: str, branch: str) -> Dict[str, Any]:
        parse_repository(f"{owner}/{repo}")
        data = self._request("GET", f"/repos/{owner}/{repo}/branches/{urllib.parse.quote(branch)}").json()
        if not isinstance(data, dict):
            raise GitHubClientError("unexpected_branch_payload", code="schema_error")
        return data

    def list_pull_requests(
        self, owner: str, repo: str, *, state: str = "all", max_pages: int = 3
    ) -> List[Dict[str, Any]]:
        parse_repository(f"{owner}/{repo}")
        items = self._paginate(
            f"/repos/{owner}/{repo}/pulls",
            query={"state": state, "sort": "updated", "direction": "desc"},
            max_pages=max_pages,
        )
        return [i for i in items if isinstance(i, dict)]

    def get_pull_request(self, owner: str, repo: str, number: int) -> Dict[str, Any]:
        parse_repository(f"{owner}/{repo}")
        if number <= 0:
            raise GitHubClientError("invalid_pr_number", code="invalid_pr")
        data = self._request("GET", f"/repos/{owner}/{repo}/pulls/{number}").json()
        if not isinstance(data, dict):
            raise GitHubClientError("unexpected_pr_payload", code="schema_error")
        return data

    def list_commit_statuses(self, owner: str, repo: str, ref: str) -> Dict[str, Any]:
        parse_repository(f"{owner}/{repo}")
        data = self._request(
            "GET", f"/repos/{owner}/{repo}/commits/{urllib.parse.quote(ref)}/status"
        ).json()
        if not isinstance(data, dict):
            raise GitHubClientError("unexpected_status_payload", code="schema_error")
        return data

    def list_check_runs(self, owner: str, repo: str, ref: str) -> Dict[str, Any]:
        parse_repository(f"{owner}/{repo}")
        data = self._request(
            "GET",
            f"/repos/{owner}/{repo}/commits/{urllib.parse.quote(ref)}/check-runs",
        ).json()
        if not isinstance(data, dict):
            raise GitHubClientError("unexpected_check_runs_payload", code="schema_error")
        return data

    def list_pull_request_reviews(
        self, owner: str, repo: str, number: int
    ) -> List[Dict[str, Any]]:
        parse_repository(f"{owner}/{repo}")
        items = self._paginate(
            f"/repos/{owner}/{repo}/pulls/{number}/reviews", max_pages=2
        )
        return [i for i in items if isinstance(i, dict)]
