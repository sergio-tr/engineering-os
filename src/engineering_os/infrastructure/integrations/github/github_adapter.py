"""GitHub read-only repository integration adapter."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from engineering_os.infrastructure.adapters import (
    RepositoryObservation,
    RepositoryObservationPort,
    UnsupportedIntegrationOperation,
)
from engineering_os.infrastructure.evidence import (
    ERROR,
    LIVE_READ_ONLY,
    UNVERIFIED,
)
from engineering_os.infrastructure.integrations.github.github_client import (
    GitHubClientError,
    GitHubReadOnlyClient,
    parse_repository,
)


def _aggregate_ci(status_payload: Dict[str, Any], checks_payload: Dict[str, Any]) -> str:
    state = str(status_payload.get("state") or "pending").lower()
    runs = checks_payload.get("check_runs") or []
    conclusions = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        conclusions.append(str(run.get("conclusion") or run.get("status") or "").lower())
    if any(c in {"failure", "timed_out", "cancelled", "action_required"} for c in conclusions):
        return "failure"
    if any(c in {"in_progress", "queued", "pending", ""} for c in conclusions) and conclusions:
        # Prefer check-runs when present
        if all(c in {"success", "neutral", "skipped"} for c in conclusions if c):
            pass
        elif any(c in {"in_progress", "queued", "pending", "waiting"} for c in conclusions):
            return "pending"
    if conclusions and all(c in {"success", "neutral", "skipped"} for c in conclusions):
        return "success"
    if state in {"success", "failure", "pending", "error"}:
        return "error" if state == "error" else state
    return "unknown"


def _aggregate_reviews(reviews: List[Dict[str, Any]]) -> str:
    if not reviews:
        return "none"
    states = [str(r.get("state", "")).upper() for r in reviews]
    if "CHANGES_REQUESTED" in states:
        return "changes_requested"
    if "APPROVED" in states:
        return "approved"
    if "COMMENTED" in states:
        return "commented"
    if "DISMISSED" in states:
        return "dismissed"
    return "pending"


class GitHubReadOnlyRepositoryAdapter(RepositoryObservationPort):
    """Observes GitHub state. Never mutates GitHub resources."""

    name = "github-read-only"

    def __init__(
        self,
        client: GitHubReadOnlyClient,
        *,
        owner: str,
        repo: str,
    ) -> None:
        self.client = client
        self.owner, self.repo = parse_repository(f"{owner}/{repo}")
        self.last_error: Optional[Dict[str, Any]] = None

    @property
    def repository_identity(self) -> str:
        return f"{self.owner}/{self.repo}"

    def observe_repository(self) -> Dict[str, Any]:
        try:
            repo = self.client.get_repository(self.owner, self.repo)
            default_branch = str(repo.get("default_branch") or "main")
            branch = self.client.get_branch(self.owner, self.repo, default_branch)
            head_sha = ((branch.get("commit") or {}) if isinstance(branch, dict) else {}).get(
                "sha"
            )
            if isinstance(head_sha, dict):
                head_sha = head_sha.get("sha")
            self.last_error = None
            return {
                "repository_identity": self.repository_identity,
                "default_branch": default_branch,
                "head_sha": head_sha,
                "private": bool(repo.get("private")),
                "html_url": repo.get("html_url"),
                "evidence_class": LIVE_READ_ONLY,
                "rate_limit": self.client.redact()["rate_limit"],
            }
        except GitHubClientError as exc:
            self.last_error = {"code": exc.code, "status": exc.status, "message": str(exc)}
            return {
                "repository_identity": self.repository_identity,
                "error": self.last_error,
                "evidence_class": ERROR,
            }

    def list_pull_requests(self, *, state: str = "all") -> List[Dict[str, Any]]:
        try:
            prs = self.client.list_pull_requests(self.owner, self.repo, state=state)
            self.last_error = None
            return [self._summarize_pr(pr, evidence_class=LIVE_READ_ONLY) for pr in prs]
        except GitHubClientError as exc:
            self.last_error = {"code": exc.code, "status": exc.status, "message": str(exc)}
            raise

    def observe_pull_request(self, number: int) -> Dict[str, Any]:
        try:
            pr = self.client.get_pull_request(self.owner, self.repo, number)
            head_sha = ((pr.get("head") or {}) if isinstance(pr.get("head"), dict) else {}).get(
                "sha"
            )
            status_payload: Dict[str, Any] = {}
            checks_payload: Dict[str, Any] = {"check_runs": []}
            reviews: List[Dict[str, Any]] = []
            if head_sha:
                try:
                    status_payload = self.client.list_commit_statuses(
                        self.owner, self.repo, str(head_sha)
                    )
                except GitHubClientError:
                    status_payload = {"state": "unknown"}
                try:
                    checks_payload = self.client.list_check_runs(
                        self.owner, self.repo, str(head_sha)
                    )
                except GitHubClientError:
                    checks_payload = {"check_runs": []}
            try:
                reviews = self.client.list_pull_request_reviews(
                    self.owner, self.repo, number
                )
            except GitHubClientError:
                reviews = []
            summary = self._summarize_pr(pr, evidence_class=LIVE_READ_ONLY)
            summary["ci_status"] = _aggregate_ci(status_payload, checks_payload)
            summary["review_status"] = _aggregate_reviews(reviews)
            summary["check_runs_count"] = len(checks_payload.get("check_runs") or [])
            summary["combined_status_state"] = status_payload.get("state")
            summary["reviews_count"] = len(reviews)
            if summary.get("merged") and not summary.get("merge_commit_sha"):
                summary["evidence_class"] = UNVERIFIED
                summary["unverified_reason"] = "missing_merge_commit_sha"
            self.last_error = None
            return summary
        except GitHubClientError as exc:
            self.last_error = {"code": exc.code, "status": exc.status, "message": str(exc)}
            return {
                "pr_number": number,
                "repository_identity": self.repository_identity,
                "error": self.last_error,
                "evidence_class": ERROR,
                "pr_state": "error",
                "ci_status": "unknown",
                "review_status": "unknown",
                "merge_commit_sha": None,
            }

    def observe(
        self, project_id: str, execution_id: str, *, pr_number: Optional[int] = None
    ) -> RepositoryObservation:
        if pr_number is None:
            return RepositoryObservation(
                pr_identity=None,
                pr_state="unassociated",
                ci_status="unknown",
                merge_commit_sha=None,
                base_branch_sha=None,
                review_status="unknown",
                evidence_class=UNVERIFIED,
                repository_identity=self.repository_identity,
                details={"project_id": project_id, "execution_id": execution_id},
            )
        summary = self.observe_pull_request(pr_number)
        return RepositoryObservation(
            pr_identity=f"{self.repository_identity}#{pr_number}",
            pr_state=str(summary.get("pr_state") or "unknown"),
            ci_status=str(summary.get("ci_status") or "unknown"),
            merge_commit_sha=summary.get("merge_commit_sha"),
            base_branch_sha=summary.get("base_sha"),
            review_status=str(summary.get("review_status") or "unknown"),
            evidence_class=str(summary.get("evidence_class") or LIVE_READ_ONLY),
            repository_identity=self.repository_identity,
            pr_number=pr_number,
            head_sha=summary.get("head_sha"),
            base_ref=summary.get("base_ref"),
            details=summary,
        )

    def simulate_pr(self, project_id: str, execution_id: str) -> RepositoryObservation:
        raise UnsupportedIntegrationOperation(
            "GitHubReadOnlyRepositoryAdapter does not support simulate_pr"
        )

    def record_owner_merge_decision(
        self, execution_id: str, *, approved: bool
    ) -> RepositoryObservation:
        raise UnsupportedIntegrationOperation(
            "GitHubReadOnlyRepositoryAdapter rejects merge mutations; "
            "use observe/reconcile against real PR state"
        )

    def _summarize_pr(
        self, pr: Dict[str, Any], *, evidence_class: str
    ) -> Dict[str, Any]:
        merged = bool(pr.get("merged"))
        state = str(pr.get("state") or "unknown")
        if merged:
            pr_state = "merged"
        elif state == "closed":
            pr_state = "closed"
        else:
            pr_state = "open"
        head = pr.get("head") if isinstance(pr.get("head"), dict) else {}
        base = pr.get("base") if isinstance(pr.get("base"), dict) else {}
        return {
            "pr_number": pr.get("number"),
            "title": pr.get("title"),
            "pr_state": pr_state,
            "merged": merged,
            "merge_commit_sha": pr.get("merge_commit_sha"),
            "head_sha": head.get("sha"),
            "head_ref": head.get("ref"),
            "base_sha": base.get("sha"),
            "base_ref": base.get("ref"),
            "html_url": pr.get("html_url"),
            "repository_identity": self.repository_identity,
            "evidence_class": evidence_class,
            "draft": bool(pr.get("draft")),
        }
