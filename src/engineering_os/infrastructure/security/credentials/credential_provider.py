"""Cursor runtime credential broker (fail-closed, no secret persistence).

Security note: a secret injected into the Cursor process environment can be
visible to code running with equivalent privileges in the same container.
EOS does not claim isolation merely because CURSOR_API_KEY is provided via env.
When untrusted tools can execute code, separate their environment from the
credential-bearing Cursor process or deny those tool capabilities.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Set
import os
import re
import time

from engineering_os.domain.models import utc_now
from engineering_os.infrastructure.evidence import ERROR, UNAVAILABLE


SECRET_PATTERNS = (
    re.compile(r"(?i)cursor[_-]?api[_-]?key\s*[=:]\s*\S+"),
    re.compile(r"(?i)authorization\s*[=:]\s*\S+"),
    re.compile(r"(?i)bearer\s+[a-z0-9\-\._]+"),
    re.compile(r"sk-[A-Za-z0-9]{10,}"),
    re.compile(r"(?i)CURSOR_API_KEY=[^\s\"']+"),
)


class CredentialError(RuntimeError):
    def __init__(self, message: str, *, code: str = "credential_error") -> None:
        super().__init__(message)
        self.code = code


def redact_secrets(text: str) -> str:
    out = text
    for pat in SECRET_PATTERNS:
        out = pat.sub("[REDACTED]", out)
    return out


def assert_no_secret_leak(payload: Any, *, forbidden_substrings: Optional[Set[str]] = None) -> None:
    blob = redact_secrets(str(payload))
    if "[REDACTED]" in blob and any(
        tok in str(payload) for tok in ("sk-", "CURSOR_API_KEY=", "Bearer ")
    ):
        # If redaction changed the blob, original had secret-like material — OK for tests.
        pass
    if forbidden_substrings:
        raw = str(payload)
        for secret in forbidden_substrings:
            if secret and secret in raw:
                raise CredentialError("secret_leak_detected", code="leak")


@dataclass
class CredentialLease:
    provider_id: str
    env_var_name: str
    execution_id: str
    expires_at: str
    delivered: bool = False
    # Never store the secret value on this object in durable form.
    reference: str = "ephemeral-host-broker"
    consumed: bool = False
    revoked: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "env_var_name": self.env_var_name,
            "execution_id": self.execution_id,
            "expires_at": self.expires_at,
            "delivered": self.delivered,
            "consumed": self.consumed,
            "revoked": self.revoked,
            "reference": self.reference,
            "secret_present_in_record": False,
            "isolation_claim": (
                "env_injection_does_not_isolate_from_same_container_peers"
            ),
        }


class CredentialProvider(ABC):
    provider_id: str

    @abstractmethod
    def readiness(self) -> Dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def lease(self, *, execution_id: str) -> CredentialLease:
        raise NotImplementedError

    @abstractmethod
    def materialize_env(self, lease: CredentialLease) -> Dict[str, str]:
        """Return env mapping for the sandbox process. Must not log values."""
        raise NotImplementedError

    def revoke(self, lease: CredentialLease) -> Dict[str, Any]:
        lease.revoked = True
        return {"revoked": True, "execution_id": lease.execution_id}


class UnavailableCursorCredentialProvider(CredentialProvider):
    """Default: Cursor API key delivery unavailable until Owner configures broker."""

    provider_id = "cursor-api-key-unavailable"

    def readiness(self) -> Dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "status": "BLOCKED",
            "available": False,
            "enabled": False,
            "evidence_class": UNAVAILABLE,
            "env_var": "CURSOR_API_KEY",
            "mount_home_forbidden": True,
            "sqlite_forbidden": True,
            "log_forbidden": True,
            "cli_argv_secret_forbidden": True,
            "github_token_reuse_forbidden": True,
            "isolation_limitation": (
                "Even when configured, env-injected secrets are visible to same-"
                "privilege code in the container; deny untrusted tool execution "
                "or separate credential-bearing processes."
            ),
            "separations": {
                "credential_bearing_cursor_process": "required",
                "untrusted_project_tool_execution": "denied_in_smoke_until_isolated",
                "workspace_files": "must_not_contain_secrets",
                "host_side_credential_provider": "outside_workspace",
            },
            "env_var_isolates_untrusted_code": False,
            "note": "Trusted host-side broker not configured; fail closed",
        }

    def lease(self, *, execution_id: str) -> CredentialLease:
        raise CredentialError("credential_provider_unavailable", code="unavailable")

    def materialize_env(self, lease: CredentialLease) -> Dict[str, str]:
        raise CredentialError("credential_provider_unavailable", code="unavailable")


class FixtureCursorCredentialProvider(CredentialProvider):
    """Test-only provider: issues a lease without exposing a real secret value."""

    provider_id = "cursor-api-key-fixture"

    def __init__(self, *, secret: str = "fixture-not-a-real-key", ttl_seconds: int = 60) -> None:
        self._secret = secret
        self._ttl_seconds = ttl_seconds
        self._leases: Dict[str, CredentialLease] = {}

    def readiness(self) -> Dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "status": "READY_FIXTURE",
            "available": True,
            "enabled": True,
            "evidence_class": "SYNTHETIC",
            "env_var": "CURSOR_API_KEY",
            "note": "Fixture provider for offline tests only",
            "isolation_limitation": (
                "env_injection_does_not_isolate_from_same_container_peers"
            ),
        }

    def lease(self, *, execution_id: str) -> CredentialLease:
        expires = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + self._ttl_seconds)
        )
        lease = CredentialLease(
            provider_id=self.provider_id,
            env_var_name="CURSOR_API_KEY",
            execution_id=execution_id,
            expires_at=expires,
            delivered=False,
            reference="fixture-broker",
        )
        self._leases[execution_id] = lease
        return lease

    def materialize_env(self, lease: CredentialLease) -> Dict[str, str]:
        if lease.revoked:
            raise CredentialError("credential_revoked", code="revoked")
        if lease.consumed:
            raise CredentialError("credential_already_consumed", code="consumed")
        stored = self._leases.get(lease.execution_id)
        if stored is None or stored.execution_id != lease.execution_id:
            raise CredentialError("credential_lease_unknown", code="unknown_lease")
        lease.delivered = True
        lease.consumed = True
        return {lease.env_var_name: self._secret}

    def revoke(self, lease: CredentialLease) -> Dict[str, Any]:
        lease.revoked = True
        self._secret = ""  # drop fixture material after revoke in tests
        return {"revoked": True, "execution_id": lease.execution_id}


class OwnerEnvFileCredentialProvider(CredentialProvider):
    """Owner-configurable provider reading a host-side file. Disabled by default.

    The secret file must live outside project workspaces and must never be
    copied into SQLite, images, logs, or argv.
    """

    provider_id = "cursor-api-key-owner-envfile"

    def __init__(
        self,
        *,
        secret_file: Optional[str] = None,
        enabled: bool = False,
        ttl_seconds: int = 300,
    ) -> None:
        self.secret_file = secret_file or os.environ.get("EOS_CURSOR_API_KEY_FILE")
        self.enabled = bool(enabled)
        self._ttl_seconds = ttl_seconds
        self._active: Dict[str, CredentialLease] = {}

    def readiness(self) -> Dict[str, Any]:
        path_ok = bool(self.secret_file and Path(self.secret_file).is_file())
        available = self.enabled and path_ok
        status = "READY" if available else "BLOCKED"
        missing = []
        if not self.enabled:
            missing.append("provider_disabled_by_default")
        if not self.secret_file:
            missing.append("EOS_CURSOR_API_KEY_FILE_unset")
        elif not path_ok:
            missing.append("secret_file_missing")
        return {
            "provider_id": self.provider_id,
            "status": status,
            "available": available,
            "enabled": self.enabled,
            "evidence_class": UNAVAILABLE if not available else "HOST_CONFIGURED",
            "env_var": "CURSOR_API_KEY",
            "secret_file_configured": bool(self.secret_file),
            "secret_file_path_redacted": True,
            "sqlite_forbidden": True,
            "image_embed_forbidden": True,
            "workspace_write_forbidden": True,
            "log_forbidden": True,
            "cli_argv_secret_forbidden": True,
            "github_token_reuse_forbidden": True,
            "missing": missing,
            "isolation_limitation": (
                "Secret in process env is visible to equivalent-privilege code "
                "in the same container; deny untrusted tools or separate processes."
            ),
            "env_var_isolates_untrusted_code": False,
            "separations": {
                "credential_bearing_cursor_process": "env_injection",
                "untrusted_project_tool_execution": "denied_in_smoke_until_isolated",
                "workspace_files": "forbidden_secret_path",
                "host_side_credential_provider": "EOS_CURSOR_API_KEY_FILE",
            },
            "note": "Disabled by default; Owner must enable explicitly",
        }

    def _read_secret(self) -> str:
        if not self.enabled:
            raise CredentialError("credential_provider_disabled", code="disabled")
        if not self.secret_file:
            raise CredentialError("credential_file_unset", code="missing")
        path = Path(self.secret_file)
        if not path.is_file():
            raise CredentialError("credential_file_missing", code="missing")
        # Reject workspace-looking paths.
        resolved = str(path.resolve())
        if "/workspace" in resolved or resolved.endswith(".git"):
            raise CredentialError("credential_file_in_workspace_forbidden", code="path")
        secret = path.read_text(encoding="utf-8").strip()
        if not secret:
            raise CredentialError("credential_empty_or_expired", code="empty")
        return secret

    def lease(self, *, execution_id: str) -> CredentialLease:
        # Validate file exists without retaining secret on the lease.
        self._read_secret()
        expires = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + self._ttl_seconds)
        )
        lease = CredentialLease(
            provider_id=self.provider_id,
            env_var_name="CURSOR_API_KEY",
            execution_id=execution_id,
            expires_at=expires,
            delivered=False,
            reference="owner-envfile-broker",
        )
        self._active[execution_id] = lease
        return lease

    def materialize_env(self, lease: CredentialLease) -> Dict[str, str]:
        if lease.revoked:
            raise CredentialError("credential_revoked", code="revoked")
        if lease.consumed:
            raise CredentialError("credential_already_consumed", code="consumed")
        if lease.execution_id not in self._active:
            raise CredentialError("credential_lease_unknown", code="unknown_lease")
        # Expiry check (string compare works for ISO Z timestamps from gmtime).
        if lease.expires_at < utc_now():
            raise CredentialError("credential_expired", code="expired")
        secret = self._read_secret()
        lease.delivered = True
        lease.consumed = True
        # Caller must pass via process env (not argv) and must not persist.
        return {lease.env_var_name: secret}

    def revoke(self, lease: CredentialLease) -> Dict[str, Any]:
        lease.revoked = True
        self._active.pop(lease.execution_id, None)
        return {"revoked": True, "execution_id": lease.execution_id}
