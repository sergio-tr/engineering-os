"""Cursor runtime credential broker interface (fail-closed, no secret persistence)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
import re

from engineering_os.domain.models import utc_now
from engineering_os.infrastructure.evidence import ERROR, UNAVAILABLE


SECRET_PATTERNS = (
    re.compile(r"(?i)cursor[_-]?api[_-]?key"),
    re.compile(r"(?i)authorization"),
    re.compile(r"(?i)bearer\s+[a-z0-9\-\._]+"),
    re.compile(r"sk-[A-Za-z0-9]{10,}"),
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


@dataclass
class CredentialLease:
    provider_id: str
    env_var_name: str
    execution_id: str
    expires_at: str
    delivered: bool = False
    # Never store the secret value on this object in durable form.
    reference: str = "ephemeral-host-broker"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "env_var_name": self.env_var_name,
            "execution_id": self.execution_id,
            "expires_at": self.expires_at,
            "delivered": self.delivered,
            "reference": self.reference,
            "secret_present_in_record": False,
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


class UnavailableCursorCredentialProvider(CredentialProvider):
    """Default: Cursor API key delivery unavailable until Owner configures broker."""

    provider_id = "cursor-api-key-unavailable"

    def readiness(self) -> Dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "status": "BLOCKED",
            "available": False,
            "evidence_class": UNAVAILABLE,
            "env_var": "CURSOR_API_KEY",
            "mount_home_forbidden": True,
            "sqlite_forbidden": True,
            "log_forbidden": True,
            "note": "Trusted host-side broker not configured; fail closed",
        }

    def lease(self, *, execution_id: str) -> CredentialLease:
        raise CredentialError("credential_provider_unavailable", code="unavailable")

    def materialize_env(self, lease: CredentialLease) -> Dict[str, str]:
        raise CredentialError("credential_provider_unavailable", code="unavailable")


class FixtureCursorCredentialProvider(CredentialProvider):
    """Test-only provider: issues a lease without exposing a real secret value."""

    provider_id = "cursor-api-key-fixture"

    def __init__(self, *, secret: str = "fixture-not-a-real-key") -> None:
        self._secret = secret

    def readiness(self) -> Dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "status": "READY_FIXTURE",
            "available": True,
            "evidence_class": "SYNTHETIC",
            "env_var": "CURSOR_API_KEY",
            "note": "Fixture provider for offline tests only",
        }

    def lease(self, *, execution_id: str) -> CredentialLease:
        return CredentialLease(
            provider_id=self.provider_id,
            env_var_name="CURSOR_API_KEY",
            execution_id=execution_id,
            expires_at=utc_now(),
            delivered=False,
            reference="fixture-broker",
        )

    def materialize_env(self, lease: CredentialLease) -> Dict[str, str]:
        lease.delivered = True
        # Caller must not persist this mapping.
        return {lease.env_var_name: self._secret}
