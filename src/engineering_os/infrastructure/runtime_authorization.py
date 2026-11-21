"""Host-side runtime authorization — independent of UI sandbox_gate strings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Set
import hashlib
import hmac
import json
import time

from engineering_os.domain.models import utc_now


class AuthorizationError(RuntimeError):
    def __init__(self, message: str, *, code: str = "authorization_error") -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class RuntimeAuthorization:
    """Bounded single-use authorization for one ACP sandbox launch."""

    authorization_id: str
    execution_id: str
    project_id: str
    workspace_id: str
    agent_id: str
    image_digest: str
    cpu_limit: str
    memory_limit: str
    pids_limit: int
    network_mode: str
    expires_at_unix: int
    nonce: str
    signature: str
    scopes: tuple[str, ...] = ("acp.sandbox.launch",)
    issued_at: str = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "authorization_id": self.authorization_id,
            "execution_id": self.execution_id,
            "project_id": self.project_id,
            "workspace_id": self.workspace_id,
            "agent_id": self.agent_id,
            "image_digest": self.image_digest,
            "cpu_limit": self.cpu_limit,
            "memory_limit": self.memory_limit,
            "pids_limit": self.pids_limit,
            "network_mode": self.network_mode,
            "expires_at_unix": self.expires_at_unix,
            "nonce": self.nonce,
            "signature": self.signature,
            "scopes": list(self.scopes),
            "issued_at": self.issued_at,
        }

    def signing_payload(self) -> bytes:
        body = {
            "authorization_id": self.authorization_id,
            "execution_id": self.execution_id,
            "project_id": self.project_id,
            "workspace_id": self.workspace_id,
            "agent_id": self.agent_id,
            "image_digest": self.image_digest,
            "cpu_limit": self.cpu_limit,
            "memory_limit": self.memory_limit,
            "pids_limit": self.pids_limit,
            "network_mode": self.network_mode,
            "expires_at_unix": self.expires_at_unix,
            "nonce": self.nonce,
            "scopes": list(self.scopes),
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


class RuntimeAuthorizationVerifier:
    """Verifies host-side authorizations. Issuance remains disabled in production."""

    def __init__(
        self,
        *,
        secret: bytes,
        issuance_enabled: bool = False,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        self.secret = secret
        self.issuance_enabled = issuance_enabled
        self.clock = clock or time.time
        self._consumed: Set[str] = set()

    def sign(self, auth: RuntimeAuthorization) -> str:
        return hmac.new(self.secret, auth.signing_payload(), hashlib.sha256).hexdigest()

    def issue_test_only(self, **fields: Any) -> RuntimeAuthorization:
        """Test/fixture issuance only — refuse when issuance_enabled is False."""
        if not self.issuance_enabled:
            raise AuthorizationError(
                "authorization_issuance_disabled",
                code="issuance_disabled",
            )
        auth = RuntimeAuthorization(signature="", **fields)
        sig = self.sign(auth)
        return RuntimeAuthorization(**{**fields, "signature": sig})

    def verify(
        self,
        auth: RuntimeAuthorization,
        *,
        execution_id: str,
        project_id: str,
        workspace_id: str,
        agent_id: str,
        image_digest: str,
        network_mode: str,
        cpu_limit: str,
        memory_limit: str,
        pids_limit: int,
    ) -> Dict[str, Any]:
        now = int(self.clock())
        if auth.expires_at_unix < now:
            raise AuthorizationError("authorization_expired", code="expired")
        if auth.authorization_id in self._consumed:
            raise AuthorizationError("authorization_replayed", code="replay")
        expected = self.sign(auth)
        if not hmac.compare_digest(expected, auth.signature):
            raise AuthorizationError("authorization_signature_invalid", code="bad_signature")
        checks = {
            "execution_id": auth.execution_id == execution_id,
            "project_id": auth.project_id == project_id,
            "workspace_id": auth.workspace_id == workspace_id,
            "agent_id": auth.agent_id == agent_id,
            "image_digest": auth.image_digest == image_digest,
            "network_mode": auth.network_mode == network_mode,
            "cpu_limit": auth.cpu_limit == cpu_limit,
            "memory_limit": auth.memory_limit == memory_limit,
            "pids_limit": auth.pids_limit == pids_limit,
        }
        if not all(checks.values()):
            raise AuthorizationError(
                "authorization_binding_mismatch",
                code="binding_mismatch",
            )
        self._consumed.add(auth.authorization_id)
        return {
            "ok": True,
            "authorization_id": auth.authorization_id,
            "consumed": True,
            "checks": checks,
        }
