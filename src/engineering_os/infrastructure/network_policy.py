"""Bounded egress policy for Cursor runtime vs offline fixtures."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from engineering_os.infrastructure.evidence import ERROR, SYNTHETIC, UNAVAILABLE


@dataclass
class NetworkDecision:
    allowed: bool
    destination: str
    reason: str
    policy_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "destination": self.destination,
            "reason": self.reason,
            "policy_id": self.policy_id,
        }


class NetworkPolicy(ABC):
    policy_id: str

    @abstractmethod
    def readiness(self) -> Dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def evaluate(self, destination: str) -> NetworkDecision:
        raise NotImplementedError


class DenyAllNetworkPolicy(NetworkPolicy):
    """Synthetic offline / project tools default — no egress."""

    policy_id = "deny-all"

    def readiness(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "status": "READY",
            "mode": "offline_deny",
            "evidence_class": SYNTHETIC,
            "host_network": False,
        }

    def evaluate(self, destination: str) -> NetworkDecision:
        return NetworkDecision(
            allowed=False,
            destination=destination,
            reason="denied_by_default",
            policy_id=self.policy_id,
        )


class UnenforcedNetworkPolicy(NetworkPolicy):
    """Reports BLOCKED when Cursor needs egress but no enforceable broker exists."""

    policy_id = "unenforced-cursor-egress"

    def readiness(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "status": "BLOCKED",
            "mode": "cursor_requires_egress",
            "evidence_class": ERROR,
            "host_network": False,
            "dns_allowlist_insufficient": True,
            "note": (
                "Cursor needs outbound connectivity; no enforceable network broker "
                "is configured. Do not disable isolation."
            ),
        }

    def evaluate(self, destination: str) -> NetworkDecision:
        return NetworkDecision(
            allowed=False,
            destination=destination,
            reason="network_broker_unavailable",
            policy_id=self.policy_id,
        )


class FixtureAllowlistNetworkPolicy(NetworkPolicy):
    """Injected test policy with explicit permitted destinations."""

    policy_id = "fixture-allowlist"

    def __init__(self, allowed: Optional[Set[str]] = None) -> None:
        self.allowed = set(allowed or {"api.cursor.com", "cursor.com"})

    def readiness(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "status": "READY_FIXTURE",
            "mode": "allowlist_fixture",
            "evidence_class": SYNTHETIC,
            "allowed_destinations": sorted(self.allowed),
            "host_network": False,
        }

    def evaluate(self, destination: str) -> NetworkDecision:
        from engineering_os.infrastructure.egress_enforcer import is_ip_literal

        host = destination.lower().split("/")[0]
        if "://" in host:
            host = host.split("://", 1)[1]
        host = host.split("@")[-1]
        host_only = host.split(":")[0].strip("[]")
        if is_ip_literal(host_only):
            return NetworkDecision(
                allowed=False,
                destination=destination,
                reason="ip_literal_bypass_denied",
                policy_id=self.policy_id,
            )
        if host_only in self.allowed or host in self.allowed:
            return NetworkDecision(
                allowed=True,
                destination=destination,
                reason="allowlisted_fixture",
                policy_id=self.policy_id,
            )
        return NetworkDecision(
            allowed=False,
            destination=destination,
            reason="not_allowlisted",
            policy_id=self.policy_id,
        )
