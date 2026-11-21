"""Concrete rootless Podman egress enforcement for Cursor ACP (EOS-10).

Chosen approach: pasta/slirp4netns custom network with DNS allowlist + no host
network + IP-literal deny at policy layer + fail-closed when pasta/CNI is absent.

HTTP_PROXY / application allowlists alone are NOT treated as enforcement.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
import ipaddress
import re
import shutil

from engineering_os.infrastructure.evidence import ERROR, SYNTHETIC, UNAVAILABLE
from engineering_os.infrastructure.network_policy import NetworkDecision, NetworkPolicy


DEFAULT_CURSOR_DESTINATIONS = frozenset(
    {
        "api.cursor.com",
        "api2.cursor.sh",
        "cursor.com",
        "www.cursor.com",
    }
)

_IP_LITERAL = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$|^\[?[0-9a-fA-F:]+\]?$"
)


def is_ip_literal(host: str) -> bool:
    candidate = host.strip().lower().split("/")[0]
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    if ":" in candidate and not candidate.count(":") == 1:
        # IPv6
        try:
            ipaddress.ip_address(candidate.split("%")[0])
            return True
        except ValueError:
            pass
    host_only = candidate.split(":")[0]
    try:
        ipaddress.ip_address(host_only)
        return True
    except ValueError:
        return bool(_IP_LITERAL.match(host_only))


def is_private_or_link_local(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host.strip().split("%")[0].strip("[]"))
    except ValueError:
        return False
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
    )


@dataclass
class EgressObservation:
    destination: str
    allowed: bool
    reason: str
    enforcement: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "destination": self.destination,
            "allowed": self.allowed,
            "reason": self.reason,
            "enforcement": self.enforcement,
        }


class PastaAllowlistEgressPolicy(NetworkPolicy):
    """Enforceable Cursor egress via rootless pasta network + destination policy.

    Podman argv uses a dedicated network (never --network=host). DNS names must
    match the allowlist; IP literals and private ranges are denied.
    """

    policy_id = "pasta-allowlist-egress"

    def __init__(
        self,
        *,
        allowed_destinations: Optional[Set[str]] = None,
        network_name: str = "eos-cursor-egress",
        pasta_available: Optional[bool] = None,
        rootless_podman: Optional[bool] = None,
        host_network_forbidden: bool = True,
        max_connections: int = 32,
        connect_timeout_seconds: int = 10,
        observations: Optional[List[EgressObservation]] = None,
    ) -> None:
        self.allowed = {
            d.lower() for d in (allowed_destinations or DEFAULT_CURSOR_DESTINATIONS)
        }
        self.network_name = network_name
        self.host_network_forbidden = host_network_forbidden
        self.max_connections = max_connections
        self.connect_timeout_seconds = connect_timeout_seconds
        self._observations: List[EgressObservation] = list(observations or [])
        if pasta_available is None:
            pasta_available = bool(shutil.which("pasta") or shutil.which("passt"))
        self.pasta_available = bool(pasta_available)
        self.rootless_podman = rootless_podman

    def readiness(self) -> Dict[str, Any]:
        missing: List[str] = []
        if not self.pasta_available:
            missing.append("pasta_or_passt_binary")
        if self.rootless_podman is False:
            missing.append("rootless_podman")
        if self.rootless_podman is None:
            missing.append("rootless_podman_unverified")
        status = "READY" if not missing else "BLOCKED"
        owner_action = None
        if "pasta_or_passt_binary" in missing:
            owner_action = (
                "Install passt/pasta for rootless Podman egress isolation, e.g. "
                "`sudo apt-get install -y passt` (Debian/Ubuntu) or the distro "
                "equivalent, then re-run `eos cursor readiness`."
            )
        return {
            "policy_id": self.policy_id,
            "status": status,
            "mode": "pasta_allowlist",
            "evidence_class": SYNTHETIC if not missing else ERROR,
            "allowed_destinations": sorted(self.allowed),
            "host_network": False,
            "host_network_forbidden": self.host_network_forbidden,
            "network_name": self.network_name,
            "pasta_available": self.pasta_available,
            "rootless_podman": self.rootless_podman,
            "dns_allowlist_insufficient_alone": True,
            "http_proxy_insufficient_alone": True,
            "ip_literal_bypass_denied": True,
            "private_host_interface_denied": True,
            "max_connections": self.max_connections,
            "connect_timeout_seconds": self.connect_timeout_seconds,
            "missing": missing,
            "owner_action": owner_action,
            "note": (
                "Network namespace must route only through the approved pasta path; "
                "application HTTP_PROXY is not sufficient enforcement."
            ),
        }

    def evaluate(self, destination: str) -> NetworkDecision:
        host = destination.lower().split("/")[0]
        # Strip scheme if present
        if "://" in host:
            host = host.split("://", 1)[1]
        host = host.split("@")[-1]
        host_only = host.split(":")[0].strip("[]")

        if is_ip_literal(host_only):
            decision = NetworkDecision(
                allowed=False,
                destination=destination,
                reason="ip_literal_bypass_denied",
                policy_id=self.policy_id,
            )
        elif is_private_or_link_local(host_only):
            decision = NetworkDecision(
                allowed=False,
                destination=destination,
                reason="private_or_link_local_denied",
                policy_id=self.policy_id,
            )
        elif host_only in self.allowed or host in self.allowed:
            if not self.pasta_available:
                decision = NetworkDecision(
                    allowed=False,
                    destination=destination,
                    reason="egress_enforcer_unavailable",
                    policy_id=self.policy_id,
                )
            else:
                decision = NetworkDecision(
                    allowed=True,
                    destination=destination,
                    reason="allowlisted_via_pasta",
                    policy_id=self.policy_id,
                )
        else:
            decision = NetworkDecision(
                allowed=False,
                destination=destination,
                reason="not_allowlisted",
                policy_id=self.policy_id,
            )
        self._observations.append(
            EgressObservation(
                destination=destination,
                allowed=decision.allowed,
                reason=decision.reason,
                enforcement=self.policy_id,
            )
        )
        return decision

    def observations(self) -> List[Dict[str, Any]]:
        return [o.to_dict() for o in self._observations]

    def podman_network_args(self) -> List[str]:
        """Argv fragment for Cursor launches. Never returns host networking."""
        ready = self.readiness()
        if ready["status"] != "READY":
            raise RuntimeError("egress_enforcement_unavailable")
        # Dedicated network name; pasta is Podman's rootless default backend when present.
        return ["--network", self.network_name]

    def audit_evidence(self) -> Dict[str, Any]:
        return {
            "policy": self.readiness(),
            "observations": self.observations(),
            "host_network_used": False,
        }


class FailClosedEgressPolicy(NetworkPolicy):
    """Default production policy until pasta enforcer is Host-verified."""

    policy_id = "fail-closed-cursor-egress"

    def readiness(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "status": "BLOCKED",
            "mode": "fail_closed",
            "evidence_class": UNAVAILABLE,
            "host_network": False,
            "missing": ["pasta_allowlist_enforcer_not_configured"],
            "owner_action": (
                "Configure PastaAllowlistEgressPolicy after installing passt/pasta "
                "and creating network `eos-cursor-egress`."
            ),
            "note": "Fail closed: no Cursor egress until enforcer is READY",
        }

    def evaluate(self, destination: str) -> NetworkDecision:
        return NetworkDecision(
            allowed=False,
            destination=destination,
            reason="fail_closed",
            policy_id=self.policy_id,
        )
