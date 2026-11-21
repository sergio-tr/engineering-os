"""Egress policy selection for Cursor ACP (EOS-11).

Primary enforceable path for Podman 3.4.4 WSL2: `--network=none` + trusted
host-side UDS egress broker (`TrustedEgressBroker`).

PastaAllowlistEgressPolicy is retained only as a capability-gated option for
Podman >= 4.4.1 and is NEVER reported ENFORCED merely because `pasta`/`passt`
binaries exist. Pasta is not a destination deny-by-default firewall.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set
import ipaddress
import re
import shutil

from engineering_os.infrastructure.evidence import ERROR, SYNTHETIC, UNAVAILABLE
from engineering_os.infrastructure.network.policy.network_policy import NetworkDecision, NetworkPolicy
from engineering_os.infrastructure.runtime.oci.podman_capabilities import (
    PASTA_MIN_VERSION,
    PodmanCapabilities,
    probe_podman_capabilities,
    version_tuple_to_str,
)


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
    if ":" in candidate and candidate.count(":") != 1:
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
    """Legacy/optional pasta path — capability gated. Not a destination firewall."""

    policy_id = "pasta-allowlist-egress"

    def __init__(
        self,
        *,
        allowed_destinations: Optional[Set[str]] = None,
        network_name: str = "eos-cursor-egress",
        pasta_available: Optional[bool] = None,
        rootless_podman: Optional[bool] = None,
        capabilities: Optional[PodmanCapabilities] = None,
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
        self.capabilities = capabilities
        if pasta_available is None:
            pasta_available = bool(shutil.which("pasta") or shutil.which("passt"))
        self.pasta_available = bool(pasta_available)
        self.rootless_podman = rootless_podman

    def readiness(self) -> Dict[str, Any]:
        caps = self.capabilities or probe_podman_capabilities()
        missing: List[str] = []
        if not caps.pasta_network_mode_supported:
            missing.append(
                f"pasta_requires_podman>={version_tuple_to_str(PASTA_MIN_VERSION)}"
            )
            if caps.version:
                missing.append(
                    f"observed_podman_version={version_tuple_to_str(caps.version)}"
                )
        if not self.pasta_available and not (
            caps.pasta_binary_present or caps.passt_binary_present
        ):
            missing.append("pasta_or_passt_binary")
        if caps.rootless is False or self.rootless_podman is False:
            missing.append("rootless_podman")
        if caps.rootless is None and self.rootless_podman is None:
            missing.append("rootless_podman_unverified")
        # Pasta alone never counts as destination enforcement.
        missing.append("pasta_is_not_destination_firewall")
        status = "BLOCKED"
        return {
            "policy_id": self.policy_id,
            "status": status,
            "mode": "pasta_allowlist_unenforceable_alone",
            "enforcement": "NOT_ENFORCED",
            "evidence_class": ERROR,
            "allowed_destinations": sorted(self.allowed),
            "host_network": False,
            "host_network_forbidden": self.host_network_forbidden,
            "network_name": self.network_name,
            "pasta_available": self.pasta_available
            or caps.pasta_binary_present
            or caps.passt_binary_present,
            "pasta_network_mode_supported": caps.pasta_network_mode_supported,
            "podman_version": version_tuple_to_str(caps.version),
            "rootless_podman": caps.rootless
            if caps.rootless is not None
            else self.rootless_podman,
            "dns_allowlist_insufficient_alone": True,
            "http_proxy_insufficient_alone": True,
            "ip_literal_bypass_denied": True,
            "private_host_interface_denied": True,
            "max_connections": self.max_connections,
            "connect_timeout_seconds": self.connect_timeout_seconds,
            "missing": missing,
            "owner_action": (
                "Do not install passt expecting Podman 3.4.4 pasta support. "
                "Use UdsBrokerEgressPolicy (--network=none + host broker) instead."
            ),
            "recommended_policy": "uds-broker-network-none",
            "note": (
                "Network name configuration or pasta binary presence does NOT "
                "equal ENFORCED destination filtering."
            ),
        }

    def evaluate(self, destination: str) -> NetworkDecision:
        # Always deny — pasta path is not treated as enforceable.
        decision = NetworkDecision(
            allowed=False,
            destination=destination,
            reason="pasta_policy_not_enforced",
            policy_id=self.policy_id,
        )
        self._observations.append(
            EgressObservation(
                destination=destination,
                allowed=False,
                reason=decision.reason,
                enforcement="NOT_ENFORCED",
            )
        )
        return decision

    def observations(self) -> List[Dict[str, Any]]:
        return [o.to_dict() for o in self._observations]

    def podman_network_args(self) -> List[str]:
        raise RuntimeError("pasta_egress_not_enforced_use_uds_broker")

    def audit_evidence(self) -> Dict[str, Any]:
        return {
            "policy": self.readiness(),
            "observations": self.observations(),
            "host_network_used": False,
            "enforcement": "NOT_ENFORCED",
        }


class UdsBrokerEgressPolicy(NetworkPolicy):
    """Enforceable egress via --network=none + trusted host UDS broker."""

    policy_id = "uds-broker-network-none"

    def __init__(
        self,
        *,
        allowed_destinations: Optional[Set[str]] = None,
        broker_ready: bool = False,
        broker_socket_path: Optional[str] = None,
        capabilities: Optional[PodmanCapabilities] = None,
        observations: Optional[List[EgressObservation]] = None,
    ) -> None:
        self.allowed = {
            d.lower() for d in (allowed_destinations or DEFAULT_CURSOR_DESTINATIONS)
        }
        self.broker_ready = broker_ready
        self.broker_socket_path = broker_socket_path
        self.capabilities = capabilities
        self._observations: List[EgressObservation] = list(observations or [])

    def readiness(self) -> Dict[str, Any]:
        caps = self.capabilities or probe_podman_capabilities()
        missing: List[str] = []
        if not caps.network_none_supported:
            missing.append("network_none_unsupported")
        if caps.rootless is False:
            missing.append("rootless_podman")
        if caps.rootless is None:
            missing.append("rootless_podman_unverified")
        if not self.broker_ready:
            missing.append("egress_broker_not_started")
        if not self.broker_socket_path:
            missing.append("broker_socket_path_unset")
        # READY only when broker is actually configured; still not ENFORCED until
        # Owner runtime probe proves isolation.
        if missing:
            status = "BLOCKED"
            enforcement = "NOT_ENFORCED"
            evidence = ERROR
        else:
            status = "READY_FOR_OWNER_PROBE"
            enforcement = "CONFIGURED_NOT_YET_PROBED"
            evidence = SYNTHETIC
        return {
            "policy_id": self.policy_id,
            "status": status,
            "mode": "network_none_uds_broker",
            "enforcement": enforcement,
            "evidence_class": evidence,
            "allowed_destinations": sorted(self.allowed),
            "host_network": False,
            "container_network": "none",
            "direct_outbound_from_container": False,
            "broker_ready": self.broker_ready,
            "broker_socket_path_configured": bool(self.broker_socket_path),
            "podman_version": version_tuple_to_str(caps.version),
            "pasta_network_mode_supported": caps.pasta_network_mode_supported,
            "http_proxy_insufficient_alone": True,
            "ip_literal_bypass_denied": True,
            "private_host_interface_denied": True,
            "dns_controlled_by_broker": True,
            "missing": missing,
            "owner_action": (
                "Run `eos network probe --dry-run`, then Owner-gated "
                "`eos network probe --execute ...` after image/broker setup."
            ),
            "note": (
                "ENFORCED requires successful Owner network probe evidence; "
                "configured broker alone is not enough."
            ),
        }

    def evaluate(self, destination: str) -> NetworkDecision:
        host = destination.lower().split("/")[0]
        if "://" in host:
            host = host.split("://", 1)[1]
        host = host.split("@")[-1]
        host_only = host.split(":")[0].strip("[]")
        if not self.broker_ready:
            decision = NetworkDecision(
                allowed=False,
                destination=destination,
                reason="egress_broker_unavailable",
                policy_id=self.policy_id,
            )
        elif is_ip_literal(host_only):
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
            decision = NetworkDecision(
                allowed=True,
                destination=destination,
                reason="allowlisted_via_uds_broker",
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
        return ["--network", "none"]

    def audit_evidence(self) -> Dict[str, Any]:
        return {
            "policy": self.readiness(),
            "observations": self.observations(),
            "host_network_used": False,
        }


class FailClosedEgressPolicy(NetworkPolicy):
    """Default production policy until UDS broker is configured."""

    policy_id = "fail-closed-cursor-egress"

    def readiness(self) -> Dict[str, Any]:
        caps = probe_podman_capabilities()
        return {
            "policy_id": self.policy_id,
            "status": "BLOCKED",
            "mode": "fail_closed",
            "enforcement": "NOT_ENFORCED",
            "evidence_class": UNAVAILABLE,
            "host_network": False,
            "podman_version": version_tuple_to_str(caps.version),
            "pasta_network_mode_supported": caps.pasta_network_mode_supported,
            "recommended_policy": "uds-broker-network-none",
            "missing": ["uds_broker_not_configured"],
            "owner_action": (
                "Configure UdsBrokerEgressPolicy with --network=none; "
                "do not rely on pasta for Podman 3.4.4."
            ),
            "note": "Fail closed: no Cursor egress until broker is READY_FOR_OWNER_PROBE",
        }

    def evaluate(self, destination: str) -> NetworkDecision:
        return NetworkDecision(
            allowed=False,
            destination=destination,
            reason="fail_closed",
            policy_id=self.policy_id,
        )


def select_egress_policy(
    *,
    capabilities: Optional[PodmanCapabilities] = None,
    broker_ready: bool = False,
    broker_socket_path: Optional[str] = None,
) -> NetworkPolicy:
    """Choose the concrete policy for this host. Prefer UDS broker on Podman 3.x."""
    caps = capabilities or probe_podman_capabilities()
    if broker_ready or broker_socket_path:
        return UdsBrokerEgressPolicy(
            broker_ready=broker_ready,
            broker_socket_path=broker_socket_path,
            capabilities=caps,
        )
    # Never auto-select pasta as ENFORCED.
    return FailClosedEgressPolicy()
