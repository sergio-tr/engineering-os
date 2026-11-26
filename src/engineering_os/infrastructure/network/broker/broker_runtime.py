"""Per-execution TrustedEgressBroker lifecycle for Owner-operated probes (EOS-12/12.1).

Completes EOS-11 with startup/shutdown, UDS permissions, quotas, CONNECT
tunnel ownership and fail-closed cleanup. Real outbound sockets only when
`connect_fn` / `open_upstream_fn` is the live connector and Owner gates are
asserted upstream.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set
import os
import tempfile
import threading

from engineering_os.domain.models import new_id, utc_now
from engineering_os.infrastructure.network.broker.egress_broker import (
    ConnectFn,
    OpenUpstreamFn,
    ResolveFn,
    TrustedEgressBroker,
    blocked_connect,
    live_open_upstream,
    write_tcp_uds_relay_script,
)
from engineering_os.infrastructure.network.policy.egress_enforcer import DEFAULT_CURSOR_DESTINATIONS
from engineering_os.infrastructure.evidence import ERROR, SYNTHETIC, UNAVAILABLE


def live_connect(
    host: str,
    port: int,
    timeout: float,
    resolved_addrs: Optional[List[str]] = None,
) -> tuple:
    """Compatibility wrapper — prefer live_open_upstream (connection-owning)."""
    return live_open_upstream(host, port, timeout, resolved_addrs)


@dataclass
class BrokerInstance:
    broker_id: str
    execution_id: str
    socket_path: str
    relay_path: str
    work_dir: str
    started_at: str
    stopped_at: Optional[str] = None
    cleanup_verified: bool = False
    observations: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "broker_id": self.broker_id,
            "execution_id": self.execution_id,
            "socket_path": self.socket_path,
            "relay_path": self.relay_path,
            "work_dir": self.work_dir,
            "started_at": self.started_at,
            "stopped_at": self.stopped_at,
            "cleanup_verified": self.cleanup_verified,
            "observation_count": len(self.observations),
        }


class BrokerRuntime:
    """Manages one broker per execution with restricted UDS permissions."""

    def __init__(
        self,
        *,
        connect_fn: Optional[Callable[..., Any]] = None,
        open_upstream_fn: Optional[OpenUpstreamFn] = None,
        resolve_fn: Optional[ResolveFn] = None,
        allowed_destinations: Optional[Set[str]] = None,
        max_connections: int = 16,
        connect_timeout_seconds: float = 10.0,
        tunnel_deadline_seconds: float = 30.0,
        max_tunnel_bytes: int = 4 * 1024 * 1024,
        max_request_bytes: int = 64 * 1024,
        root: Optional[Path] = None,
    ) -> None:
        self.connect_fn = open_upstream_fn or connect_fn or blocked_connect
        self.resolve_fn = resolve_fn
        self.allowed = set(allowed_destinations or DEFAULT_CURSOR_DESTINATIONS)
        self.max_connections = max_connections
        self.connect_timeout_seconds = connect_timeout_seconds
        self.tunnel_deadline_seconds = tunnel_deadline_seconds
        self.max_tunnel_bytes = max_tunnel_bytes
        self.max_request_bytes = max_request_bytes
        self.root = Path(root or (Path(tempfile.gettempdir()) / "eos-egress-brokers"))
        self.root.mkdir(parents=True, exist_ok=True)
        self._active: Dict[str, TrustedEgressBroker] = {}
        self._instances: Dict[str, BrokerInstance] = {}
        self._lock = threading.RLock()

    def status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "policy_id": "uds-broker-network-none",
                "active_brokers": len(self._active),
                "instances": [i.to_dict() for i in self._instances.values()],
                "max_connections": self.max_connections,
                "max_request_bytes": self.max_request_bytes,
                "connect_timeout_seconds": self.connect_timeout_seconds,
                "tunnel_deadline_seconds": self.tunnel_deadline_seconds,
                "unrestricted_tcp_forwarder": False,
                "host_network_fallback": False,
                "podman_socket_mounted": False,
                "live_connect_enabled": self.connect_fn is not blocked_connect,
                "evidence_class": SYNTHETIC,
            }

    def start(self, *, execution_id: str) -> BrokerInstance:
        with self._lock:
            if execution_id in self._active:
                raise RuntimeError("broker_already_active_for_execution")
            broker_id = new_id("broker")
            work = self.root / execution_id
            if work.exists():
                for child in work.iterdir():
                    if child.is_file():
                        child.unlink(missing_ok=True)
            work.mkdir(parents=True, exist_ok=True)
            os.chmod(work, 0o700)
            sock = work / "broker.sock"
            relay = write_tcp_uds_relay_script(work / "relay.py")
            broker = TrustedEgressBroker(
                allowed_destinations=self.allowed,
                resolve_fn=self.resolve_fn,
                connect_fn=self.connect_fn,
                connect_timeout_seconds=self.connect_timeout_seconds,
                tunnel_deadline_seconds=self.tunnel_deadline_seconds,
                max_tunnel_bytes=self.max_tunnel_bytes,
                max_connections=self.max_connections,
                socket_path=str(sock),
            )
            path = broker.start_unix_server(str(sock))
            os.chmod(path, 0o600)
            st = os.stat(path)
            if st.st_mode & 0o077:
                os.chmod(path, 0o600)
            instance = BrokerInstance(
                broker_id=broker_id,
                execution_id=execution_id,
                socket_path=path,
                relay_path=str(relay),
                work_dir=str(work),
                started_at=utc_now(),
            )
            self._active[execution_id] = broker
            self._instances[execution_id] = instance
            return instance

    def get(self, execution_id: str) -> Optional[TrustedEgressBroker]:
        return self._active.get(execution_id)

    def instance(self, execution_id: str) -> Optional[BrokerInstance]:
        return self._instances.get(execution_id)

    def stop(self, execution_id: str) -> Dict[str, Any]:
        with self._lock:
            broker = self._active.pop(execution_id, None)
            instance = self._instances.get(execution_id)
            if broker is None:
                return {
                    "stopped": False,
                    "reason": "not_active",
                    "cleanup_verified": False,
                    "evidence_class": UNAVAILABLE,
                }
            broker.mark_crashed()
            broker.stop()
            observations = broker.observations()
            tunnel_stats = broker.tunnel_stats()
            tunnel_events = broker.tunnel_events()
            sock_gone = True
            if instance and Path(instance.socket_path).exists():
                try:
                    Path(instance.socket_path).unlink()
                except OSError:
                    sock_gone = False
            cleanup_ok = sock_gone
            if instance:
                instance.stopped_at = utc_now()
                instance.observations = observations
                instance.cleanup_verified = cleanup_ok
                try:
                    work = Path(instance.work_dir)
                    if work.is_dir():
                        for child in work.iterdir():
                            if child.name == "relay.py":
                                continue
                            if child.is_file():
                                child.unlink(missing_ok=True)
                except OSError:
                    cleanup_ok = False
                    instance.cleanup_verified = False
            return {
                "stopped": True,
                "cleanup_verified": cleanup_ok,
                "observations": observations,
                "tunnel_stats": tunnel_stats,
                "tunnel_events": tunnel_events,
                "instance": instance.to_dict() if instance else None,
                "evidence_class": SYNTHETIC if cleanup_ok else ERROR,
            }

    def interrupt(self, execution_id: str) -> Dict[str, Any]:
        """Fail-closed interrupt without full cleanup (probe case)."""
        broker = self._active.get(execution_id)
        if not broker:
            return {"interrupted": False, "reason": "not_active"}
        broker.mark_crashed()
        return {
            "interrupted": True,
            "fail_closed": True,
            "evaluate_api_cursor": broker.evaluate_destination(
                "api.cursor.com", 443
            ).to_dict(),
        }


def cursor_proxy_env(*, relay_port: int = 18080) -> Dict[str, str]:
    """Documented Cursor CLI proxy settings through the in-container relay."""
    proxy = f"http://127.0.0.1:{relay_port}"
    return {
        "HTTP_PROXY": proxy,
        "HTTPS_PROXY": proxy,
        "ALL_PROXY": proxy,
        "NO_PROXY": "",
        "NODE_USE_ENV_PROXY": "1",
        "EOS_EGRESS_RELAY_PORT": str(relay_port),
        "EOS_EGRESS_UDS": "/runtime/egress/broker.sock",
        "NODE_OPTIONS": "--no-experimental-fetch",
        "CURSOR_DISABLE_AUTO_UPDATE": "1",
    }


def proxy_compatibility_matrix() -> Dict[str, Any]:
    return {
        "documented_env": ["HTTP_PROXY", "HTTPS_PROXY", "NODE_USE_ENV_PROXY"],
        "configured": cursor_proxy_env(),
        "http_supported": "EXPECTED",
        "https_connect_supported": "EXPECTED",
        "websocket_guaranteed": False,
        "streaming_guaranteed": False,
        "auth_success_not_proxy_proof": True,
        "direct_network_fallback_forbidden": True,
        "live_blocked_until_owner_probe": True,
        "evidence_class": UNAVAILABLE,
        "note": (
            "Cursor Docs document HTTP_PROXY/HTTPS_PROXY and NODE_USE_ENV_PROXY=1. "
            "Successful API-key auth alone does not prove complete proxy coverage."
        ),
    }
