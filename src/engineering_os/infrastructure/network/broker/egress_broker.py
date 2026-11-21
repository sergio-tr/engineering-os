"""Trusted host-side egress broker for rootless Podman + --network=none (EOS-11).

Design (compatible with Podman 3.4.4):
- Container has no direct outbound route (`--network=none`).
- Host runs an allowlisted HTTP CONNECT / forward proxy on a Unix domain socket.
- A tiny TCP→UDS relay inside the container (loopback only) exposes HTTP_PROXY.
- Destination validation, DNS control, IP-literal deny and private-range deny
  happen in the trusted broker — never by HTTP_PROXY alone.

This module does not open real network connections during automated tests when
`connect_fn` is injected / `dry_run=True`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import ipaddress
import json
import os
import select
import socket
import socketserver
import tempfile
import threading

from engineering_os.domain.models import new_id, utc_now
from engineering_os.infrastructure.network.policy.egress_enforcer import (
    DEFAULT_CURSOR_DESTINATIONS,
    is_ip_literal,
    is_private_or_link_local,
)
from engineering_os.infrastructure.evidence import ERROR, SYNTHETIC, UNAVAILABLE


class EgressBrokerError(RuntimeError):
    def __init__(self, message: str, *, code: str = "egress_broker_error") -> None:
        super().__init__(message)
        self.code = code


ConnectFn = Callable[[str, int, float], Tuple[bool, str]]
ResolveFn = Callable[[str], List[str]]


def default_resolve(host: str) -> List[str]:
    """Real DNS — not used in automated tests."""
    infos = socket.getaddrinfo(host, None)
    addrs: List[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in addrs:
            addrs.append(addr)
    return addrs


def blocked_connect(host: str, port: int, timeout: float) -> Tuple[bool, str]:
    return False, "connect_disabled_in_offline_mode"


@dataclass
class BrokerDecision:
    allowed: bool
    host: str
    port: int
    reason: str
    resolved_addrs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "host": self.host,
            "port": self.port,
            "reason": self.reason,
            "resolved_addrs": list(self.resolved_addrs),
        }


class TrustedEgressBroker:
    """Allowlist HTTP proxy policy engine + optional UDS server."""

    policy_id = "uds-broker-network-none"

    def __init__(
        self,
        *,
        allowed_destinations: Optional[Set[str]] = None,
        allowed_ports: Optional[Set[int]] = None,
        resolve_fn: Optional[ResolveFn] = None,
        connect_fn: Optional[ConnectFn] = None,
        connect_timeout_seconds: float = 10.0,
        max_connections: int = 32,
        socket_path: Optional[str] = None,
    ) -> None:
        self.allowed = {
            d.lower() for d in (allowed_destinations or DEFAULT_CURSOR_DESTINATIONS)
        }
        self.allowed_ports = set(allowed_ports or {443, 80})
        self.resolve_fn = resolve_fn  # None => do not resolve in evaluate-only path
        self.connect_fn = connect_fn or blocked_connect
        self.connect_timeout_seconds = connect_timeout_seconds
        self.max_connections = max_connections
        self.socket_path = socket_path
        self._observations: List[Dict[str, Any]] = []
        self._lock = threading.RLock()
        self._server: Optional[socketserver.ThreadingUnixStreamServer] = None
        self._thread: Optional[threading.Thread] = None
        self._active = 0
        self._crashed = False

    def readiness(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "status": "READY" if not self._crashed else "BLOCKED",
            "mode": "network_none_uds_broker",
            "enforcement": "broker_destination_allowlist",
            "evidence_class": SYNTHETIC if not self._crashed else ERROR,
            "host_network": False,
            "container_network": "none",
            "direct_outbound_from_container": False,
            "http_proxy_insufficient_alone": True,
            "pasta_not_required": True,
            "allowed_destinations": sorted(self.allowed),
            "allowed_ports": sorted(self.allowed_ports),
            "socket_path_configured": bool(self.socket_path),
            "socket_listening": bool(self._server is not None),
            "max_connections": self.max_connections,
            "connect_timeout_seconds": self.connect_timeout_seconds,
            "ip_literal_bypass_denied": True,
            "private_host_interface_denied": True,
            "dns_controlled_by_broker": True,
            "crashed": self._crashed,
            "note": (
                "Container must use --network=none and reach the host only via "
                "the mounted UDS relay; HTTPS_PROXY alone is not isolation."
            ),
        }

    def evaluate_destination(self, host: str, port: int = 443) -> BrokerDecision:
        host_l = host.lower().strip().strip("[]")
        if "://" in host_l:
            host_l = host_l.split("://", 1)[1]
        host_l = host_l.split("@")[-1].split("/")[0].split(":")[0]

        if self._crashed:
            decision = BrokerDecision(False, host_l, port, "broker_crashed")
        elif is_ip_literal(host_l):
            decision = BrokerDecision(False, host_l, port, "ip_literal_bypass_denied")
        elif is_private_or_link_local(host_l):
            decision = BrokerDecision(False, host_l, port, "private_or_link_local_denied")
        elif port not in self.allowed_ports:
            decision = BrokerDecision(False, host_l, port, "port_not_allowlisted")
        elif host_l not in self.allowed:
            decision = BrokerDecision(False, host_l, port, "destination_not_allowlisted")
        else:
            resolved: List[str] = []
            if self.resolve_fn is not None:
                try:
                    resolved = list(self.resolve_fn(host_l))
                except Exception as exc:  # noqa: BLE001
                    decision = BrokerDecision(
                        False, host_l, port, f"dns_failed:{exc}", resolved
                    )
                    self._observe(decision)
                    return decision
                for addr in resolved:
                    if is_private_or_link_local(addr) or addr in {
                        "0.0.0.0",
                        "::",
                        "::1",
                    }:
                        decision = BrokerDecision(
                            False,
                            host_l,
                            port,
                            "dns_rebinding_or_private_resolution",
                            resolved,
                        )
                        self._observe(decision)
                        return decision
            decision = BrokerDecision(
                True, host_l, port, "allowlisted_via_broker", resolved
            )
        self._observe(decision)
        return decision

    def _observe(self, decision: BrokerDecision) -> None:
        with self._lock:
            self._observations.append(
                {**decision.to_dict(), "observed_at": utc_now()}
            )

    def observations(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._observations)

    def mark_crashed(self) -> None:
        self._crashed = True

    def probe_plan(self) -> Dict[str, Any]:
        """Offline dry-run plan of Owner network verification cases."""
        cases = [
            ("api.cursor.com", 443, True, "allowed_destination"),
            ("evil.example", 443, False, "unapproved_public"),
            ("1.2.3.4", 443, False, "direct_ip"),
            ("10.0.0.1", 443, False, "private_network"),
            ("127.0.0.1", 443, False, "loopback_host"),
            ("169.254.169.254", 80, False, "metadata_link_local"),
            ("::1", 443, False, "ipv6_loopback"),
        ]
        results = []
        for host, port, expect_allow, label in cases:
            d = self.evaluate_destination(host, port)
            results.append(
                {
                    "case": label,
                    "host": host,
                    "port": port,
                    "expected_allowed": expect_allow,
                    "decision": d.to_dict(),
                    "ok": d.allowed == expect_allow,
                }
            )
        # DNS rebinding simulation
        rebind = TrustedEgressBroker(
            allowed_destinations={"api.cursor.com"},
            resolve_fn=lambda h: ["10.0.0.5"],
            connect_fn=blocked_connect,
        )
        rebind_decision = rebind.evaluate_destination("api.cursor.com", 443)
        results.append(
            {
                "case": "dns_rebinding_private",
                "host": "api.cursor.com",
                "port": 443,
                "expected_allowed": False,
                "decision": rebind_decision.to_dict(),
                "ok": not rebind_decision.allowed,
            }
        )
        crashed = TrustedEgressBroker(
            allowed_destinations={"api.cursor.com"}, connect_fn=blocked_connect
        )
        crashed.mark_crashed()
        crash_decision = crashed.evaluate_destination("api.cursor.com", 443)
        results.append(
            {
                "case": "broker_interruption_fail_closed",
                "host": "api.cursor.com",
                "port": 443,
                "expected_allowed": False,
                "decision": crash_decision.to_dict(),
                "ok": not crash_decision.allowed,
            }
        )
        return {
            "action": "dry_run",
            "policy_id": self.policy_id,
            "cases": results,
            "all_ok": all(r["ok"] for r in results),
            "enforcement": "broker_destination_allowlist",
            "container_network": "none",
            "executed": False,
            "live_cursor_acp": False,
            "note": "Owner-gated runtime probe required for real container verification",
        }

    def start_unix_server(self, socket_path: Optional[str] = None) -> str:
        """Start UDS HTTP proxy server. Owner-operated; not used in CI tests."""
        path = socket_path or self.socket_path
        if not path:
            base = Path(tempfile.mkdtemp(prefix="eos-egress-"))
            path = str(base / "broker.sock")
        self.socket_path = path
        if Path(path).exists():
            Path(path).unlink()
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        broker = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self) -> None:  # type: ignore[override]
                broker._handle_client(self.rfile, self.wfile)

        class Server(socketserver.ThreadingUnixStreamServer):
            daemon_threads = True
            allow_reuse_address = True

        self._server = Server(path, Handler)
        os.chmod(path, 0o600)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return path

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self.socket_path and Path(self.socket_path).exists():
            try:
                Path(self.socket_path).unlink()
            except OSError:
                pass

    def _handle_client(self, rfile: Any, wfile: Any) -> None:
        with self._lock:
            if self._active >= self.max_connections:
                wfile.write(b"HTTP/1.1 503 Busy\r\n\r\n")
                return
            self._active += 1
        try:
            if self._crashed:
                wfile.write(b"HTTP/1.1 503 Broker Down\r\n\r\n")
                return
            line = rfile.readline().decode("utf-8", errors="replace").strip()
            if not line:
                return
            parts = line.split()
            if len(parts) < 2:
                wfile.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                return
            method, target = parts[0].upper(), parts[1]
            # Drain headers
            while True:
                hdr = rfile.readline()
                if not hdr or hdr in (b"\r\n", b"\n"):
                    break
            host = ""
            port = 443
            if method == "CONNECT":
                if ":" in target:
                    host, port_s = target.rsplit(":", 1)
                    port = int(port_s)
                else:
                    host, port = target, 443
            else:
                # Absolute-form forward proxy: GET http://host/path
                if "://" in target:
                    rest = target.split("://", 1)[1]
                    hostport = rest.split("/", 1)[0]
                    if ":" in hostport:
                        host, port_s = hostport.rsplit(":", 1)
                        port = int(port_s)
                    else:
                        host, port = hostport, (80 if method != "CONNECT" else 443)
                else:
                    wfile.write(b"HTTP/1.1 400 Absolute URL Required\r\n\r\n")
                    return
            decision = self.evaluate_destination(host, port)
            if not decision.allowed:
                wfile.write(
                    f"HTTP/1.1 403 Forbidden\r\nX-EOS-Deny: {decision.reason}\r\n\r\n".encode(
                        "utf-8"
                    )
                )
                return
            ok, reason = self.connect_fn(
                decision.host, decision.port, self.connect_timeout_seconds
            )
            if not ok:
                wfile.write(
                    f"HTTP/1.1 502 Bad Gateway\r\nX-EOS-Deny: {reason}\r\n\r\n".encode(
                        "utf-8"
                    )
                )
                return
            if method == "CONNECT":
                wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            else:
                wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        finally:
            with self._lock:
                self._active -= 1


def write_tcp_uds_relay_script(path: Path) -> Path:
    """Write a tiny stdlib TCP→UDS relay used inside --network=none containers."""
    path.parent.mkdir(parents=True, exist_ok=True)
    script = '''#!/usr/bin/env python3
"""EOS TCP→UDS relay: listen on 127.0.0.1:PORT, forward to UDS broker."""
from __future__ import annotations
import os, socket, select, sys, threading

UDS = os.environ.get("EOS_EGRESS_UDS", "/runtime/egress/broker.sock")
PORT = int(os.environ.get("EOS_EGRESS_RELAY_PORT", "18080"))

def pipe(a, b):
    try:
        while True:
            r, _, _ = select.select([a], [], [], 60)
            if not r:
                break
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except Exception:
        pass
    finally:
        try: a.close()
        except Exception: pass
        try: b.close()
        except Exception: pass

def handle(client):
    upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    upstream.connect(UDS)
    t1 = threading.Thread(target=pipe, args=(client, upstream), daemon=True)
    t2 = threading.Thread(target=pipe, args=(upstream, client), daemon=True)
    t1.start(); t2.start(); t1.join(); t2.join()

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT))
    srv.listen(32)
    if len(sys.argv) > 1:
        import subprocess
        threading.Thread(target=lambda: [handle(c) for c,_ in iter(srv.accept, None)], daemon=True).start()
        raise SystemExit(subprocess.call(sys.argv[1:]))
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()

if __name__ == "__main__":
    main()
'''
    path.write_text(script, encoding="utf-8")
    path.chmod(0o755)
    return path


def cursor_proxy_compatibility() -> Dict[str, Any]:
    """Deterministic diagnostics: do not assume HTTPS_PROXY covers all Cursor traffic."""
    return {
        "status": "NOT_TESTED",
        "evidence_class": UNAVAILABLE,
        "documented_auth": "CURSOR_API_KEY / --api-key",
        "documented_acp": "agent acp over stdio",
        "proxy_env_candidates": ["HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "ALL_PROXY"],
        "websocket_proxy_guaranteed": False,
        "assumption_forbidden": True,
        "live_blocked_until_owner_probe": True,
        "note": (
            "Cursor CLI may open HTTPS and WebSocket connections. "
            "Proxy env coverage is NOT assumed complete. Owner must run "
            "`eos network probe` with an uncredentialed disposable workload "
            "before live Cursor. If Cursor bypasses the broker, keep live BLOCKED."
        ),
        "fail_closed_on_bypass": True,
        "unrestricted_network_fallback_forbidden": True,
    }


def broker_podman_args(
    *,
    socket_host_path: str,
    relay_host_path: str,
    relay_port: int = 18080,
) -> Dict[str, Any]:
    """Argv fragments for Cursor/network-probe launches using network=none + UDS."""
    return {
        "network_args": ["--network", "none"],
        "mounts": [
            f"type=bind,src={socket_host_path},dst=/runtime/egress/broker.sock",
            f"type=bind,src={relay_host_path},dst=/runtime/egress/relay.py,ro",
        ],
        "env": {
            "EOS_EGRESS_UDS": "/runtime/egress/broker.sock",
            "EOS_EGRESS_RELAY_PORT": str(relay_port),
            "HTTP_PROXY": f"http://127.0.0.1:{relay_port}",
            "HTTPS_PROXY": f"http://127.0.0.1:{relay_port}",
            "ALL_PROXY": f"http://127.0.0.1:{relay_port}",
            "NO_PROXY": "",
        },
        "controls": {
            "network_none": True,
            "host_network": False,
            "direct_outbound": False,
            "broker_enforced": True,
            "http_proxy_alone_insufficient": True,
        },
    }
