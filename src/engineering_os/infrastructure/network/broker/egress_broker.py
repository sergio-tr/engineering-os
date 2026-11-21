"""Trusted host-side egress broker for rootless Podman + --network=none (EOS-11/12.1).

Design (compatible with Podman 3.4.4):
- Container has no direct outbound route (`--network=none`).
- Host runs an allowlisted HTTP CONNECT proxy on a Unix domain socket.
- A tiny TCP→UDS relay inside the container (loopback only) exposes HTTP_PROXY.
- Destination validation, DNS pin, IP-literal deny and private-range deny
  happen in the trusted broker — never by HTTP_PROXY alone.

CONNECT handling owns an upstream TCP socket and performs bounded bidirectional
forwarding. A 200 Connection Established response is never sent unless the
upstream connection was actually established to a broker-validated address.

This module does not open real network connections during automated tests when
`connect_fn` / `open_upstream_fn` is injected as blocked.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
import os
import select
import socket
import socketserver
import tempfile
import threading
import time

from engineering_os.domain.models import utc_now
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


# open_upstream returns (socket|None, reason). Ownership of a non-None socket
# transfers to the broker for CONNECT tunneling.
OpenUpstreamFn = Callable[..., Tuple[Optional[socket.socket], str]]
# Legacy alias: callables returning (bool, str) are adapted at construction.
ConnectFn = OpenUpstreamFn
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


def blocked_connect(
    host: str,
    port: int,
    timeout: float,
    resolved_addrs: Optional[List[str]] = None,
) -> Tuple[Optional[socket.socket], str]:
    """Offline/default connector — never opens sockets."""
    return None, "connect_disabled_in_offline_mode"


def live_open_upstream(
    host: str,
    port: int,
    timeout: float,
    resolved_addrs: Optional[List[str]] = None,
) -> Tuple[Optional[socket.socket], str]:
    """Open TCP to a broker-pinned address. Owner path only.

    Never performs a second DNS lookup. Requires non-empty resolved_addrs from
    the broker's validated resolve_fn result to prevent DNS rebinding races.
    """
    pinned = [a for a in (resolved_addrs or []) if a]
    if not pinned:
        return None, "no_pinned_addrs"
    last_err = "connect_failed"
    for addr in pinned:
        try:
            sock = socket.create_connection((addr, int(port)), timeout=timeout)
            return sock, f"connected:{addr}"
        except OSError as exc:
            last_err = f"connect_failed:{exc}"
    return None, last_err


def _adapt_connect_fn(fn: Callable[..., Any]) -> OpenUpstreamFn:
    """Accept legacy (bool, str) connectors and new socket-owning connectors."""

    def wrapper(
        host: str,
        port: int,
        timeout: float,
        resolved_addrs: Optional[List[str]] = None,
    ) -> Tuple[Optional[socket.socket], str]:
        try:
            result = fn(host, port, timeout, resolved_addrs)
        except TypeError:
            result = fn(host, port, timeout)
        if (
            isinstance(result, tuple)
            and len(result) == 2
            and isinstance(result[0], bool)
        ):
            ok, reason = result
            return (None, reason) if not ok else (None, "legacy_bool_connect_unsupported")
        return result  # type: ignore[return-value]

    return wrapper


def forward_bidirectional(
    left: socket.socket,
    right: socket.socket,
    *,
    deadline_seconds: float,
    max_bytes: int,
    chunk_size: int = 65536,
) -> Dict[str, Any]:
    """Bounded bidirectional byte relay until EOF, cancel, deadline or limit."""
    left.setblocking(False)
    right.setblocking(False)
    transferred = 0
    started = time.monotonic()
    reason = "ok"
    try:
        while True:
            if time.monotonic() - started >= deadline_seconds:
                reason = "deadline_exceeded"
                break
            if transferred >= max_bytes:
                reason = "byte_limit_exceeded"
                break
            readable, _, exceptional = select.select(
                [left, right], [], [left, right], 1.0
            )
            if exceptional:
                reason = "socket_exception"
                break
            if not readable:
                continue
            for src, dst in ((left, right), (right, left)):
                if src not in readable:
                    continue
                try:
                    data = src.recv(min(chunk_size, max_bytes - transferred))
                except BlockingIOError:
                    continue
                except OSError:
                    reason = "recv_error"
                    data = b""
                if not data:
                    reason = "peer_closed"
                    return {
                        "bytes": transferred,
                        "reason": reason,
                        "elapsed_seconds": round(time.monotonic() - started, 4),
                    }
                try:
                    dst.sendall(data)
                except OSError:
                    reason = "send_error"
                    return {
                        "bytes": transferred,
                        "reason": reason,
                        "elapsed_seconds": round(time.monotonic() - started, 4),
                    }
                transferred += len(data)
    finally:
        for sock in (left, right):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
    return {
        "bytes": transferred,
        "reason": reason,
        "elapsed_seconds": round(time.monotonic() - started, 4),
    }


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
    """Allowlist HTTP CONNECT proxy policy engine + optional UDS server."""

    policy_id = "uds-broker-network-none"

    def __init__(
        self,
        *,
        allowed_destinations: Optional[Set[str]] = None,
        allowed_ports: Optional[Set[int]] = None,
        resolve_fn: Optional[ResolveFn] = None,
        connect_fn: Optional[Callable[..., Any]] = None,
        open_upstream_fn: Optional[OpenUpstreamFn] = None,
        connect_timeout_seconds: float = 10.0,
        tunnel_deadline_seconds: float = 30.0,
        max_tunnel_bytes: int = 4 * 1024 * 1024,
        max_connections: int = 32,
        socket_path: Optional[str] = None,
    ) -> None:
        self.allowed = {
            d.lower() for d in (allowed_destinations or DEFAULT_CURSOR_DESTINATIONS)
        }
        self.allowed_ports = set(allowed_ports or {443, 80})
        self.resolve_fn = resolve_fn  # None => do not resolve in evaluate-only path
        raw = open_upstream_fn or connect_fn or blocked_connect
        self.connect_fn = _adapt_connect_fn(raw)
        self.open_upstream_fn = self.connect_fn
        self.connect_timeout_seconds = connect_timeout_seconds
        self.tunnel_deadline_seconds = tunnel_deadline_seconds
        self.max_tunnel_bytes = max_tunnel_bytes
        self.max_connections = max_connections
        self.socket_path = socket_path
        self._observations: List[Dict[str, Any]] = []
        self._tunnel_stats: List[Dict[str, Any]] = []
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
            "tunnel_deadline_seconds": self.tunnel_deadline_seconds,
            "max_tunnel_bytes": self.max_tunnel_bytes,
            "ip_literal_bypass_denied": True,
            "private_host_interface_denied": True,
            "dns_controlled_by_broker": True,
            "connect_200_requires_upstream": True,
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

    def tunnel_stats(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._tunnel_stats)

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
                    "layer": "policy",
                }
            )
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
                "layer": "policy",
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
                "layer": "policy",
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
            "verification_level": "POLICY_VALIDATED" if all(r["ok"] for r in results) else "FAILED",
            "note": "Owner-gated runtime probe required for real container verification",
        }

    def start_unix_server(self, socket_path: Optional[str] = None) -> str:
        """Start UDS HTTP CONNECT proxy server. Owner-operated; not used in CI tests."""
        path = socket_path or self.socket_path
        if not path:
            base = Path(tempfile.mkdtemp(prefix="eos-egress-"))
            path = str(base / "broker.sock")
        self.socket_path = path
        if Path(path).exists():
            Path(path).unlink()
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        broker = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:  # type: ignore[override]
                # Raw sockets only — buffered StreamRequestHandler would hide
                # post-CONNECT bytes from the bidirectional tunnel.
                broker._handle_client(self.request)

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

    @staticmethod
    def _recv_line(sock: socket.socket, *, limit: int = 65536) -> bytes:
        buf = bytearray()
        while len(buf) < limit:
            chunk = sock.recv(1)
            if not chunk:
                break
            buf.extend(chunk)
            if buf.endswith(b"\n"):
                break
        return bytes(buf)

    def _handle_client(self, client_sock: socket.socket) -> None:
        upstream: Optional[socket.socket] = None

        def reply(payload: bytes) -> None:
            client_sock.sendall(payload)

        with self._lock:
            if self._active >= self.max_connections:
                reply(b"HTTP/1.1 503 Busy\r\n\r\n")
                return
            self._active += 1
        try:
            if self._crashed:
                reply(b"HTTP/1.1 503 Broker Down\r\n\r\n")
                return
            line = self._recv_line(client_sock).decode("utf-8", errors="replace").strip()
            if not line:
                return
            parts = line.split()
            if len(parts) < 2:
                reply(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                return
            method, target = parts[0].upper(), parts[1]
            # Drain headers (raw) so the tunnel owns the socket cleanly.
            while True:
                hdr = self._recv_line(client_sock)
                if not hdr or hdr in (b"\r\n", b"\n"):
                    break

            # Fail closed: only CONNECT tunnels are supported for HTTPS egress.
            if method != "CONNECT":
                reply(
                    b"HTTP/1.1 405 Method Not Allowed\r\n"
                    b"Allow: CONNECT\r\n"
                    b"X-EOS-Deny: unsupported_proxy_method\r\n\r\n"
                )
                return

            host = ""
            port = 443
            if ":" in target:
                host, port_s = target.rsplit(":", 1)
                try:
                    port = int(port_s)
                except ValueError:
                    reply(b"HTTP/1.1 400 Bad Port\r\n\r\n")
                    return
            else:
                host, port = target, 443

            decision = self.evaluate_destination(host, port)
            if not decision.allowed:
                reply(
                    f"HTTP/1.1 403 Forbidden\r\nX-EOS-Deny: {decision.reason}\r\n\r\n".encode(
                        "utf-8"
                    )
                )
                return

            upstream, reason = self.open_upstream_fn(
                decision.host,
                decision.port,
                self.connect_timeout_seconds,
                decision.resolved_addrs,
            )
            if upstream is None:
                reply(
                    f"HTTP/1.1 502 Bad Gateway\r\nX-EOS-Deny: {reason}\r\n\r\n".encode(
                        "utf-8"
                    )
                )
                return

            # Never advertise CONNECT success without a live upstream socket.
            reply(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            stats = forward_bidirectional(
                client_sock,
                upstream,
                deadline_seconds=self.tunnel_deadline_seconds,
                max_bytes=self.max_tunnel_bytes,
            )
            upstream = None  # closed inside forward_bidirectional
            with self._lock:
                self._tunnel_stats.append(
                    {
                        "host": decision.host,
                        "port": decision.port,
                        "pinned_addrs": list(decision.resolved_addrs),
                        **stats,
                        "observed_at": utc_now(),
                    }
                )
        finally:
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass
            with self._lock:
                self._active -= 1


def write_tcp_uds_relay_script(path: Path) -> Path:
    """Write TCP→UDS relay used inside --network=none containers.

    Requires python3 in the selected image. The workload preflight fails closed
    with EOS_RELAY_MISSING_RUNTIME when python3 is absent.
    """
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
    container_uid: Optional[int] = None,
    container_gid: Optional[int] = None,
) -> Dict[str, Any]:
    """Argv fragments for Cursor/network-probe launches using network=none + UDS."""
    uid = os.getuid() if container_uid is None else container_uid
    gid = os.getgid() if container_gid is None else container_gid
    return {
        "network_args": ["--network", "none"],
        "user_args": ["--userns=keep-id", "--user", f"{uid}:{gid}"],
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
            "socket_mode": "0600",
            "container_identity": f"{uid}:{gid}",
            "world_writable_socket_forbidden": True,
        },
        "prerequisites": {
            "image_must_provide": ["python3", "wget_or_busybox_wget"],
            "loopback_required_under_network_none": True,
            "relay_runtime": "python3",
        },
    }
