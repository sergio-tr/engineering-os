"""Explicit HTTPS-through-CONNECT transport probe (EOS-12.2).

Uses stdlib socket/ssl/HTTP only. Stages are recorded as structured events.
HTTP application errors (401/403/404) after verified TLS demonstrate transport
success without claiming application success.

This module is imported by host-side tests and copied into the probe container.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
import errno
import re
import socket
import ssl
import time


# Stable stage / event codes for container + host correlation.
STAGE_RELAY_PROCESS_STARTED = "RELAY_PROCESS_STARTED"
STAGE_RELAY_TCP_LISTENING = "RELAY_TCP_LISTENING"
STAGE_RELAY_TCP_CONNECTED = "RELAY_TCP_CONNECTED"
STAGE_UDS_BROKER_REACHABLE = "UDS_BROKER_REACHABLE"
STAGE_CONNECT_SENT = "CONNECT_SENT"
STAGE_CONNECT_RESPONSE = "CONNECT_RESPONSE"
STAGE_DESTINATION_POLICY = "DESTINATION_POLICY"
STAGE_DNS_RESULT = "DNS_RESULT"
STAGE_UPSTREAM_SOCKET = "UPSTREAM_SOCKET"
STAGE_CONNECT_200 = "CONNECT_200"
STAGE_TLS_STARTED = "TLS_STARTED"
STAGE_TLS_COMPLETED = "TLS_COMPLETED"
STAGE_CERT_VALIDATED = "CERT_VALIDATED"
STAGE_HTTP_SENT = "HTTP_SENT"
STAGE_HTTP_RESPONSE = "HTTP_RESPONSE"
STAGE_TRANSPORT_CLOSED = "TRANSPORT_CLOSED"
STAGE_CLEANUP = "CLEANUP"

FAILURE_RELAY_NOT_READY = "relay_not_ready"
FAILURE_CONNECT_DENIED = "connect_denied"
FAILURE_CONNECT_BAD_GATEWAY = "connect_bad_gateway"
FAILURE_CONNECT_UNEXPECTED = "connect_unexpected_status"
FAILURE_BROKER_REQUEST_ID = "invalid_broker_request_id"
FAILURE_TLS = "tls_handshake_failed"
FAILURE_CERT = "certificate_validation_failed"
FAILURE_HTTP = "http_exchange_failed"
FAILURE_TIMEOUT = "timeout"
FAILURE_SOCKET = "socket_error"


def _now() -> float:
    return time.time()


@dataclass
class StageEvent:
    code: str
    ok: bool
    detail: str = ""
    ts: float = field(default_factory=_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "ok": self.ok,
            "detail": self.detail[:240],
            "ts": self.ts,
        }


@dataclass
class TransportProbeResult:
    request_id: str
    host: str
    port: int
    events: List[StageEvent] = field(default_factory=list)
    connect_status: Optional[int] = None
    deny_reason: Optional[str] = None
    http_status: Optional[int] = None
    tls_ok: bool = False
    cert_ok: bool = False
    transport_verified: bool = False
    failure_stage: Optional[str] = None
    failure_code: Optional[str] = None
    broker_request_id: Optional[str] = None

    def record(self, code: str, ok: bool, detail: str = "") -> None:
        self.events.append(StageEvent(code=code, ok=ok, detail=detail))
        if not ok and self.failure_stage is None:
            self.failure_stage = code
            self.failure_code = detail or code

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "broker_request_id": self.broker_request_id,
            "host": self.host,
            "port": self.port,
            "events": [e.to_dict() for e in self.events],
            "connect_status": self.connect_status,
            "deny_reason": self.deny_reason,
            "http_status": self.http_status,
            "tls_ok": self.tls_ok,
            "cert_ok": self.cert_ok,
            "transport_verified": self.transport_verified,
            "failure_stage": self.failure_stage,
            "failure_code": self.failure_code,
        }


def classify_os_error(exc: BaseException) -> str:
    """Map OSError to a stable diagnostic code."""
    if isinstance(exc, TimeoutError):
        return "timeout"
    if not isinstance(exc, OSError):
        return f"error:{type(exc).__name__}"
    err = exc.errno
    mapping = {
        errno.ECONNREFUSED: "connection_refused",
        errno.ENETUNREACH: "network_unreachable",
        errno.EHOSTUNREACH: "host_unreachable",
        errno.ETIMEDOUT: "timeout",
        errno.ECONNRESET: "connection_reset",
        errno.EPIPE: "broken_pipe",
        errno.EACCES: "permission_denied",
    }
    if err in mapping:
        return mapping[err]
    # Windows / platform-specific timeout often uses WSAETIMEDOUT etc.
    name = errno.errorcode.get(err or -1, "")
    if "TIMEDOUT" in name or "TIMEOUT" in name:
        return "timeout"
    return f"os_error:{err}:{type(exc).__name__}"


def wait_tcp_ready(
    host: str,
    port: int,
    *,
    deadline_seconds: float = 5.0,
    interval_seconds: float = 0.05,
) -> Tuple[bool, str]:
    """Bounded poll until TCP accept is possible on host:port."""
    deadline = time.monotonic() + deadline_seconds
    last = "not_attempted"
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True, "listening"
        except OSError as exc:
            last = classify_os_error(exc)
            time.sleep(interval_seconds)
    return False, f"not_ready:{last}"


def _recv_until(
    sock: socket.socket, marker: bytes, *, limit: int = 65536, initial: bytes = b""
) -> bytes:
    buf = bytearray(initial)
    while marker not in buf and len(buf) < limit:
        chunk = sock.recv(min(4096, limit - len(buf)))
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def valid_broker_request_id(value: object) -> bool:
    # IDs issued by new_id("breq") in the trusted broker.
    return isinstance(value, str) and re.fullmatch(r"breq-[0-9a-f]{12}", value) is not None


def _parse_http_head(header_blob: bytes) -> Tuple[Optional[int], Dict[str, str]]:
    head, marker, _ = header_blob.partition(b"\r\n\r\n")
    if not marker:
        return None, {}
    lines = head.split(b"\r\n")
    status_line = re.fullmatch(
        rb"HTTP/1\.[01] ([1-5][0-9]{2}) [\t\x20-\x7e\x80-\xff]*", lines[0]
    )
    if status_line is None:
        return None, {}
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        field = re.fullmatch(
            rb"([!#$%&'*+.^_`|~0-9A-Za-z-]+):([\t\x20-\x7e\x80-\xff]*)", line
        )
        if field is None:
            return None, {}
        name = field[1].decode("ascii").lower()
        if name in {"x-eos-request-id", "x-eos-deny"} and name in headers:
            return None, {}
        headers[name] = field[2].decode("iso-8859-1").strip(" \t")
    return int(status_line[1]), headers


def _read_final_http_status(sock: ssl.SSLSocket) -> Optional[int]:
    marker = b"\r\n\r\n"
    remaining = 65536
    pending = b""
    while remaining > 0:
        response = _recv_until(sock, marker, limit=remaining, initial=pending)
        status, _ = _parse_http_head(response)
        if status is None or status == 101:
            return None
        if status >= 200:
            return status
        _, _, pending = response.partition(marker)
        remaining -= len(response) - len(pending)
    return None


def https_connect_probe(
    *,
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 18080,
    target_host: str = "api.cursor.com",
    target_port: int = 443,
    request_id: str,
    timeout: float = 10.0,
    http_path: str = "/",
    expect_allow: bool = True,
) -> TransportProbeResult:
    """Explicit CONNECT → TLS → minimal GET using stdlib only."""
    result = TransportProbeResult(
        request_id=request_id, host=target_host, port=target_port
    )
    raw: Optional[socket.socket] = None
    tls_sock: Optional[ssl.SSLSocket] = None
    try:
        try:
            raw = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
            result.record(STAGE_RELAY_TCP_CONNECTED, True, f"{proxy_host}:{proxy_port}")
        except OSError as exc:
            result.record(
                STAGE_RELAY_TCP_CONNECTED, False, classify_os_error(exc)
            )
            result.failure_code = FAILURE_RELAY_NOT_READY
            return result

        connect_req = (
            f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
            f"Host: {target_host}:{target_port}\r\n"
            f"X-EOS-Request-Id: {request_id}\r\n"
            f"Proxy-Connection: keep-alive\r\n"
            f"\r\n"
        ).encode("ascii")
        raw.sendall(connect_req)
        result.record(STAGE_CONNECT_SENT, True, f"{target_host}:{target_port}")

        header_blob = _recv_until(raw, b"\r\n\r\n")
        status, headers = _parse_http_head(header_blob)
        result.connect_status = status
        broker_request_id = headers.get("x-eos-request-id")
        if valid_broker_request_id(broker_request_id):
            result.broker_request_id = broker_request_id
        deny = headers.get("x-eos-deny")
        result.deny_reason = deny
        result.record(
            STAGE_CONNECT_RESPONSE,
            status is not None,
            f"status={status};deny={deny or ''}",
        )

        if status == 403:
            result.record(STAGE_DESTINATION_POLICY, False, deny or "forbidden")
            result.failure_code = FAILURE_CONNECT_DENIED
            return result
        if status == 502:
            result.record(STAGE_UPSTREAM_SOCKET, False, deny or "bad_gateway")
            result.failure_code = FAILURE_CONNECT_BAD_GATEWAY
            return result
        if status != 200:
            result.record(
                STAGE_CONNECT_200,
                False,
                f"unexpected_status:{status}",
            )
            result.failure_code = FAILURE_CONNECT_UNEXPECTED
            return result

        result.record(STAGE_CONNECT_200, True, "connection_established")
        result.record(STAGE_DESTINATION_POLICY, True, "allowed")

        if not expect_allow:
            # Caller expected deny but got 200 — treat as leak signal upstream.
            result.failure_code = "unexpected_allow"
            return result

        if deny is not None:
            result.record(STAGE_CONNECT_RESPONSE, False, FAILURE_CONNECT_UNEXPECTED)
            return result
        if result.broker_request_id is None or result.broker_request_id == request_id:
            result.record(STAGE_CONNECT_RESPONSE, False, FAILURE_BROKER_REQUEST_ID)
            return result

        result.record(STAGE_TLS_STARTED, True, "ssl_wrap")
        ctx = ssl.create_default_context()
        try:
            tls_sock = ctx.wrap_socket(raw, server_hostname=target_host)
            raw = None  # ownership transferred
            result.tls_ok = True
            result.cert_ok = True
            result.record(STAGE_TLS_COMPLETED, True, "handshake_ok")
            result.record(STAGE_CERT_VALIDATED, True, f"hostname={target_host}")
        except ssl.SSLCertVerificationError as exc:
            result.record(STAGE_CERT_VALIDATED, False, type(exc).__name__)
            result.failure_code = FAILURE_CERT
            return result
        except ssl.SSLError as exc:
            result.record(STAGE_TLS_COMPLETED, False, type(exc).__name__)
            result.failure_code = FAILURE_TLS
            return result

        http_req = (
            f"GET {http_path} HTTP/1.1\r\n"
            f"Host: {target_host}\r\n"
            f"User-Agent: eos-network-probe/12.2\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("ascii")
        assert tls_sock is not None
        tls_sock.settimeout(timeout)
        tls_sock.sendall(http_req)
        result.record(STAGE_HTTP_SENT, True, f"GET {http_path}")

        http_status = _read_final_http_status(tls_sock)
        result.http_status = http_status
        if http_status is None:
            result.record(STAGE_HTTP_RESPONSE, False, "invalid_final_response")
            result.failure_code = FAILURE_HTTP
            return result
        result.record(STAGE_HTTP_RESPONSE, True, f"status={http_status}")
        # Any syntactically valid HTTPS response after verified TLS = transport OK.
        result.transport_verified = True
        result.failure_stage = None
        result.failure_code = None
        return result
    except OSError as exc:
        code = classify_os_error(exc)
        result.record(STAGE_TRANSPORT_CLOSED, False, code)
        result.failure_code = FAILURE_TIMEOUT if code == "timeout" else FAILURE_SOCKET
        return result
    finally:
        for sock in (tls_sock, raw):
            if sock is None:
                continue
            try:
                sock.close()
            except OSError:
                pass
        result.record(STAGE_TRANSPORT_CLOSED, True, "closed")


def format_probe_lines(result: TransportProbeResult, *, case: str) -> List[str]:
    """Emit PROBE_EVENT / PROBE_RESULT lines for the container workload."""
    lines: List[str] = []
    for ev in result.events:
        outcome = "ok" if ev.ok else "fail"
        detail = (ev.detail or "-").replace(" ", "_")[:120]
        lines.append(
            f"PROBE_EVENT {case} {ev.code} {outcome} {detail} {result.request_id}"
        )
    if result.transport_verified:
        lines.append(
            f"PROBE_RESULT {case} ok http_{result.http_status} {result.request_id}"
        )
    elif result.connect_status == 403:
        lines.append(
            f"PROBE_RESULT {case} denied {result.deny_reason or 'forbidden'} {result.request_id}"
        )
    else:
        stage = result.failure_stage or "unknown"
        code = result.failure_code or "failed"
        lines.append(
            f"PROBE_RESULT {case} failed {stage}:{code} {result.request_id}"
        )
    if result.http_status is not None:
        lines.append(
            f"PROBE_HTTP {case} {result.http_status} {result.request_id}"
        )
    return lines
