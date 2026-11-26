"""Owner-gated network enforcement probe using disposable Podman + UDS broker.

Automated tests inject a process factory and never start containers or open
real network connections. Owner `--execute` path constructs real argv and may
start containers only when explicitly gated upstream.

EOS-12.1: evidence-backed results — attempted connections and incomplete
output must never produce COMPLETED / ENFORCEMENT_VERIFIED.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple
import json
import os
import re
import subprocess
import tempfile

from engineering_os.domain.models import new_id, utc_now
from engineering_os.infrastructure.network.broker.broker_runtime import (
    BrokerRuntime,
    cursor_proxy_env,
    live_open_upstream,
    proxy_compatibility_matrix,
)
from engineering_os.infrastructure.network.broker.egress_broker import (
    EVT_CONNECT_RECEIVED,
    EVT_DESTINATION_ALLOWED,
    EVT_DNS_RESOLVED,
    EVT_TUNNEL_BYTES_TRANSFERRED,
    EVT_TUNNEL_CLOSED,
    EVT_TUNNEL_ESTABLISHED,
    EVT_UPSTREAM_CONNECTED,
    EVT_UPSTREAM_CONNECT_STARTED,
    blocked_connect,
    default_resolve,
)
from engineering_os.infrastructure.evidence import (
    ERROR,
    SYNTHETIC,
    SYNTHETIC_IN_MEMORY,
    SYNTHETIC_OCI_EXECUTED,
)
from engineering_os.infrastructure.runtime.oci.oci_process import (
    InjectedFixtureProcess,
    OciProcessHandle,
    SubprocessOciHandle,
)
from engineering_os.infrastructure.network.probe.probe_image import (
    ProbeImageError,
    ProbeImageIdentity,
    probe_image_selection_note,
    resolve_probe_image,
    synthetic_probe_image,
    validate_probe_image_ref,
)
from engineering_os.infrastructure.network.probe.probe_transport import (
    STAGE_CERT_VALIDATED,
    STAGE_CONNECT_200,
    STAGE_HTTP_RESPONSE,
    STAGE_HTTP_SENT,
    STAGE_TLS_COMPLETED,
    valid_broker_request_id,
)
from engineering_os.infrastructure.runtime.oci.podman_executor import (
    require_owner_execution_gates,
    sha256_text,
)
from engineering_os.infrastructure.runtime.sandbox.sandbox_launcher import scan_argv_for_bypass


ProbeFactory = Callable[["NetworkProbeRequest"], OciProcessHandle]

# Policy-layer cases evaluated on the broker without requiring container I/O.
POLICY_CASES = (
    ("allowed_public", "api.cursor.com", 443, True),
    ("unapproved_public", "evil.example", 443, False),
    ("direct_ip", "1.2.3.4", 443, False),
    ("private_address", "10.0.0.1", 443, False),
    ("link_local_metadata", "169.254.169.254", 80, False),
    ("ipv6_loopback", "::1", 443, False),
)

# Container observations required for ENFORCEMENT_VERIFIED.
# Values are accepted outcome tokens for PROBE_RESULT <case> <outcome> ...
REQUIRED_CONTAINER_OBSERVATIONS: Dict[str, Set[str]] = {
    "allowed_public": {"ok"},
    "unapproved_public": {"denied"},
    "direct_external": {"denied"},
    "private_address": {"denied"},
    "ip_literal": {"denied"},
}

FALSE_POSITIVE_OUTCOMES = {"attempted", "skipped", "missing", "error", "LEAK"}
ALLOWED_SUMMARY_FIELDS = {
    "relay_ready",
    "connect_status",
    "tls_ok",
    "cert_ok",
    "http_status",
    "transport_verified",
    "failure_stage",
    "failure_code",
    "request_id",
    "broker_request_id",
}


@dataclass
class NetworkProbeRequest:
    execution_id: str
    project_id: str
    image_ref: str
    correlation_id: str = ""


@dataclass
class NetworkProbeResult:
    run_id: str
    executed: bool
    dry_run: bool
    cases: List[Dict[str, Any]]
    broker: Dict[str, Any]
    argv: List[str]
    container_id: Optional[str]
    cleanup: Dict[str, Any]
    evidence_refs: List[str]
    evidence_hashes: Dict[str, str]
    provenance: str
    status: str
    failure_reason: Optional[str]
    proxy_compatibility: Dict[str, Any]
    verification_level: str = "NOT_TESTED"
    policy_validated: bool = False
    transport_verified: bool = False
    enforcement_verified: bool = False
    container_observations: Dict[str, str] = field(default_factory=dict)
    prerequisites: Dict[str, Any] = field(default_factory=dict)
    image_identity: Dict[str, Any] = field(default_factory=dict)
    allowed_path: Dict[str, Any] = field(default_factory=dict)
    denied_paths: List[Dict[str, Any]] = field(default_factory=list)
    tunnel_events: List[Dict[str, Any]] = field(default_factory=list)
    probe_events: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "executed": self.executed,
            "dry_run": self.dry_run,
            "cases": list(self.cases),
            "broker": dict(self.broker),
            "argv": list(self.argv),
            "container_id": self.container_id,
            "cleanup": dict(self.cleanup),
            "evidence_refs": list(self.evidence_refs),
            "evidence_hashes": dict(self.evidence_hashes),
            "provenance": self.provenance,
            "status": self.status,
            "failure_reason": self.failure_reason,
            "proxy_compatibility": dict(self.proxy_compatibility),
            "verification_level": self.verification_level,
            "POLICY_VALIDATED": self.policy_validated,
            "TRANSPORT_VERIFIED": self.transport_verified,
            "ENFORCEMENT_VERIFIED": self.enforcement_verified,
            "container_observations": dict(self.container_observations),
            "prerequisites": dict(self.prerequisites),
            "image_identity": dict(self.image_identity),
            "allowed_path": dict(self.allowed_path),
            "denied_paths": list(self.denied_paths),
            "tunnel_events": list(self.tunnel_events),
            "probe_events": list(self.probe_events),
            "live_cursor_acp": False,
        }


def probe_prerequisites(
    *,
    image_ref: str,
    container_uid: int,
    container_gid: int,
    image_identity: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Dry-run / Owner preflight facts — no containers started here."""
    return {
        "image_ref": image_ref or None,
        "image_identity": dict(image_identity or {}),
        "image_must_provide": ["python3"],
        "relay_runtime": "python3",
        "workload_runtime": "python3_stdlib",
        "optional_binaries_forbidden_as_requirement": ["wget", "nc"],
        "socket_mode": "0600",
        "container_user": f"{container_uid}:{container_gid}",
        "userns": "keep-id",
        "network": "none",
        "loopback_required": True,
        "world_writable_socket_forbidden": True,
        "privileged_container_forbidden": True,
        "host_network_forbidden": True,
        "fixture_alpine_resolver_forbidden": True,
        "implicit_pull_forbidden": True,
        "note": probe_image_selection_note(),
    }


def write_probe_workload_script(path: Path) -> Path:
    """EOS-12.2 workload: staged CONNECT/TLS probe + broker-correlated denials."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix == ".sh":
        path = path.with_suffix(".py")
    script = r'''#!/usr/bin/env python3
"""EOS-12.2 network probe workload — staged HTTPS-through-CONNECT diagnostics."""
from __future__ import annotations
import os
import socket
import subprocess
import sys
import time
import uuid

sys.path.insert(0, "/probe")
from transport import (  # type: ignore  # noqa: E402
    STAGE_RELAY_PROCESS_STARTED,
    STAGE_RELAY_TCP_LISTENING,
    STAGE_UDS_BROKER_REACHABLE,
    classify_os_error,
    format_probe_lines,
    https_connect_probe,
    wait_tcp_ready,
)

RELAY = "/runtime/egress/relay.py"
UDS = os.environ.get("EOS_EGRESS_UDS", "/runtime/egress/broker.sock")
PORT = int(os.environ.get("EOS_EGRESS_RELAY_PORT", "18080"))


def emit(line: str) -> None:
    print(line, flush=True)


def report(case: str, outcome: str, detail: str, req: str = "-") -> None:
    emit(f"PROBE_RESULT {case} {outcome} {detail} {req}")


def event(case: str, code: str, ok: bool, detail: str, req: str = "-") -> None:
    emit(f"PROBE_EVENT {case} {code} {'ok' if ok else 'fail'} {(detail or '-')[:120]} {req}")


def main() -> int:
    if not os.path.isfile(RELAY):
        report("relay_script", "missing", "path")
        emit("PROBE_DONE")
        return 1
    if not os.path.isfile("/probe/transport.py"):
        report("transport_module", "missing", "path")
        emit("PROBE_DONE")
        return 1

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        s.close()
        event("relay", "LOOPBACK_OK", True, "127.0.0.1")
    except OSError as exc:
        report("loopback", "failed", classify_os_error(exc))
        emit("PROBE_DONE")
        return 1

    # UDS must exist and be connectable from this UID before starting the relay.
    try:
        us = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        us.settimeout(2.0)
        us.connect(UDS)
        us.close()
        event("relay", STAGE_UDS_BROKER_REACHABLE, True, UDS)
    except OSError as exc:
        event("relay", STAGE_UDS_BROKER_REACHABLE, False, classify_os_error(exc))
        report("relay_runtime", "failed", f"uds:{classify_os_error(exc)}")
        emit("PROBE_DONE")
        return 1

    relay_proc = subprocess.Popen(
        [sys.executable, RELAY],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    event("relay", STAGE_RELAY_PROCESS_STARTED, True, f"pid={relay_proc.pid}")

    ready = False
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if relay_proc.poll() is not None:
            event("relay", STAGE_RELAY_TCP_LISTENING, False, "relay_exited")
            report("relay_start", "failed", f"exit_{relay_proc.returncode}")
            emit("PROBE_DONE")
            return 1
        line = ""
        if relay_proc.stdout is not None:
            # Non-blocking-ish: short select via timeout on readline is not available;
            # fall through to TCP poll which is the authoritative readiness signal.
            pass
        ok, detail = wait_tcp_ready("127.0.0.1", PORT, deadline_seconds=0.2)
        if ok:
            ready = True
            event("relay", STAGE_RELAY_TCP_LISTENING, True, detail)
            break
        time.sleep(0.05)

    if not ready:
        event("relay", STAGE_RELAY_TCP_LISTENING, False, "deadline")
        report("relay_start", "failed", "not_ready")
        relay_proc.kill()
        emit("PROBE_DONE")
        return 1

    # --- Allowed path: explicit CONNECT → TLS → GET ---
    req_allow = f"req-allow-{uuid.uuid4().hex[:12]}"
    allowed = https_connect_probe(
        proxy_host="127.0.0.1",
        proxy_port=PORT,
        target_host="api.cursor.com",
        target_port=443,
        request_id=req_allow,
        timeout=12.0,
        expect_allow=True,
    )
    for line in format_probe_lines(allowed, case="allowed_public"):
        emit(line)
    emit(
        "PROBE_ALLOWED_PATH "
        f"relay_ready=true "
        f"connect_status={allowed.connect_status} "
        f"tls_ok={allowed.tls_ok} "
        f"cert_ok={allowed.cert_ok} "
        f"http_status={allowed.http_status} "
        f"transport_verified={allowed.transport_verified} "
        f"failure_stage={allowed.failure_stage or '-'} "
        f"failure_code={allowed.failure_code or '-'} "
        f"request_id={allowed.request_id} "
        f"broker_request_id={allowed.broker_request_id or '-'}"
    )

    # --- Denied destinations: require CONNECT 403 + deny reason ---
    denied_cases = (
        ("unapproved_public", "evil.example", 443, "destination_not_allowlisted"),
        ("private_address", "10.0.0.1", 443, "ip_literal_bypass_denied"),
        ("ip_literal", "1.2.3.4", 443, "ip_literal_bypass_denied"),
    )
    for case, host, port, expected_reason_substr in denied_cases:
        req = f"req-{case}-{uuid.uuid4().hex[:8]}"
        result = https_connect_probe(
            proxy_host="127.0.0.1",
            proxy_port=PORT,
            target_host=host,
            target_port=port,
            request_id=req,
            timeout=8.0,
            expect_allow=False,
        )
        for line in format_probe_lines(result, case=case):
            emit(line)
        if result.connect_status == 403 and result.deny_reason:
            if expected_reason_substr in (result.deny_reason or ""):
                report(case, "denied", result.deny_reason, req)
            else:
                report(case, "failed", f"unexpected_deny:{result.deny_reason}", req)
        elif result.connect_status == 200:
            report(case, "LEAK", "connect_200", req)
        else:
            # Do not treat relay/connectivity failures as enforcement denials.
            report(
                case,
                "failed",
                f"no_broker_deny:status={result.connect_status}:{result.failure_code}",
                req,
            )

    # Direct external — no proxy; capture concrete network error.
    try:
        socket.create_connection(("1.1.1.1", 443), 2.0).close()
        report("direct_external", "LEAK", "route_exists")
    except OSError as exc:
        code = classify_os_error(exc)
        report("direct_external", "denied", f"no_proxy:{code}")
        event("direct_external", "DIRECT_CONNECT_BLOCKED", True, code)

    relay_proc.terminate()
    try:
        relay_proc.wait(timeout=2)
    except Exception:
        relay_proc.kill()
    event("relay", "CLEANUP", True, "relay_stopped")
    emit("PROBE_DONE")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        report("workload", "error", type(exc).__name__)
        emit("PROBE_DONE")
        raise SystemExit(1)
'''
    path.write_text(script, encoding="utf-8")
    path.chmod(0o755)
    return path


def write_probe_transport_module(path: Path) -> Path:
    """Copy probe_transport.py into the execution work dir for container mount."""
    import shutil

    src = Path(__file__).with_name("probe_transport.py")
    path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, path)
    path.chmod(0o644)
    return path


def build_probe_podman_argv(
    *,
    image_ref: str,
    container_name: str,
    socket_host_path: str,
    relay_host_path: str,
    workload_host_path: str,
    transport_host_path: str,
    memory_limit: str = "128m",
    cpu_limit: str = "0.25",
    pids_limit: int = 32,
    container_uid: Optional[int] = None,
    container_gid: Optional[int] = None,
) -> List[str]:
    if not re.fullmatch(r"eos-netprobe-[A-Za-z0-9._-]{4,80}", container_name):
        raise RuntimeError("invalid_probe_container_name")
    for p in (socket_host_path, relay_host_path, workload_host_path, transport_host_path):
        if not Path(p).exists():
            raise RuntimeError(f"probe_path_missing:{p}")
    uid = os.getuid() if container_uid is None else container_uid
    gid = os.getgid() if container_gid is None else container_gid
    env = cursor_proxy_env()
    argv = [
        "podman",
        "run",
        "-i",
        "--pull=never",
        "--read-only",
        "--network",
        "none",
        "--userns=keep-id",
        "--user",
        f"{uid}:{gid}",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--memory",
        memory_limit,
        "--cpus",
        cpu_limit,
        "--pids-limit",
        str(pids_limit),
        "--tmpfs",
        "/runtime/tmp:rw,noexec,nosuid,size=16m",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=16m",
        "--mount",
        f"type=bind,src={socket_host_path},dst=/runtime/egress/broker.sock",
        "--mount",
        f"type=bind,src={relay_host_path},dst=/runtime/egress/relay.py,ro",
        "--mount",
        f"type=bind,src={workload_host_path},dst=/probe/run.py,ro",
        "--mount",
        f"type=bind,src={transport_host_path},dst=/probe/transport.py,ro",
        "--workdir",
        "/tmp",
        "--name",
        container_name,
    ]
    for key, value in env.items():
        argv.extend(["-e", f"{key}={value}"])
    argv.extend([image_ref, "python3", "/probe/run.py"])
    bypass = scan_argv_for_bypass(argv)
    if bypass:
        raise RuntimeError(f"argv_bypass:{','.join(bypass)}")
    joined = " ".join(argv)
    if "CURSOR_API_KEY=" in joined or "sk-" in joined:
        raise RuntimeError("secret_in_probe_argv")
    if "docker.sock" in joined or "podman.sock" in joined:
        raise RuntimeError("runtime_socket_mount_forbidden")
    if "65534:65534" in joined and uid != 65534:
        raise RuntimeError("nobody_uid_incompatible_with_socket_0600")
    return argv


def parse_probe_output(
    lines: Sequence[str],
) -> Tuple[Dict[str, str], bool, List[str], List[Dict[str, Any]], Dict[str, Any]]:
    """Parse PROBE_RESULT / PROBE_EVENT / PROBE_ALLOWED_PATH lines."""
    observations: Dict[str, str] = {}
    diagnostics: List[str] = []
    events: List[Dict[str, Any]] = []
    allowed_path: Dict[str, Any] = {}
    allowed_http: List[List[str]] = []
    done = False
    allowed_summary_seen = False
    for raw in lines:
        line = raw.strip()
        parts = line.split()
        if not parts:
            continue
        record = parts[0]
        if line == "PROBE_DONE":
            done = True
            continue
        if line.startswith("EOS_RELAY_MISSING_RUNTIME"):
            diagnostics.append(line)
            observations["relay_runtime"] = "missing"
            continue
        if record == "PROBE_ALLOWED_PATH":
            if allowed_summary_seen:
                diagnostics.append("duplicate_allowed_path")
                continue
            allowed_summary_seen = True
            for token in parts[1:]:
                key, sep, value = token.partition("=")
                if (
                    not sep
                    or not value
                    or key not in ALLOWED_SUMMARY_FIELDS
                    or key in allowed_path
                ):
                    diagnostics.append("invalid_allowed_path_field")
                    continue
                allowed_path[key] = value
            continue
        if record == "PROBE_EVENT":
            if len(parts) >= 5:
                if parts[1] == "allowed_public" and len(parts) != 6:
                    diagnostics.append("malformed_allowed_event")
                events.append(
                    {
                        "case": parts[1],
                        "code": parts[2],
                        "ok": parts[3] == "ok",
                        "detail": parts[4],
                        "request_id": parts[5] if len(parts) > 5 else "",
                    }
                )
            elif len(parts) >= 2 and parts[1] == "allowed_public":
                diagnostics.append("malformed_allowed_event")
            continue
        if record == "PROBE_HTTP":
            if len(parts) >= 2 and parts[1] == "allowed_public":
                allowed_http.append(parts[2:])
            continue
        if record == "PROBE_RESULT":
            if len(parts) >= 3:
                if parts[1] == "allowed_public" and parts[1] in observations:
                    diagnostics.append("duplicate_allowed_result")
                    continue
                observations[parts[1]] = parts[2]
                if parts[1] == "allowed_public":
                    if len(parts) == 5:
                        allowed_path["result_detail"] = parts[3]
                        allowed_path["result_request_id"] = parts[4]
                    else:
                        diagnostics.append("malformed_allowed_result")
            else:
                diagnostics.append(f"malformed:{line}")
    if allowed_http:
        expected = [allowed_path.get("http_status"), allowed_path.get("request_id")]
        if allowed_http == [expected]:
            allowed_path["http_statuses"] = {"allowed_public": expected[0]}
        else:
            diagnostics.append("inconsistent_allowed_http")
    return observations, done, diagnostics, events, allowed_path


def evaluate_container_observations(
    observations: Dict[str, str],
    *,
    done: bool,
    allowed_path: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, List[str]]:
    """Return (ok, missing_or_bad). Never treats 'attempted' as success.

    allowed_public may be 'ok' when TLS+HTTP completed even if HTTP status is
    401/403/404 (transport evidence). 'failed'/'attempted' never pass.
    """
    problems: List[str] = []
    if not done:
        problems.append("missing_PROBE_DONE")
    for case, accepted in REQUIRED_CONTAINER_OBSERVATIONS.items():
        outcome = observations.get(case)
        if outcome is None:
            problems.append(f"missing_observation:{case}")
        elif outcome in FALSE_POSITIVE_OUTCOMES or outcome not in accepted:
            problems.append(f"bad_observation:{case}={outcome}")
    if observations.get("relay_runtime") == "missing":
        problems.append("relay_runtime_missing_python3")
    ap = allowed_path or {}
    if observations.get("allowed_public") == "ok":
        # Require explicit transport flags when present.
        tv = str(ap.get("transport_verified", "")).lower()
        if tv and tv not in {"true", "1", "yes"}:
            problems.append("allowed_public_ok_without_transport_verified")
    return (not problems), problems


def _allowed_flag(allowed_path: Dict[str, Any], field_name: str) -> bool:
    return str(allowed_path.get(field_name, "")).lower() in {"true", "1", "yes"}


def _allowed_transport_verified(
    allowed_path: Dict[str, Any], probe_events: Sequence[Dict[str, Any]]
) -> bool:
    """Check that the result, summary, and stage evidence describe one exchange."""
    client_id = allowed_path.get("request_id")
    status = allowed_path.get("http_status", "")
    if (
        client_id in (None, "", "-")
        or allowed_path.get("result_request_id") != client_id
        or re.fullmatch(r"[2-5][0-9]{2}", status) is None
        or allowed_path.get("result_detail") != f"http_{status}"
        or allowed_path.get("http_statuses") != {"allowed_public": status}
        or allowed_path.get("connect_status") != "200"
        or allowed_path.get("failure_stage") != "-"
        or allowed_path.get("failure_code") != "-"
        or not all(
            _allowed_flag(allowed_path, name)
            for name in ("relay_ready", "tls_ok", "cert_ok", "transport_verified")
        )
    ):
        return False

    events = [event for event in probe_events if event["case"] == "allowed_public"]
    if any(event["request_id"] != client_id or not event["ok"] for event in events):
        return False
    stages = {
        STAGE_CONNECT_200: "connection_established",
        STAGE_TLS_COMPLETED: "handshake_ok",
        STAGE_CERT_VALIDATED: "hostname=api.cursor.com",
        STAGE_HTTP_SENT: "GET_/",
        STAGE_HTTP_RESPONSE: f"status={status}",
    }
    observed = [(e["code"], e["detail"]) for e in events if e["code"] in stages]
    return observed == list(stages.items())


@dataclass(frozen=True)
class AllowedBrokerEvidence:
    stages: Set[str] = field(default_factory=set)
    bidirectional_traffic: bool = False
    verified: bool = False


def correlate_allowed_with_broker(
    allowed_path: Dict[str, Any],
    tunnel_events: Sequence[Dict[str, Any]],
) -> AllowedBrokerEvidence:
    """Verify the broker events for the CONNECT response's request ID."""
    broker_id = allowed_path.get("broker_request_id")
    client_id = allowed_path.get("request_id")
    if not valid_broker_request_id(broker_id) or client_id in (None, "", "-", broker_id):
        return AllowedBrokerEvidence()

    events = [event for event in tunnel_events if event.get("request_id") == broker_id]
    if any(
        event.get("host") != "api.cursor.com"
        or event.get("port") != 443
        for event in events
    ):
        return AllowedBrokerEvidence()

    received = [event for event in events if event.get("code") == EVT_CONNECT_RECEIVED]
    if len(received) != 1 or received[0].get("detail") != f"client_req_id={client_id}":
        return AllowedBrokerEvidence()

    codes = [event.get("code") for event in events]
    chain = [
        EVT_CONNECT_RECEIVED,
        EVT_DESTINATION_ALLOWED,
        EVT_DNS_RESOLVED,
        EVT_UPSTREAM_CONNECT_STARTED,
        EVT_UPSTREAM_CONNECTED,
        EVT_TUNNEL_ESTABLISHED,
        EVT_TUNNEL_BYTES_TRANSFERRED,
        EVT_TUNNEL_CLOSED,
    ]
    optional = {EVT_UPSTREAM_CONNECT_STARTED, EVT_TUNNEL_CLOSED}
    expected = [code for code in chain if code not in optional or code in codes]
    successful = [event for event in events if event.get("ok") is True]
    traffic_events = [
        event for event in successful if event.get("code") == EVT_TUNNEL_BYTES_TRANSFERRED
    ]
    traffic = len(traffic_events) == 1 and _has_bidirectional_traffic(
        traffic_events[0].get("detail")
    )
    return AllowedBrokerEvidence(
        stages={
            event["code"] for event in successful if isinstance(event.get("code"), str)
        },
        bidirectional_traffic=traffic,
        verified=traffic and codes == expected and len(successful) == len(events),
    )


def _has_bidirectional_traffic(detail: object) -> bool:
    match = re.fullmatch(
        r"bytes=([1-9][0-9]{0,19}) client_to_upstream=([1-9][0-9]{0,19}) "
        r"upstream_to_client=([1-9][0-9]{0,19})",
        str(detail),
    )
    if match is None:
        return False
    total, sent, received = map(int, match.groups())
    return total == sent + received


def correlate_denied_with_broker(
    observations: Dict[str, str],
    tunnel_events: Sequence[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Require broker DESTINATION_DENIED events for each denied container case."""
    denied_paths: List[Dict[str, Any]] = []
    problems: List[str] = []
    deny_events = [
        e
        for e in tunnel_events
        if e.get("code") == "DESTINATION_DENIED" and e.get("ok") is False
    ]
    mapping = {
        "unapproved_public": "evil.example",
        "private_address": "10.0.0.1",
        "ip_literal": "1.2.3.4",
    }
    for case, host in mapping.items():
        outcome = observations.get(case)
        matches = [e for e in deny_events if e.get("host") == host]
        entry = {
            "case": case,
            "host": host,
            "container_outcome": outcome,
            "broker_denials": matches,
            "ok": outcome == "denied" and bool(matches),
        }
        denied_paths.append(entry)
        if outcome == "denied" and not matches:
            problems.append(f"missing_broker_deny:{case}")
        if outcome != "denied":
            problems.append(f"denied_case_not_ok:{case}={outcome}")
    return denied_paths, problems


def legacy_false_positive_would_pass(observations: Dict[str, str], policy_ok: bool) -> bool:
    """Reproduce pre-12.1 success logic for regression tests."""
    if not policy_ok:
        return False
    # Old logic: 'attempted' counted as acceptable; only LEAK failed.
    for case, outcome in observations.items():
        if outcome == "LEAK":
            return False
    return True


class InjectedNetworkProbeProcess(InjectedFixtureProcess):
    """Offline probe peer that emits evidence-complete PROBE_RESULT lines."""

    def __init__(
        self,
        *,
        container_id: str = "injected-netprobe",
        lines: Optional[List[str]] = None,
    ) -> None:
        super().__init__(scenario="success", container_id=container_id)
        self._stdout.extend(
            lines
            or [
                "PROBE_EVENT relay RELAY_TCP_LISTENING ok listening -",
                "PROBE_EVENT allowed_public CONNECT_200 ok connection_established req-allow-inj",
                "PROBE_EVENT allowed_public TLS_COMPLETED ok handshake_ok req-allow-inj",
                "PROBE_EVENT allowed_public CERT_VALIDATED ok hostname=api.cursor.com req-allow-inj",
                "PROBE_EVENT allowed_public HTTP_SENT ok GET_/ req-allow-inj",
                "PROBE_EVENT allowed_public HTTP_RESPONSE ok status=403 req-allow-inj",
                "PROBE_ALLOWED_PATH relay_ready=true connect_status=200 tls_ok=true cert_ok=true http_status=403 transport_verified=true failure_stage=- failure_code=- request_id=req-allow-inj",
                "PROBE_RESULT allowed_public ok http_403 req-allow-inj",
                "PROBE_HTTP allowed_public 403 req-allow-inj",
                "PROBE_RESULT unapproved_public denied destination_not_allowlisted req-deny-1",
                "PROBE_RESULT private_address denied ip_literal_bypass_denied req-deny-2",
                "PROBE_RESULT ip_literal denied ip_literal_bypass_denied req-deny-3",
                "PROBE_RESULT direct_external denied no_proxy:network_unreachable",
                "PROBE_DONE",
            ]
        )


class NetworkProbeExecutor:
    def __init__(
        self,
        *,
        broker_runtime: Optional[BrokerRuntime] = None,
        process_factory: Optional[ProbeFactory] = None,
        allow_real_podman: bool = False,
        use_live_connect: bool = False,
        image_inspect_fn: Optional[Any] = None,
        python_check_fn: Optional[Any] = None,
    ) -> None:
        if broker_runtime is not None:
            self.broker_runtime = broker_runtime
        elif use_live_connect:
            self.broker_runtime = BrokerRuntime(
                connect_fn=live_open_upstream,
                resolve_fn=default_resolve,
            )
        else:
            self.broker_runtime = BrokerRuntime(connect_fn=blocked_connect)
        self.process_factory = process_factory
        self.allow_real_podman = allow_real_podman
        self.use_live_connect = use_live_connect
        self.image_inspect_fn = image_inspect_fn
        self.python_check_fn = python_check_fn
        self.last_handle: Optional[OciProcessHandle] = None

    def resolve_image(
        self,
        image_ref: Optional[str],
        *,
        owner_real: bool,
        verify_python: bool = False,
    ) -> ProbeImageIdentity:
        """Dedicated probe image path — never uses Alpine fixture resolver."""
        if owner_real:
            return resolve_probe_image(
                image_ref,
                require_image=True,
                allow_host_inspect=True,
                verify_python=verify_python,
                inspect_fn=self.image_inspect_fn,
                python_check_fn=self.python_check_fn,
            )
        # Offline / injected: never call Alpine fixture resolver; never pull.
        if not image_ref:
            return resolve_probe_image(None, require_image=False)
        try:
            validate_probe_image_ref(image_ref)
        except ProbeImageError:
            # Ignore legacy fixture tags in offline tests; use synthetic ID.
            return synthetic_probe_image()
        if self.image_inspect_fn is not None:
            return resolve_probe_image(
                image_ref,
                require_image=False,
                allow_host_inspect=True,
                verify_python=verify_python,
                inspect_fn=self.image_inspect_fn,
                python_check_fn=self.python_check_fn,
            )
        return synthetic_probe_image(image_ref)

    def dry_run_plan(self, request: NetworkProbeRequest) -> Dict[str, Any]:
        from engineering_os.infrastructure.network.broker.egress_broker import TrustedEgressBroker

        plan = TrustedEgressBroker(connect_fn=blocked_connect).probe_plan()
        uid, gid = os.getuid(), os.getgid()
        image_error: Optional[str] = None
        try:
            identity = self.resolve_image(
                request.image_ref or None,
                owner_real=False,
                verify_python=False,
            )
        except ProbeImageError as exc:
            identity = ProbeImageIdentity(
                requested_ref=request.image_ref or "",
                image_id=None,
                digest=None,
                architecture=None,
                os_name=None,
                size=None,
                blocked_reasons=[exc.code],
                validated=False,
            )
            image_error = str(exc)
        image = identity.image_id or identity.requested_ref or "<IMAGE_ID_REQUIRED>"
        prereq = probe_prerequisites(
            image_ref=image if identity.requested_ref else "",
            container_uid=uid,
            container_gid=gid,
            image_identity=identity.to_dict(),
        )
        env = cursor_proxy_env()
        argv_preview = [
            "podman",
            "run",
            "-i",
            "--pull=never",
            "--read-only",
            "--network",
            "none",
            "--userns=keep-id",
            "--user",
            f"{uid}:{gid}",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--memory",
            "128m",
            "--cpus",
            "0.25",
            "--pids-limit",
            "32",
            "--tmpfs",
            "/runtime/tmp:rw,noexec,nosuid,size=16m",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
            "--mount",
            "type=bind,src=<BROKER_SOCK_0600>,dst=/runtime/egress/broker.sock",
            "--mount",
            "type=bind,src=<RELAY_PY>,dst=/runtime/egress/relay.py,ro",
            "--mount",
            "type=bind,src=<PROBE_RUN_PY>,dst=/probe/run.py,ro",
            "--mount",
            "type=bind,src=<PROBE_TRANSPORT_PY>,dst=/probe/transport.py,ro",
            "--workdir",
            "/tmp",
            "--name",
            "eos-netprobe-<execution_suffix>",
        ]
        for key, value in env.items():
            argv_preview.extend(["-e", f"{key}={value}"])
        argv_preview.extend([image, "python3", "/probe/run.py"])
        return {
            "action": "dry_run",
            "executed": False,
            "dry_run": True,
            "plan": plan,
            "argv_preview": argv_preview,
            "prerequisites": prereq,
            "image_identity": identity.to_dict(),
            "image_error": image_error,
            "proxy_compatibility": proxy_compatibility_matrix(),
            "credentials_present": False,
            "host_network": False,
            "live_cursor_acp": False,
            "verification_level": "NOT_TESTED",
            "POLICY_VALIDATED": bool(plan.get("all_ok")),
            "TRANSPORT_VERIFIED": False,
            "ENFORCEMENT_VERIFIED": False,
            "note": probe_image_selection_note(),
        }

    def run(
        self,
        request: NetworkProbeRequest,
        *,
        execute: bool = False,
        allow_phase_b: bool = False,
        owner_authorize_runtime_execution: bool = False,
        dry_run: bool = True,
    ) -> NetworkProbeResult:
        if dry_run or not execute:
            plan = self.dry_run_plan(request)
            return NetworkProbeResult(
                run_id=new_id("netprobe"),
                executed=False,
                dry_run=True,
                cases=plan["plan"]["cases"],
                broker={"status": "not_started"},
                argv=plan["argv_preview"],
                container_id=None,
                cleanup={"cleaned_up": True, "note": "dry_run"},
                evidence_refs=[f"dry-run:{request.execution_id}"],
                evidence_hashes={"plan": sha256_text(str(plan["plan"]))},
                provenance=SYNTHETIC_IN_MEMORY,
                status="DRY_RUN",
                failure_reason=plan.get("image_error"),
                proxy_compatibility=plan["proxy_compatibility"],
                verification_level="NOT_TESTED",
                policy_validated=bool(plan.get("POLICY_VALIDATED")),
                transport_verified=False,
                enforcement_verified=False,
                prerequisites=plan["prerequisites"],
                image_identity=plan.get("image_identity") or {},
            )

        require_owner_execution_gates(
            execute=execute,
            allow_phase_b=allow_phase_b,
            owner_authorize_runtime_execution=owner_authorize_runtime_execution,
        )

        instance = None
        handle: Optional[OciProcessHandle] = None
        interrupt: Dict[str, Any] = {}
        broker_cleanup: Dict[str, Any] = {"stopped": False, "cleanup_verified": False}
        cleanup_handle: Dict[str, Any] = {"cleaned_up": False}
        cases: List[Dict[str, Any]] = []
        lines: List[str] = []
        argv: List[str] = []
        mode = "UNSTARTED"
        provenance = ERROR
        failure_reason: Optional[str] = None
        status = "FAILED"
        observations: Dict[str, str] = {}
        uid, gid = os.getuid(), os.getgid()
        owner_real = bool(self.allow_real_podman and self.process_factory is None)
        image_identity_dict: Dict[str, Any] = {}
        selected_image = request.image_ref
        prereq = probe_prerequisites(
            image_ref=request.image_ref or "",
            container_uid=uid,
            container_gid=gid,
        )

        try:
            identity = self.resolve_image(
                request.image_ref or None,
                owner_real=owner_real,
                verify_python=owner_real,
            )
            image_identity_dict = identity.to_dict()
            if owner_real:
                if not identity.validated or identity.blocked_reasons:
                    raise ProbeImageError(
                        "probe_image_validation_failed:"
                        + ",".join(identity.blocked_reasons or ["unknown"]),
                        code="probe_image_validation_failed",
                    )
                selected_image = identity.image_id or identity.requested_ref
            elif not request.image_ref:
                # Injected offline path may use synthetic identity.
                identity = synthetic_probe_image()
                image_identity_dict = identity.to_dict()
                selected_image = identity.image_id or identity.requested_ref
            else:
                selected_image = identity.image_id or identity.requested_ref
            prereq = probe_prerequisites(
                image_ref=selected_image or "",
                container_uid=uid,
                container_gid=gid,
                image_identity=image_identity_dict,
            )

            instance = self.broker_runtime.start(execution_id=request.execution_id)
            broker = self.broker_runtime.get(request.execution_id)
            assert broker is not None

            for label, host, port, expect in POLICY_CASES:
                decision = broker.evaluate_destination(host, port)
                cases.append(
                    {
                        "case": label,
                        "host": host,
                        "port": port,
                        "expected_allowed": expect,
                        "decision": decision.to_dict(),
                        "ok": decision.allowed == expect,
                        "layer": "policy",
                    }
                )
            from engineering_os.infrastructure.network.broker.egress_broker import (
                TrustedEgressBroker,
            )

            rebind = TrustedEgressBroker(
                allowed_destinations={"api.cursor.com"},
                resolve_fn=lambda h: ["10.0.0.5"],
                connect_fn=blocked_connect,
            )
            rd = rebind.evaluate_destination("api.cursor.com", 443)
            cases.append(
                {
                    "case": "dns_rebinding",
                    "host": "api.cursor.com",
                    "expected_allowed": False,
                    "decision": rd.to_dict(),
                    "ok": not rd.allowed,
                    "layer": "policy",
                }
            )

            workload = write_probe_workload_script(Path(instance.work_dir) / "run.py")
            transport_mod = write_probe_transport_module(
                Path(instance.work_dir) / "transport.py"
            )
            name = f"eos-netprobe-{request.execution_id[-12:]}"
            argv = build_probe_podman_argv(
                image_ref=selected_image or request.image_ref,
                container_name=name,
                socket_host_path=instance.socket_path,
                relay_host_path=instance.relay_path,
                workload_host_path=str(workload),
                transport_host_path=str(transport_mod),
                container_uid=uid,
                container_gid=gid,
            )

            if self.process_factory:
                handle = self.process_factory(request)
                provenance = SYNTHETIC_IN_MEMORY
                mode = "INJECTED"
                # Seed broker-side deny events via UDS CONNECT (no upstream).
                _seed_broker_policy_denials(instance.socket_path)
            else:
                if not self.allow_real_podman:
                    failure_reason = "real_podman_disabled_in_executor_config"
                    status = "REFUSED_PODMAN_DISABLED"
                    provenance = ERROR
                else:
                    proc = subprocess.Popen(
                        argv,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        bufsize=1,
                    )
                    handle = SubprocessOciHandle(
                        proc,
                        container_name=name,
                        container_id=name,
                        cleanup_argv=["podman", "rm", "-f", name],
                        grace_seconds=2.0,
                    )
                    provenance = SYNTHETIC_OCI_EXECUTED
                    mode = "PODMAN"

            self.last_handle = handle
            if handle is not None:
                for _ in range(128):
                    line = handle.read_line(0.25)
                    if line is None:
                        if handle.poll_exit() is not None:
                            break
                        continue
                    lines.append(line)
                    if line.strip() == "PROBE_DONE":
                        break

            interrupt = self.broker_runtime.interrupt(request.execution_id)
            cases.append(
                {
                    "case": "broker_shutdown_interrupts",
                    "expected_allowed": False,
                    "decision": interrupt.get("evaluate_api_cursor"),
                    "ok": not (interrupt.get("evaluate_api_cursor") or {}).get(
                        "allowed", True
                    ),
                    "layer": "runtime",
                }
            )
        except Exception as exc:  # noqa: BLE001
            failure_reason = f"probe_exception:{exc}"
            status = "FAILED"
            provenance = ERROR
        finally:
            if handle is not None:
                try:
                    cleanup_handle = handle.cleanup(grace_seconds=2.0)
                except Exception as exc:  # noqa: BLE001
                    cleanup_handle = {
                        "cleaned_up": False,
                        "error": f"cleanup_exception:{exc}",
                    }
            try:
                broker_cleanup = self.broker_runtime.stop(request.execution_id)
            except Exception as exc:  # noqa: BLE001
                broker_cleanup = {
                    "stopped": False,
                    "cleanup_verified": False,
                    "error": f"broker_cleanup_exception:{exc}",
                }

        observations, done, diagnostics, probe_events, allowed_path = parse_probe_output(
            lines
        )
        obs_ok, obs_problems = evaluate_container_observations(
            observations, done=done, allowed_path=allowed_path
        )
        tunnel_events = list(broker_cleanup.get("tunnel_events") or [])
        denied_paths, deny_problems = correlate_denied_with_broker(
            observations, tunnel_events
        )
        policy_ok = bool(cases) and all(
            c.get("ok") for c in cases if c.get("layer") == "policy"
        )
        runtime_ok = all(c.get("ok") for c in cases if c.get("layer") == "runtime")
        cleanup_ok = bool(cleanup_handle.get("cleaned_up")) and bool(
            broker_cleanup.get("cleanup_verified")
        )

        # Attach container observation cases (never promote attempted→ok).
        for case_name, outcome in observations.items():
            accepted = REQUIRED_CONTAINER_OBSERVATIONS.get(case_name)
            ok = bool(accepted and outcome in accepted)
            cases.append(
                {
                    "case": f"container_{case_name}",
                    "outcome": outcome,
                    "ok": ok,
                    "layer": "container",
                    "decision": {"reason": f"container_reported:{outcome}"},
                }
            )
        for problem in obs_problems:
            cases.append(
                {
                    "case": "container_evidence",
                    "ok": False,
                    "layer": "container",
                    "decision": {"reason": problem},
                }
            )
        for diag in diagnostics:
            cases.append(
                {
                    "case": "container_diagnostic",
                    "ok": False,
                    "layer": "container",
                    "decision": {"reason": diag},
                }
            )

        transport_ok = (
            mode in {"INJECTED", "PODMAN"}
            and observations.get("allowed_public") == "ok"
            and "relay_runtime" not in observations
            and not diagnostics
            and _allowed_transport_verified(allowed_path, probe_events)
        )
        allowed_broker = correlate_allowed_with_broker(allowed_path, tunnel_events)
        # Broker-confirmed denials required only for real OCI enforcement.
        denials_ok = not deny_problems if mode == "PODMAN" else True
        for problem in deny_problems if mode == "PODMAN" else []:
            cases.append(
                {
                    "case": "broker_correlation",
                    "ok": False,
                    "layer": "broker",
                    "decision": {"reason": problem},
                }
            )

        enforcement_ok = (
            policy_ok
            and runtime_ok
            and obs_ok
            and transport_ok
            and denials_ok
            and allowed_broker.verified
            and cleanup_ok
            and mode == "PODMAN"
            and status != "REFUSED_PODMAN_DISABLED"
            and failure_reason is None
        )

        if status == "REFUSED_PODMAN_DISABLED":
            verification_level = "POLICY_VALIDATED" if policy_ok else "FAILED"
        elif failure_reason and mode != "INJECTED":
            verification_level = "FAILED"
            status = "FAILED"
        elif enforcement_ok:
            verification_level = "ENFORCEMENT_VERIFIED"
            status = "COMPLETED"
            failure_reason = None
        elif policy_ok and transport_ok and obs_ok and not cleanup_ok:
            verification_level = "TRANSPORT_VERIFIED"
            status = "FAILED"
            failure_reason = "probe_cleanup_incomplete"
        elif policy_ok and transport_ok and obs_ok and mode == "INJECTED":
            verification_level = "TRANSPORT_VERIFIED"
            status = "COMPLETED"
            failure_reason = None
        elif policy_ok and transport_ok and not denials_ok:
            verification_level = "TRANSPORT_VERIFIED"
            status = "FAILED"
            failure_reason = "broker_denial_correlation_incomplete:" + ",".join(
                deny_problems
            )
        elif policy_ok and transport_ok and mode == "PODMAN" and not allowed_broker.verified:
            verification_level = "TRANSPORT_VERIFIED"
            status = "FAILED"
            failure_reason = "broker_allowed_correlation_incomplete"
        elif policy_ok and not obs_ok:
            verification_level = "POLICY_VALIDATED"
            status = "FAILED"
            failure_reason = "container_evidence_incomplete:" + ",".join(obs_problems)
        elif policy_ok and not transport_ok and mode in {"INJECTED", "PODMAN"}:
            verification_level = "POLICY_VALIDATED"
            status = "FAILED"
            failure_reason = "container_allowed_transport_incomplete"
        else:
            verification_level = "FAILED"
            status = "FAILED"
            failure_reason = failure_reason or (
                "probe_failed:"
                + ",".join(obs_problems or deny_problems or ["unknown"])
            )

        # Normalize allowed_path booleans for machine-readable output.
        allowed_path_out = {
            "relay_ready": _allowed_flag(allowed_path, "relay_ready"),
            "broker_connected": EVT_CONNECT_RECEIVED in allowed_broker.stages,
            "connect_response_code": _maybe_int(allowed_path.get("connect_status")),
            "destination_allowed": EVT_DESTINATION_ALLOWED in allowed_broker.stages,
            "dns_resolution": EVT_DNS_RESOLVED in allowed_broker.stages,
            "upstream_connected": EVT_UPSTREAM_CONNECTED in allowed_broker.stages,
            "tunnel_established": EVT_TUNNEL_ESTABLISHED in allowed_broker.stages,
            "bidirectional_traffic": allowed_broker.bidirectional_traffic,
            "broker_correlation_verified": allowed_broker.verified,
            "tls_handshake": _allowed_flag(allowed_path, "tls_ok"),
            "certificate_validated": _allowed_flag(allowed_path, "cert_ok"),
            "http_status": _maybe_int(allowed_path.get("http_status")),
            "transport_verified": transport_ok,
            "failure_stage": allowed_path.get("failure_stage")
            if str(allowed_path.get("failure_stage", "-")) not in {"-", ""}
            else None,
            "failure_code": allowed_path.get("failure_code")
            if str(allowed_path.get("failure_code", "-")) not in {"-", ""}
            else None,
            "request_id": allowed_path.get("request_id"),
            "broker_request_id": (
                allowed_path["broker_request_id"]
                if valid_broker_request_id(allowed_path.get("broker_request_id"))
                else None
            ),
            "raw": dict(allowed_path),
        }

        run_id = new_id("netprobe")
        return NetworkProbeResult(
            run_id=run_id,
            executed=mode in {"INJECTED", "PODMAN"},
            dry_run=False,
            cases=cases,
            broker={
                **(instance.to_dict() if instance else {}),
                "mode": mode,
                "interrupt": interrupt,
                "observations": broker_cleanup.get("observations") or [],
                "tunnel_stats": broker_cleanup.get("tunnel_stats") or [],
                "tunnel_events": tunnel_events,
                "live_connect_enabled": self.broker_runtime.status().get(
                    "live_connect_enabled"
                ),
            },
            argv=argv,
            container_id=handle.container_id if handle else None,
            cleanup={
                "container": cleanup_handle,
                "broker": broker_cleanup,
            },
            evidence_refs=[
                f"netprobe:{run_id}",
                f"broker:{(instance.broker_id if instance else 'none')}",
                f"container:{(handle.container_id if handle else 'none')}",
            ],
            evidence_hashes={
                "cases": sha256_text(str(cases)),
                "argv": sha256_text(str(argv)),
                "output": sha256_text("\n".join(lines)),
            },
            provenance=provenance,
            status=status,
            failure_reason=failure_reason,
            proxy_compatibility=proxy_compatibility_matrix(),
            verification_level=verification_level,
            policy_validated=policy_ok,
            transport_verified=bool(transport_ok and policy_ok),
            enforcement_verified=(
                enforcement_ok and verification_level == "ENFORCEMENT_VERIFIED"
            ),
            container_observations=observations,
            prerequisites=prereq,
            image_identity=image_identity_dict,
            allowed_path=allowed_path_out,
            denied_paths=denied_paths,
            tunnel_events=tunnel_events,
            probe_events=probe_events,
        )


def _maybe_int(value: Any) -> Optional[int]:
    try:
        if value is None or value == "" or value == "None":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _seed_broker_policy_denials(socket_path: str) -> None:
    """Issue CONNECT requests for known-denied hosts to create broker events."""
    import socket as _socket

    for host, port in (("evil.example", 443), ("10.0.0.1", 443), ("1.2.3.4", 443)):
        try:
            sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect(socket_path)
            sock.sendall(
                (
                    f"CONNECT {host}:{port} HTTP/1.1\r\n"
                    f"Host: {host}:{port}\r\n"
                    f"X-EOS-Request-Id: seed-{host}\r\n"
                    f"\r\n"
                ).encode("ascii")
            )
            sock.recv(1024)
            sock.close()
        except OSError:
            continue


def default_injected_probe_factory(
    *, lines: Optional[List[str]] = None
) -> ProbeFactory:
    def factory(request: NetworkProbeRequest) -> OciProcessHandle:
        return InjectedNetworkProbeProcess(
            container_id=f"injected-probe-{request.execution_id[-8:]}",
            lines=lines,
        )

    return factory
