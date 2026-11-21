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
    """Pure-Python probe workload — no wget/nc dependency."""
    path.parent.mkdir(parents=True, exist_ok=True)
    # Accept .py or legacy .sh path names from callers.
    if path.suffix == ".sh":
        path = path.with_suffix(".py")
    script = r'''#!/usr/bin/env python3
"""EOS-12.1 network probe workload — stdlib only, proxy-only, evidence-strict."""
from __future__ import annotations
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

PROXY = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY") or "http://127.0.0.1:18080"
RELAY = "/runtime/egress/relay.py"


def report(case: str, outcome: str, detail: str) -> None:
    print(f"PROBE_RESULT {case} {outcome} {detail}", flush=True)


def via_proxy(url: str, timeout: float = 8.0) -> None:
    handler = urllib.request.ProxyHandler({"http": PROXY, "https": PROXY})
    opener = urllib.request.build_opener(handler)
    opener.open(url, timeout=timeout).read(64)


def main() -> int:
    if not os.path.isfile(RELAY):
        report("relay_script", "missing", "path")
        print("PROBE_DONE", flush=True)
        return 1

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        s.close()
    except OSError:
        report("loopback", "failed", "network_none")
        print("PROBE_DONE", flush=True)
        return 1

    relay_proc = subprocess.Popen([sys.executable, RELAY])
    time.sleep(0.3)
    if relay_proc.poll() is not None:
        report("relay_start", "failed", "init")
        print("PROBE_DONE", flush=True)
        return 1

    # Allowed destination — require verified data exchange via CONNECT tunnel.
    try:
        via_proxy("https://api.cursor.com/", timeout=8.0)
        report("allowed_public", "ok", "via_proxy")
    except Exception:
        report("allowed_public", "failed", "via_proxy")

    for case, url in (
        ("unapproved_public", "https://evil.example/"),
        ("private_address", "https://10.0.0.1/"),
        ("ip_literal", "https://1.2.3.4/"),
    ):
        try:
            via_proxy(url, timeout=5.0)
            report(case, "LEAK", "via_proxy")
        except Exception:
            report(case, "denied", "via_proxy")

    # Direct external TCP must fail under --network=none (no proxy).
    try:
        socket.create_connection(("1.1.1.1", 443), 2.0).close()
        report("direct_external", "LEAK", "route_exists")
    except OSError:
        report("direct_external", "denied", "no_route")

    relay_proc.terminate()
    try:
        relay_proc.wait(timeout=2)
    except Exception:
        relay_proc.kill()
    print("PROBE_DONE", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        report("workload", "error", type(exc).__name__)
        print("PROBE_DONE", flush=True)
        raise SystemExit(1)
'''
    path.write_text(script, encoding="utf-8")
    path.chmod(0o755)
    return path


def build_probe_podman_argv(
    *,
    image_ref: str,
    container_name: str,
    socket_host_path: str,
    relay_host_path: str,
    workload_host_path: str,
    memory_limit: str = "128m",
    cpu_limit: str = "0.25",
    pids_limit: int = 32,
    container_uid: Optional[int] = None,
    container_gid: Optional[int] = None,
) -> List[str]:
    if not re.fullmatch(r"eos-netprobe-[A-Za-z0-9._-]{4,80}", container_name):
        raise RuntimeError("invalid_probe_container_name")
    for p in (socket_host_path, relay_host_path, workload_host_path):
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


def parse_probe_output(lines: Sequence[str]) -> Tuple[Dict[str, str], bool, List[str]]:
    """Parse PROBE_RESULT lines. Returns observations, done_seen, diagnostics."""
    observations: Dict[str, str] = {}
    diagnostics: List[str] = []
    done = False
    for raw in lines:
        line = raw.strip()
        if line == "PROBE_DONE":
            done = True
            continue
        if line.startswith("EOS_RELAY_MISSING_RUNTIME"):
            diagnostics.append(line)
            observations["relay_runtime"] = "missing"
            continue
        if line.startswith("PROBE_RESULT"):
            parts = line.split()
            if len(parts) >= 3:
                observations[parts[1]] = parts[2]
            else:
                diagnostics.append(f"malformed:{line}")
    return observations, done, diagnostics


def evaluate_container_observations(
    observations: Dict[str, str], *, done: bool
) -> Tuple[bool, List[str]]:
    """Return (ok, missing_or_bad). Never treats 'attempted' as success."""
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
    return (not problems), problems


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
                "PROBE_RESULT allowed_public ok via_proxy",
                "PROBE_RESULT unapproved_public denied via_proxy",
                "PROBE_RESULT private_address denied via_proxy",
                "PROBE_RESULT ip_literal denied via_proxy",
                "PROBE_RESULT direct_external denied no_route",
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
            name = f"eos-netprobe-{request.execution_id[-12:]}"
            argv = build_probe_podman_argv(
                image_ref=selected_image or request.image_ref,
                container_name=name,
                socket_host_path=instance.socket_path,
                relay_host_path=instance.relay_path,
                workload_host_path=str(workload),
                container_uid=uid,
                container_gid=gid,
            )

            if self.process_factory:
                handle = self.process_factory(request)
                provenance = SYNTHETIC_IN_MEMORY
                mode = "INJECTED"
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
                for _ in range(64):
                    line = handle.read_line(0.2)
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

        observations, done, diagnostics = parse_probe_output(lines)
        obs_ok, obs_problems = evaluate_container_observations(observations, done=done)
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
            and obs_ok
            and "relay_runtime" not in observations
        )
        enforcement_ok = (
            policy_ok
            and runtime_ok
            and obs_ok
            and cleanup_ok
            and mode in {"INJECTED", "PODMAN"}
            and status != "REFUSED_PODMAN_DISABLED"
            and failure_reason is None
        )

        if status == "REFUSED_PODMAN_DISABLED":
            verification_level = "POLICY_VALIDATED" if policy_ok else "FAILED"
        elif failure_reason:
            verification_level = "FAILED"
            status = "FAILED"
        elif enforcement_ok:
            verification_level = (
                "ENFORCEMENT_VERIFIED"
                if mode == "PODMAN"
                else "TRANSPORT_VERIFIED"
            )
            # Injected path can prove transport+policy evidence offline, never
            # claim live OCI enforcement without real Podman provenance.
            if mode == "INJECTED":
                verification_level = "TRANSPORT_VERIFIED"
            status = "COMPLETED"
            failure_reason = None
        elif policy_ok and not obs_ok:
            verification_level = "POLICY_VALIDATED"
            status = "FAILED"
            failure_reason = "container_evidence_incomplete:" + ",".join(obs_problems)
        else:
            verification_level = "FAILED"
            status = "FAILED"
            failure_reason = failure_reason or (
                "probe_failed:" + ",".join(obs_problems or ["unknown"])
            )

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
            transport_verified=transport_ok and policy_ok,
            enforcement_verified=(
                enforcement_ok and mode == "PODMAN" and verification_level == "ENFORCEMENT_VERIFIED"
            ),
            container_observations=observations,
            prerequisites=prereq,
            image_identity=image_identity_dict,
        )


def default_injected_probe_factory(
    *, lines: Optional[List[str]] = None
) -> ProbeFactory:
    def factory(request: NetworkProbeRequest) -> OciProcessHandle:
        return InjectedNetworkProbeProcess(
            container_id=f"injected-probe-{request.execution_id[-8:]}",
            lines=lines,
        )

    return factory
