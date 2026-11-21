"""Owner-gated network enforcement probe using disposable Podman + UDS broker.

Automated tests inject a process factory and never start containers or open
real network connections. Owner `--execute` path constructs real argv and may
start containers only when explicitly gated upstream.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence
import json
import os
import re
import subprocess
import tempfile

from engineering_os.domain.models import new_id, utc_now
from engineering_os.infrastructure.network.broker.broker_runtime import (
    BrokerRuntime,
    cursor_proxy_env,
    live_connect,
    proxy_compatibility_matrix,
)
from engineering_os.infrastructure.network.broker.egress_broker import blocked_connect
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
from engineering_os.infrastructure.runtime.oci.podman_executor import (
    probe_podman_runtime,
    require_owner_execution_gates,
    resolve_local_fixture_image,
    sha256_text,
)
from engineering_os.infrastructure.runtime.sandbox.sandbox_launcher import scan_argv_for_bypass


ProbeFactory = Callable[["NetworkProbeRequest"], OciProcessHandle]


PROBE_CASES = (
    ("allowed_public", "api.cursor.com", 443, True),
    ("unapproved_public", "evil.example", 443, False),
    ("direct_ip", "1.2.3.4", 443, False),
    ("private_address", "10.0.0.1", 443, False),
    ("link_local_metadata", "169.254.169.254", 80, False),
    ("ipv6_loopback", "::1", 443, False),
)


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
            "live_cursor_acp": False,
        }


def write_probe_workload_script(path: Path) -> Path:
    """Disposable probe script: talks only via HTTPS_PROXY to the relay."""
    path.parent.mkdir(parents=True, exist_ok=True)
    script = r'''#!/bin/sh
# EOS-12 network probe workload — no credentials, proxy-only.
set -eu
PROXY="${HTTPS_PROXY:-http://127.0.0.1:18080}"
# Start TCP→UDS relay in background if present.
if [ -f /runtime/egress/relay.py ]; then
  python3 /runtime/egress/relay.py &
  RELAY_PID=$!
  sleep 0.2
fi
report() { echo "PROBE_RESULT $1 $2 $3"; }
# Allowed destination — expect broker 200 or connect attempt via CONNECT.
if command -v wget >/dev/null 2>&1; then
  if wget -q -O /dev/null --timeout=5 -e use_proxy=yes -e https_proxy="$PROXY" https://api.cursor.com/ 2>/tmp/eos_probe_err; then
    report allowed_public ok via_proxy
  else
    # Even failures are reported; broker may return 403/502 after allow decision.
    report allowed_public attempted via_proxy
  fi
  if wget -q -O /dev/null --timeout=5 -e use_proxy=yes -e https_proxy="$PROXY" https://evil.example/ 2>/dev/null; then
    report unapproved_public LEAK via_proxy
  else
    report unapproved_public denied via_proxy
  fi
else
  report tool missing wget
fi
# Direct external TCP must fail under --network=none (no route).
if command -v nc >/dev/null 2>&1; then
  if nc -z -w 2 1.1.1.1 443 2>/dev/null; then
    report direct_external LEAK route_exists
  else
    report direct_external denied no_route
  fi
else
  # Busybox may lack nc; try /dev/tcp if bash — alpine uses ash.
  report direct_external skipped no_nc
fi
if [ -n "${RELAY_PID:-}" ]; then
  kill "$RELAY_PID" 2>/dev/null || true
fi
echo PROBE_DONE
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
) -> List[str]:
    if not re.fullmatch(r"eos-netprobe-[A-Za-z0-9._-]{4,80}", container_name):
        raise RuntimeError("invalid_probe_container_name")
    for p in (socket_host_path, relay_host_path, workload_host_path):
        if not Path(p).exists():
            raise RuntimeError(f"probe_path_missing:{p}")
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
        "65534:65534",
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
        f"type=bind,src={workload_host_path},dst=/probe/run.sh,ro",
        "--workdir",
        "/tmp",
        "--name",
        container_name,
    ]
    for key, value in env.items():
        argv.extend(["-e", f"{key}={value}"])
    argv.extend([image_ref, "sh", "/probe/run.sh"])
    bypass = scan_argv_for_bypass(argv)
    if bypass:
        raise RuntimeError(f"argv_bypass:{','.join(bypass)}")
    joined = " ".join(argv)
    if "CURSOR_API_KEY=" in joined or "sk-" in joined:
        raise RuntimeError("secret_in_probe_argv")
    if "docker.sock" in joined or "podman.sock" in joined:
        raise RuntimeError("runtime_socket_mount_forbidden")
    return argv


class InjectedNetworkProbeProcess(InjectedFixtureProcess):
    """Offline probe peer that emits PROBE_RESULT lines via stderr/stdout."""

    def __init__(self, *, container_id: str = "injected-netprobe") -> None:
        super().__init__(scenario="success", container_id=container_id)
        # Preload stdout with probe evidence lines after ACP-like silence.
        self._stdout.extend(
            [
                "PROBE_RESULT allowed_public attempted via_proxy",
                "PROBE_RESULT unapproved_public denied via_proxy",
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
    ) -> None:
        self.broker_runtime = broker_runtime or BrokerRuntime(
            connect_fn=live_connect if use_live_connect else blocked_connect
        )
        self.process_factory = process_factory
        self.allow_real_podman = allow_real_podman
        self.use_live_connect = use_live_connect
        self.last_handle: Optional[OciProcessHandle] = None

    def dry_run_plan(self, request: NetworkProbeRequest) -> Dict[str, Any]:
        # Policy-level cases without containers.
        from engineering_os.infrastructure.network.broker.egress_broker import TrustedEgressBroker

        plan = TrustedEgressBroker(connect_fn=blocked_connect).probe_plan()
        image = request.image_ref or resolve_local_fixture_image() or "localhost/alpine:eos-fixture"
        argv_preview = [
            "podman",
            "run",
            "--network",
            "none",
            "--mount",
            "type=bind,src=<SOCK>,dst=/runtime/egress/broker.sock",
            "--mount",
            "type=bind,src=<RELAY>,dst=/runtime/egress/relay.py,ro",
            image,
            "sh",
            "/probe/run.sh",
        ]
        return {
            "action": "dry_run",
            "executed": False,
            "dry_run": True,
            "plan": plan,
            "argv_preview": argv_preview,
            "proxy_compatibility": proxy_compatibility_matrix(),
            "credentials_present": False,
            "host_network": False,
            "live_cursor_acp": False,
            "note": "Dry-run is not an executed network probe",
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
                failure_reason=None,
                proxy_compatibility=plan["proxy_compatibility"],
            )

        require_owner_execution_gates(
            execute=execute,
            allow_phase_b=allow_phase_b,
            owner_authorize_runtime_execution=owner_authorize_runtime_execution,
        )

        instance = self.broker_runtime.start(execution_id=request.execution_id)
        broker = self.broker_runtime.get(request.execution_id)
        assert broker is not None

        # Evaluate policy cases on the live broker instance (still offline-safe
        # when connect_fn is blocked_connect).
        cases: List[Dict[str, Any]] = []
        for label, host, port, expect in PROBE_CASES:
            decision = broker.evaluate_destination(host, port)
            cases.append(
                {
                    "case": label,
                    "host": host,
                    "port": port,
                    "expected_allowed": expect,
                    "decision": decision.to_dict(),
                    "ok": decision.allowed == expect,
                }
            )
        # DNS rebinding
        from engineering_os.infrastructure.network.broker.egress_broker import TrustedEgressBroker

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
            }
        )

        workload = write_probe_workload_script(
            Path(instance.work_dir) / "run.sh"
        )
        name = f"eos-netprobe-{request.execution_id[-12:]}"
        argv = build_probe_podman_argv(
            image_ref=request.image_ref,
            container_name=name,
            socket_host_path=instance.socket_path,
            relay_host_path=instance.relay_path,
            workload_host_path=str(workload),
        )

        if self.process_factory:
            handle = self.process_factory(request)
            provenance = SYNTHETIC_IN_MEMORY
            mode = "INJECTED"
        else:
            if not self.allow_real_podman:
                interrupt = self.broker_runtime.interrupt(request.execution_id)
                cleanup = self.broker_runtime.stop(request.execution_id)
                return NetworkProbeResult(
                    run_id=new_id("netprobe"),
                    executed=False,
                    dry_run=False,
                    cases=cases,
                    broker={**instance.to_dict(), "interrupt": interrupt},
                    argv=argv,
                    container_id=None,
                    cleanup=cleanup,
                    evidence_refs=[f"broker:{instance.broker_id}"],
                    evidence_hashes={"cases": sha256_text(str(cases))},
                    provenance=ERROR,
                    status="REFUSED_PODMAN_DISABLED",
                    failure_reason="real_podman_disabled_in_executor_config",
                    proxy_compatibility=proxy_compatibility_matrix(),
                )
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
        # Drain probe output briefly.
        lines: List[str] = []
        for _ in range(32):
            line = handle.read_line(0.2)
            if line is None:
                if handle.poll_exit() is not None:
                    break
                continue
            lines.append(line)
            if line.strip() == "PROBE_DONE":
                break

        # Broker interrupt fail-closed demonstration.
        interrupt = self.broker_runtime.interrupt(request.execution_id)
        cases.append(
            {
                "case": "broker_shutdown_interrupts",
                "expected_allowed": False,
                "decision": interrupt.get("evaluate_api_cursor"),
                "ok": not (interrupt.get("evaluate_api_cursor") or {}).get(
                    "allowed", True
                ),
            }
        )

        cleanup_handle = handle.cleanup(grace_seconds=2.0)
        broker_cleanup = self.broker_runtime.stop(request.execution_id)

        # Parse container lines into case supplements.
        for line in lines:
            if line.startswith("PROBE_RESULT"):
                parts = line.split()
                if len(parts) >= 3 and parts[2] == "LEAK":
                    cases.append(
                        {
                            "case": parts[1],
                            "ok": False,
                            "decision": {"reason": "container_reported_leak"},
                            "expected_allowed": False,
                        }
                    )

        all_ok = all(c.get("ok") for c in cases)
        run_id = new_id("netprobe")
        return NetworkProbeResult(
            run_id=run_id,
            executed=True,
            dry_run=False,
            cases=cases,
            broker={
                **instance.to_dict(),
                "mode": mode,
                "interrupt": interrupt,
                "observations": broker_cleanup.get("observations") or [],
            },
            argv=argv,
            container_id=handle.container_id,
            cleanup={
                "container": cleanup_handle,
                "broker": broker_cleanup,
            },
            evidence_refs=[
                f"netprobe:{run_id}",
                f"broker:{instance.broker_id}",
                f"container:{handle.container_id}",
            ],
            evidence_hashes={
                "cases": sha256_text(str(cases)),
                "argv": sha256_text(str(argv)),
                "output": sha256_text("\n".join(lines)),
            },
            provenance=provenance,
            status="COMPLETED" if all_ok and cleanup_handle.get("cleaned_up") else "FAILED",
            failure_reason=None if all_ok else "one_or_more_probe_cases_failed",
            proxy_compatibility=proxy_compatibility_matrix(),
        )


def default_injected_probe_factory() -> ProbeFactory:
    def factory(request: NetworkProbeRequest) -> OciProcessHandle:
        return InjectedNetworkProbeProcess(
            container_id=f"injected-probe-{request.execution_id[-8:]}"
        )

    return factory
