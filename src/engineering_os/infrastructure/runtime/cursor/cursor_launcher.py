"""Cursor ACP OCI launcher — Owner-gated, fail-closed (EOS-10).

Never starts Cursor on the host. Never falls back to an unisolated process.
Live launch remains blocked unless SANDBOX PASS + host auth + Owner triple-gate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence
import re

from engineering_os.domain.models import new_id, utc_now
from engineering_os.infrastructure.security.credentials.credential_provider import (
    CredentialLease,
    CredentialProvider,
    UnavailableCursorCredentialProvider,
    redact_secrets,
)
from engineering_os.infrastructure.runtime.cursor.cursor_runtime import CursorRuntimePlanner
from engineering_os.infrastructure.network.broker.egress_broker import (
    broker_podman_args,
    cursor_proxy_compatibility,
)
from engineering_os.infrastructure.network.policy.egress_enforcer import (
    PastaAllowlistEgressPolicy,
    UdsBrokerEgressPolicy,
)
from engineering_os.infrastructure.evidence import (
    CURSOR_ACP_LIVE,
    SYNTHETIC_IN_MEMORY,
)
from engineering_os.infrastructure.network.policy.network_policy import NetworkPolicy, UnenforcedNetworkPolicy
from engineering_os.infrastructure.runtime.oci.oci_process import (
    InjectedFixtureProcess,
    OciProcessError,
    OciProcessHandle,
    SubprocessOciHandle,
)
from engineering_os.infrastructure.runtime.oci.podman_executor import require_owner_execution_gates
from engineering_os.infrastructure.security.authorization.runtime_authorization import (
    AuthorizationError,
    RuntimeAuthorization,
    RuntimeAuthorizationVerifier,
)
from engineering_os.infrastructure.runtime.sandbox.sandbox_launcher import scan_argv_for_bypass


ProcessFactory = Callable[["CursorLaunchRequest"], OciProcessHandle]


@dataclass
class CursorLaunchRequest:
    execution_id: str
    project_id: str
    task_id: str
    workspace_id: str
    workspace_host_path: str
    image_ref: str
    image_digest: str
    acp_argv: Sequence[str]
    memory_limit: str = "512m"
    cpu_limit: str = "1.0"
    pids_limit: int = 128
    wall_clock_seconds: int = 120
    correlation_id: str = ""
    network_mode: str = "none"
    credential_provider_id: str = ""
    network_policy_id: str = ""
    broker_socket_host_path: str = ""
    relay_host_path: str = ""
    deny_untrusted_tools: bool = True
    smoke_mode: str = "ask"


@dataclass
class CursorLaunchPlan:
    argv: List[str]
    env_keys: List[str]
    controls: Dict[str, bool]
    blocked_reasons: List[str] = field(default_factory=list)
    mode: str = "PLANNED"
    image_ref: str = ""
    image_digest: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "argv": list(self.argv),
            "env_keys": list(self.env_keys),
            "controls": dict(self.controls),
            "blocked_reasons": list(self.blocked_reasons),
            "mode": self.mode,
            "image_ref": self.image_ref,
            "image_digest": self.image_digest,
            # Never include secret values.
            "secrets_in_argv": False,
        }


def build_cursor_podman_argv(
    *,
    image_ref: str,
    container_name: str,
    workspace_host_path: str,
    acp_argv: Sequence[str],
    memory_limit: str = "512m",
    cpu_limit: str = "1.0",
    pids_limit: int = 128,
    network_args: Optional[Sequence[str]] = None,
) -> List[str]:
    if not re.fullmatch(r"eos-cursor-[A-Za-z0-9._-]{4,80}", container_name):
        raise OciProcessError("invalid_container_name", code="name")
    if list(acp_argv) not in (["agent", "acp"], ["cursor-agent", "acp"]):
        raise OciProcessError("unapproved_acp_command", code="command")
    net_args = list(network_args or ["--network", "none"])
    if "--network" in net_args:
        idx = net_args.index("--network")
        if idx + 1 < len(net_args) and net_args[idx + 1] in {"host", "private"}:
            raise OciProcessError("host_network_forbidden", code="network")
        if idx + 1 < len(net_args) and net_args[idx + 1] != "none":
            # EOS-11 default enforceable path is network=none + UDS broker.
            raise OciProcessError(
                "non_none_network_requires_verified_enforcement",
                code="network",
            )
    extra_mounts: List[str] = []
    # Optional broker mounts appended by caller via network_args side channel
    # are not used; mounts are passed separately through build kwargs below.
    argv = [
        "podman",
        "run",
        "-i",
        "--pull=never",
        "--read-only",
        *net_args,
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
        "/runtime/tmp:rw,noexec,nosuid,size=64m",
        "--tmpfs",
        "/runtime/home:rw,size=32m",
        "--tmpfs",
        "/runtime/cache:rw,size=64m",
        "--tmpfs",
        "/runtime/config:rw,size=16m",
        "--tmpfs",
        "/runtime/egress:rw,size=8m",
        "--mount",
        f"type=bind,src={workspace_host_path},dst=/workspace,ro",
        *extra_mounts,
        "--workdir",
        "/workspace",
        "--name",
        container_name,
        "-e",
        "HOME=/runtime/home",
        "-e",
        "XDG_CACHE_HOME=/runtime/cache",
        "-e",
        "XDG_CONFIG_HOME=/runtime/config",
        "-e",
        "PATH=/usr/local/bin:/usr/bin:/bin",
        "-e",
        "CURSOR_DISABLE_AUTO_UPDATE=1",
        "-e",
        "EOS_CURSOR_SMOKE_MODE=ask",
        "-e",
        "EOS_DENY_UNTRUSTED_TOOLS=1",
        # CURSOR_API_KEY is passed via env dict to Popen — never as argv value.
        # HTTPS_PROXY points at loopback relay only when broker mounts are present.
        image_ref,
        *list(acp_argv),
    ]
    bypass = scan_argv_for_bypass(argv)
    if bypass:
        raise OciProcessError(f"argv_bypass:{','.join(bypass)}", code="bypass")
    # Ensure no secret-looking tokens in argv.
    joined = " ".join(argv)
    if "sk-" in joined or "CURSOR_API_KEY=" in joined:
        raise OciProcessError("secret_in_argv_forbidden", code="secret")
    return argv


class CursorAcpLauncher:
    """Plans and (when fully authorized) launches Cursor ACP inside Podman."""

    def __init__(
        self,
        *,
        runtime: Optional[CursorRuntimePlanner] = None,
        credentials: Optional[CredentialProvider] = None,
        network: Optional[NetworkPolicy] = None,
        auth_verifier: Optional[RuntimeAuthorizationVerifier] = None,
        sandbox_gate: str = "NOT_TESTED",
        process_factory: Optional[ProcessFactory] = None,
        allow_real_podman: bool = False,
        grace_seconds: float = 2.0,
    ) -> None:
        self.runtime = runtime or CursorRuntimePlanner()
        self.credentials = credentials or UnavailableCursorCredentialProvider()
        self.network = network or UnenforcedNetworkPolicy()
        self.auth_verifier = auth_verifier
        self.sandbox_gate = sandbox_gate
        self.process_factory = process_factory
        self.allow_real_podman = allow_real_podman
        self.grace_seconds = grace_seconds
        self.last_handle: Optional[OciProcessHandle] = None
        self.last_lease: Optional[CredentialLease] = None

    def plan(self, request: CursorLaunchRequest) -> CursorLaunchPlan:
        blocked: List[str] = []
        if self.sandbox_gate != "PASS":
            blocked.append("sandbox_gate_not_pass")
        else:
            blocked.append("sandbox_gate_pass_insufficient_without_host_auth")
        if not self.runtime.image_digest:
            blocked.append("image_digest_unverified")
        if request.image_digest and self.runtime.image_digest:
            if request.image_digest != self.runtime.image_digest:
                blocked.append("image_identity_mismatch")
        cred = self.credentials.readiness()
        if not cred.get("available"):
            blocked.append("credential_provider_unavailable")
        net = self.network.readiness()
        acceptable_net = {"READY", "READY_FIXTURE", "READY_FOR_OWNER_PROBE"}
        if net.get("status") not in acceptable_net:
            blocked.append("egress_enforcement_unavailable")
        if net.get("enforcement") == "NOT_ENFORCED" and net.get("status") != "READY_FIXTURE":
            blocked.append("egress_not_enforced")
        if isinstance(self.network, PastaAllowlistEgressPolicy):
            blocked.append("pasta_policy_rejected_use_uds_broker")
        egress = self.network.evaluate("api.cursor.com")
        if not egress.allowed and net.get("status") != "READY_FIXTURE":
            blocked.append("cursor_egress_denied")
        if self.network.evaluate("1.2.3.4").allowed:
            blocked.append("ip_literal_bypass_possible")
        if self.auth_verifier is None:
            blocked.append("runtime_authorization_missing")
        if request.deny_untrusted_tools is False:
            blocked.append("untrusted_tools_must_be_denied_until_credential_isolation")
        blocked.append("live_cursor_requires_owner_triple_gate")
        proxy_diag = cursor_proxy_compatibility()
        if proxy_diag.get("live_blocked_until_owner_probe"):
            blocked.append("cursor_proxy_compatibility_not_owner_probed")

        network_args: List[str] = ["--network", "none"]
        if isinstance(self.network, UdsBrokerEgressPolicy):
            network_args = self.network.podman_network_args()
        elif request.network_mode and request.network_mode != "none":
            blocked.append("non_none_network_forbidden_without_verified_enforcement")

        broker_fragment: Dict[str, Any] = {}
        if request.broker_socket_host_path and request.relay_host_path:
            broker_fragment = broker_podman_args(
                socket_host_path=request.broker_socket_host_path,
                relay_host_path=request.relay_host_path,
            )
            network_args = list(broker_fragment["network_args"])

        argv: List[str] = []
        try:
            argv = build_cursor_podman_argv(
                image_ref=request.image_ref,
                container_name=f"eos-cursor-{request.execution_id[-12:]}",
                workspace_host_path=request.workspace_host_path,
                acp_argv=request.acp_argv,
                memory_limit=request.memory_limit,
                cpu_limit=request.cpu_limit,
                pids_limit=request.pids_limit,
                network_args=network_args,
            )
            for mount in broker_fragment.get("mounts") or []:
                # Insert mounts before image ref.
                img_idx = argv.index(request.image_ref)
                argv[img_idx:img_idx] = ["--mount", mount]
            for key, value in (broker_fragment.get("env") or {}).items():
                img_idx = argv.index(request.image_ref)
                argv[img_idx:img_idx] = ["-e", f"{key}={value}"]
        except OciProcessError as exc:
            blocked.append(str(exc))

        controls = {
            "read_only_root": True,
            "host_network": False,
            "network_none": True,
            "cap_drop_all": True,
            "no_new_privileges": True,
            "pull_never": True,
            "secrets_not_in_argv": True,
            "workspace_bind_ro": True,
            "auto_update_disabled": True,
            "deny_untrusted_tools": bool(request.deny_untrusted_tools),
            "smoke_mode": request.smoke_mode,
            "credential_env_not_isolated_from_peers": True,
            "broker_mounts": bool(broker_fragment),
        }
        mode = "BLOCKED" if blocked else "PLANNED"
        return CursorLaunchPlan(
            argv=argv,
            env_keys=[
                "CURSOR_API_KEY",
                "HOME",
                "PATH",
                "CURSOR_DISABLE_AUTO_UPDATE",
                "HTTPS_PROXY",
                "HTTP_PROXY",
                "EOS_DENY_UNTRUSTED_TOOLS",
            ],
            controls=controls,
            blocked_reasons=sorted(set(blocked)),
            mode=mode,
            image_ref=request.image_ref,
            image_digest=request.image_digest,
        )

    def dry_run(self, request: CursorLaunchRequest) -> Dict[str, Any]:
        plan = self.plan(request)
        return {
            "action": "dry_run",
            "plan": plan.to_dict(),
            "started": False,
            "live_cursor_acp": False,
            "evidence_class": SYNTHETIC_IN_MEMORY,
            "launch_eligible": plan.mode == "PLANNED" and self.sandbox_gate == "PASS",
        }

    def launch(
        self,
        request: CursorLaunchRequest,
        *,
        authorization: Optional[RuntimeAuthorization] = None,
        execute: bool = False,
        allow_phase_b: bool = False,
        owner_authorize_runtime_execution: bool = False,
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        if dry_run or not execute:
            return self.dry_run(request)

        require_owner_execution_gates(
            execute=execute,
            allow_phase_b=allow_phase_b,
            owner_authorize_runtime_execution=owner_authorize_runtime_execution,
        )
        if self.sandbox_gate != "PASS":
            raise AuthorizationError(
                "sandbox_gate_not_pass", code="sandbox_gate"
            )
        if authorization is None or self.auth_verifier is None:
            raise AuthorizationError(
                "runtime_authorization_required", code="auth_required"
            )

        cmd_profile = " ".join(request.acp_argv)
        self.auth_verifier.verify(
            authorization,
            execution_id=request.execution_id,
            project_id=request.project_id,
            workspace_id=request.workspace_id,
            agent_id="cursor",
            image_digest=request.image_digest,
            network_mode=request.network_mode,
            cpu_limit=request.cpu_limit,
            memory_limit=request.memory_limit,
            pids_limit=request.pids_limit,
            task_id=request.task_id,
            credential_provider_id=request.credential_provider_id
            or self.credentials.provider_id,
            acp_command_profile=cmd_profile,
            network_policy_id=request.network_policy_id
            or getattr(self.network, "policy_id", ""),
        )

        plan = self.plan(request)
        # After auth, still refuse if plan has structural blockers other than
        # the informational gate notes that are cleared by Owner path.
        structural = [
            b
            for b in plan.blocked_reasons
            if b
            not in {
                "sandbox_gate_not_pass",
                "sandbox_gate_pass_insufficient_without_host_auth",
                "live_cursor_requires_owner_triple_gate",
            }
        ]
        if structural and not self.process_factory:
            raise AuthorizationError(
                f"launch_blocked:{','.join(structural)}", code="blocked"
            )

        lease = self.credentials.lease(execution_id=request.execution_id)
        env = self.credentials.materialize_env(lease)
        self.last_lease = lease
        # Never log env values.
        env_keys = sorted(env.keys())

        if self.process_factory:
            handle = self.process_factory(request)
            evidence = SYNTHETIC_IN_MEMORY
            mode = "INJECTED"
        else:
            if not self.allow_real_podman:
                self.credentials.revoke(lease)
                if self.auth_verifier:
                    self.auth_verifier.release_inflight(request.execution_id)
                raise AuthorizationError(
                    "real_podman_disabled", code="podman_disabled"
                )
            handle = self._spawn(plan, request, env)
            evidence = CURSOR_ACP_LIVE
            mode = "PODMAN_CURSOR"

        self.last_handle = handle
        return {
            "action": "started",
            "started": True,
            "mode": mode,
            "plan": plan.to_dict(),
            "container_id": handle.container_id,
            "evidence_class": evidence,
            "credential_lease": lease.to_dict(),
            "env_keys": env_keys,
            "authorization_id": authorization.authorization_id,
            "started_at": utc_now(),
            "live_cursor_acp": evidence == CURSOR_ACP_LIVE,
            "note": redact_secrets(
                "Cursor ACP launched; secrets not present in this record"
            ),
        }

    def _spawn(
        self,
        plan: CursorLaunchPlan,
        request: CursorLaunchRequest,
        env: Dict[str, str],
    ) -> SubprocessOciHandle:
        import os

        full_env = {**os.environ, **env}
        # Strip potentially confusing proxy vars so pasta path is authoritative.
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"):
            full_env.pop(k, None)
        name = f"eos-cursor-{request.execution_id[-12:]}"
        handle, _ = SubprocessOciHandle.start_podman(
            plan.argv,
            container_name=name,
            env=full_env,
            grace_seconds=self.grace_seconds,
        )
        return handle


def default_cursor_injected_factory(scenario: str = "success") -> ProcessFactory:
    def factory(request: CursorLaunchRequest) -> OciProcessHandle:
        return InjectedFixtureProcess(
            scenario=scenario,
            container_id=f"cursor-injected-{request.execution_id[-8:]}",
        )

    return factory
