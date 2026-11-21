"""Composition root — the only place that wires concrete infrastructure."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Optional
import os

from engineering_os.application.deps import ControlPlaneDependencies
from engineering_os.config import ControlPlaneConfiguration
from engineering_os.infrastructure.adapters import (
    DisabledLiveExecutionAdapter,
    LocalEvidenceAdapter,
    LocalOwnerDecisionProvider,
    SimulatedRepositoryIntegrationAdapter,
    SyntheticExecutionAdapter,
)
from engineering_os.infrastructure.acp_adapter import AcpExecutionAdapter
from engineering_os.infrastructure.acpx_bridge import AcpxSandboxBridge
from engineering_os.infrastructure.credential_provider import (
    UnavailableCursorCredentialProvider,
)
from engineering_os.infrastructure.cursor_bridge import CursorBridge
from engineering_os.infrastructure.cursor_runtime import CursorRuntimePlanner
from engineering_os.infrastructure.gateway_client import (
    OpenClawGatewayClient,
    default_gateway_client,
)
from engineering_os.infrastructure.github_client import DEFAULT_API_BASE, HttpTransport
from engineering_os.infrastructure.network_policy import UnenforcedNetworkPolicy
from engineering_os.infrastructure.openclaw_adapter import OpenClawCoordinatorAdapter
from engineering_os.infrastructure.openclaw_client import OpenClawCliClient
from engineering_os.infrastructure.paperclip_client import DEFAULT_PAPERCLIP_URL
from engineering_os.infrastructure.podman_executor import (
    PodmanSandboxExecutor,
    default_injected_factory,
)
from engineering_os.infrastructure.sandbox_launcher import PodmanAcpSandboxLauncher
from engineering_os.infrastructure.sqlite_repo import Repository, default_db_path
from engineering_os.infrastructure.workspace_prep import WorkspacePreparer


def build_dependencies(
    repo: Repository,
    *,
    config: Optional[ControlPlaneConfiguration] = None,
    execution_adapter: Optional[Any] = None,
    live_adapter: Optional[Any] = None,
    evidence: Optional[LocalEvidenceAdapter] = None,
    repo_integration: Optional[SimulatedRepositoryIntegrationAdapter] = None,
    approval_provider: Optional[LocalOwnerDecisionProvider] = None,
    github_transport: Optional[HttpTransport] = None,
    github_token_provider: Optional[Callable[[], Optional[str]]] = None,
    paperclip_transport: Optional[HttpTransport] = None,
    paperclip_token_provider: Optional[Callable[[], Optional[str]]] = None,
    openclaw_client: Optional[OpenClawCliClient] = None,
    gateway_client: Optional[OpenClawGatewayClient] = None,
    acpx_bridge: Optional[AcpxSandboxBridge] = None,
    oci_executor: Optional[PodmanSandboxExecutor] = None,
    cursor_bridge: Optional[CursorBridge] = None,
) -> ControlPlaneDependencies:
    """Wire concrete adapters. Prefer this over constructing clients inside use cases."""
    cfg = config or ControlPlaneConfiguration(
        sandbox_gate="NOT_TESTED",
        max_attempts=3,
        acp_scenario="success",
        github_api_base=DEFAULT_API_BASE,
        paperclip_url=os.environ.get("EOS_PAPERCLIP_URL") or DEFAULT_PAPERCLIP_URL,
        paperclip_company_id=os.environ.get("EOS_PAPERCLIP_COMPANY_ID"),
    )
    gateway = gateway_client or default_gateway_client()
    acpx = acpx_bridge or AcpxSandboxBridge(
        repo,
        gateway=gateway,
        sandbox=PodmanAcpSandboxLauncher(),
        sandbox_gate=cfg.sandbox_gate,
    )
    oci = oci_executor or PodmanSandboxExecutor(
        process_factory=default_injected_factory("success"),
        allow_real_podman=False,
        code_revision="eos08-dev",
    )
    cursor = cursor_bridge or CursorBridge(
        repo,
        credentials=UnavailableCursorCredentialProvider(),
        network=UnenforcedNetworkPolicy(),
        workspace=WorkspacePreparer(),
        runtime=CursorRuntimePlanner(),
        sandbox_gate=cfg.sandbox_gate,
    )
    return ControlPlaneDependencies(
        repo=repo,
        config=cfg,
        synthetic=execution_adapter or SyntheticExecutionAdapter(),
        live=live_adapter or DisabledLiveExecutionAdapter(),
        evidence=evidence or LocalEvidenceAdapter(),
        repo_integration=repo_integration or SimulatedRepositoryIntegrationAdapter(),
        approval_provider=approval_provider or LocalOwnerDecisionProvider(),
        openclaw=OpenClawCoordinatorAdapter(client=openclaw_client),
        acp=AcpExecutionAdapter(
            repo,
            sandbox_gate=cfg.sandbox_gate,
            synthetic_scenario=cfg.acp_scenario,
        ),
        gateway=gateway,
        acpx=acpx,
        oci=oci,
        cursor=cursor,
        github_transport=github_transport,
        github_token_provider=github_token_provider
        or (lambda: os.environ.get("EOS_GITHUB_TOKEN") or None),
        paperclip_transport=paperclip_transport,
        paperclip_token_provider=paperclip_token_provider
        or (lambda: os.environ.get("EOS_PAPERCLIP_TOKEN") or None),
    )


def open_control_plane(db_path: Optional[str | Path] = None, **kwargs: Any) -> Any:
    """Open SQLite and return a ControlPlane facade (lazy import avoids cycles)."""
    from engineering_os.application.services import ControlPlane

    path = Path(db_path) if db_path else default_db_path()
    repo = Repository(path)
    deps = build_dependencies(repo, **kwargs)
    return ControlPlane.from_dependencies(deps)
