"""Typed dependency bundles for the control plane composition root."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from engineering_os.config import ControlPlaneConfiguration
from engineering_os.infrastructure.adapters import (
    ExecutionAdapter,
    LocalEvidenceAdapter,
    LocalOwnerDecisionProvider,
    SimulatedRepositoryIntegrationAdapter,
)
from engineering_os.infrastructure.acp_adapter import AcpExecutionAdapter
from engineering_os.infrastructure.acpx_bridge import AcpxSandboxBridge
from engineering_os.infrastructure.cursor_bridge import CursorBridge
from engineering_os.infrastructure.gateway_client import OpenClawGatewayClient
from engineering_os.infrastructure.openclaw_adapter import OpenClawCoordinatorAdapter
from engineering_os.infrastructure.podman_executor import PodmanSandboxExecutor
from engineering_os.infrastructure.sqlite_repo import Repository


@dataclass(frozen=True)
class ControlPlaneDependencies:
    """Explicit injectable collaborators. Built only by the composition root."""

    repo: Repository
    config: ControlPlaneConfiguration
    synthetic: ExecutionAdapter
    live: ExecutionAdapter
    evidence: LocalEvidenceAdapter
    repo_integration: SimulatedRepositoryIntegrationAdapter
    approval_provider: LocalOwnerDecisionProvider
    openclaw: OpenClawCoordinatorAdapter
    acp: AcpExecutionAdapter
    gateway: OpenClawGatewayClient
    acpx: AcpxSandboxBridge
    oci: PodmanSandboxExecutor
    cursor: CursorBridge
    github_transport: Optional[Any] = None
    github_token_provider: Optional[Callable[[], Optional[str]]] = None
    paperclip_transport: Optional[Any] = None
    paperclip_token_provider: Optional[Callable[[], Optional[str]]] = None
