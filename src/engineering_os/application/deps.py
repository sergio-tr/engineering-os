"""Typed dependency bundles for the control plane composition root."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from engineering_os.config import ControlPlaneConfiguration
from engineering_os.ports.authorization import OwnerDecisionPort
from engineering_os.ports.coordination import CoordinatorPort
from engineering_os.ports.evidence import EvidencePort
from engineering_os.ports.execution import ExecutionPort
from engineering_os.ports.persistence import ControlPlaneStorePort
from engineering_os.ports.repository_integration import RepositoryIntegrationPort


@dataclass(frozen=True)
class ControlPlaneDependencies:
    """Explicit injectable collaborators. Built only by the composition root.

    Persistence and core adapters are typed as ports. Concrete Cursor/OCI/ACP
    bridges are opaque objects constructed in bootstrap (not imported here).
    """

    repo: ControlPlaneStorePort
    config: ControlPlaneConfiguration
    synthetic: ExecutionPort
    live: ExecutionPort
    evidence: EvidencePort
    repo_integration: RepositoryIntegrationPort
    approval_provider: OwnerDecisionPort
    openclaw: CoordinatorPort
    acp: Any
    gateway: Any
    acpx: Any
    oci: Any
    cursor: Any
    github_transport: Optional[Any] = None
    github_token_provider: Optional[Callable[[], Optional[str]]] = None
    paperclip_transport: Optional[Any] = None
    paperclip_token_provider: Optional[Callable[[], Optional[str]]] = None
