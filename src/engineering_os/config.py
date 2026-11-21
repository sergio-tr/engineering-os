"""Typed configuration value objects for Engineering OS."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ControlPlaneConfiguration:
    """Immutable control-plane settings (not a service locator)."""

    sandbox_gate: str = "NOT_TESTED"
    max_attempts: int = 3
    acp_scenario: str = "success"
    github_api_base: str = "https://api.github.com"
    paperclip_url: Optional[str] = None
    paperclip_company_id: Optional[str] = None


@dataclass(frozen=True)
class SandboxResourceLimits:
    memory_limit: str = "512m"
    cpu_limit: str = "1.0"
    pids_limit: int = 128


@dataclass(frozen=True)
class NetworkEgressConfig:
    network_mode: str = "none"
    network_policy_id: str = "uds-broker-network-none"
    broker_socket_host_path: str = ""
    relay_host_path: str = ""


@dataclass(frozen=True)
class WorkspaceIdentity:
    workspace_id: str
    host_path: str
    project_id: str
    execution_id: str


@dataclass(frozen=True)
class CursorSmokeRequest:
    execution_id: str
    project_id: str
    task_id: str
    workspace: WorkspaceIdentity
    execute: bool = False
    allow_phase_b: bool = False
    owner_authorize_runtime_execution: bool = False
    dry_run: bool = True
