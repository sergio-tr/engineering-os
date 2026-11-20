"""Operational domain models (separate from canonical contract schemas)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import json
import uuid


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


@dataclass
class Project:
    project_id: str
    name: str
    repository_identity: str
    status: str = "ACTIVE"
    isolation_requirements: str = "synthetic-default-deny"
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)
    version: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Goal:
    goal_id: str
    project_id: str
    title: str
    description: str = ""
    priority: int = 100
    approval_state: str = "PENDING"
    lifecycle_state: str = "DRAFT"
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)
    version: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Task:
    task_id: str
    goal_id: str
    project_id: str
    description: str
    depends_on: List[str] = field(default_factory=list)
    assigned_agent_ref: str = "synthetic-agent"
    execution_eligible: bool = False
    lifecycle_state: str = "PLANNED"
    blocked_reason: Optional[str] = None
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)
    version: int = 1

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        return data


@dataclass
class Execution:
    execution_id: str
    task_id: str
    project_id: str
    execution_contract_ref: str
    runner_type: str
    attempt_number: int = 1
    status: str = "PREPARED"
    failure_reason: Optional[str] = None
    evidence_refs: List[str] = field(default_factory=list)
    idempotency_key: str = ""
    started_at: Optional[str] = None
    ended_at: Optional[str] = None
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)
    version: int = 1
    integration_state: Optional[str] = None
    synthetic: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Approval:
    approval_id: str
    requested_action: str
    scope: str
    approver_reference: str
    decision: str = "PENDING"
    expires_at: Optional[str] = None
    audit_metadata: Dict[str, Any] = field(default_factory=dict)
    goal_id: Optional[str] = None
    project_id: Optional[str] = None
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["audit_metadata"] = dict(self.audit_metadata)
        return data


@dataclass
class OperationalEvent:
    event_id: str
    aggregate_type: str
    aggregate_id: str
    event_type: str
    correlation_id: str
    payload: Dict[str, Any]
    timestamp: str = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "aggregate_type": self.aggregate_type,
            "aggregate_id": self.aggregate_id,
            "event_type": self.event_type,
            "correlation_id": self.correlation_id,
            "payload": self.payload,
            "timestamp": self.timestamp,
        }


def dumps_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def loads_json(text: str) -> Any:
    return json.loads(text) if text else None
