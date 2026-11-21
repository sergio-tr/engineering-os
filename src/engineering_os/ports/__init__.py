"""Application ports (Protocols). Infrastructure adapters implement these."""

from engineering_os.ports.persistence import UnitOfWorkPort
from engineering_os.ports.execution import ExecutionPort
from engineering_os.ports.evidence import EvidencePort
from engineering_os.ports.authorization import OwnerDecisionPort

__all__ = [
    "UnitOfWorkPort",
    "ExecutionPort",
    "EvidencePort",
    "OwnerDecisionPort",
]
