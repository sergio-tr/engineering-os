"""SQLite persistence package for the Engineering OS control plane."""

from engineering_os.infrastructure.persistence.sqlite.errors import ConcurrencyError
from engineering_os.infrastructure.persistence.sqlite.facade import Repository
from engineering_os.infrastructure.persistence.sqlite.paths import default_db_path
from engineering_os.infrastructure.persistence.sqlite.schema import SCHEMA

__all__ = [
    "SCHEMA",
    "ConcurrencyError",
    "Repository",
    "default_db_path",
]