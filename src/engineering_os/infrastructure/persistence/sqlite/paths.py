"""Default database path resolution."""

from __future__ import annotations

import os
from pathlib import Path


def default_db_path() -> Path:
    override = os.environ.get("EOS_DB_PATH")
    if override:
        return Path(override)
    base = Path(os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share"))
    return base / "engineering-os" / "control-plane.sqlite3"