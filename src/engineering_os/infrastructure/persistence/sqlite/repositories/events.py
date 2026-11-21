"""SQLite persistence for events."""

from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional, Sequence

from engineering_os.domain.models import dumps_json, loads_json, utc_now
from engineering_os.infrastructure.persistence.sqlite.connection import SqliteDatabase
from engineering_os.infrastructure.persistence.sqlite.errors import ConcurrencyError
from engineering_os.domain.models import OperationalEvent


class SqliteEventRepository:
    def __init__(self, db: SqliteDatabase) -> None:
        self.db = db

    def append_event(self, event: OperationalEvent) -> OperationalEvent:
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO operational_events(
                  event_id, aggregate_type, aggregate_id, event_type,
                  correlation_id, payload_json, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.aggregate_type,
                    event.aggregate_id,
                    event.event_type,
                    event.correlation_id,
                    dumps_json(event.payload),
                    event.timestamp,
                ),
            )
        return event


    def list_events(
        self,
        *,
        limit: int = 100,
        aggregate_type: Optional[str] = None,
        aggregate_id: Optional[str] = None,
    ) -> List[OperationalEvent]:
        clauses: List[str] = []
        params: List[Any] = []
        if aggregate_type:
            clauses.append("aggregate_type = ?")
            params.append(aggregate_type)
        if aggregate_id:
            clauses.append("aggregate_id = ?")
            params.append(aggregate_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        rows = self.db.fetchall(
            f"""
            SELECT * FROM operational_events {where}
            ORDER BY timestamp ASC, event_id ASC LIMIT ?
            """,
            params,
        )
        return [self._row_event(r) for r in rows]


    def _row_event(self, row: sqlite3.Row) -> OperationalEvent:
        return OperationalEvent(
            event_id=row["event_id"],
            aggregate_type=row["aggregate_type"],
            aggregate_id=row["aggregate_id"],
            event_type=row["event_type"],
            correlation_id=row["correlation_id"],
            payload=dict(loads_json(row["payload_json"]) or {}),
            timestamp=row["timestamp"],
        )
