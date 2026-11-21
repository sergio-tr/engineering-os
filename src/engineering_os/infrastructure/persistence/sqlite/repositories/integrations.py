"""SQLite persistence for integrations."""

from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional, Sequence

from engineering_os.domain.models import dumps_json, loads_json, utc_now
from engineering_os.infrastructure.persistence.sqlite.connection import SqliteDatabase
from engineering_os.infrastructure.persistence.sqlite.errors import ConcurrencyError


class SqliteIntegrationRepository:
    def __init__(self, db: SqliteDatabase) -> None:
        self.db = db

    def upsert_github_connection(self, data: Dict[str, Any]) -> Dict[str, Any]:
        now = utc_now()
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO github_connections(
                  project_id, owner, repo, repository_identity, api_base,
                  default_branch, head_sha, last_sync_at, last_error_json,
                  created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(project_id) DO UPDATE SET
                  owner=excluded.owner,
                  repo=excluded.repo,
                  repository_identity=excluded.repository_identity,
                  api_base=excluded.api_base,
                  default_branch=excluded.default_branch,
                  head_sha=excluded.head_sha,
                  last_sync_at=excluded.last_sync_at,
                  last_error_json=excluded.last_error_json,
                  updated_at=excluded.updated_at
                """,
                (
                    data["project_id"],
                    data["owner"],
                    data["repo"],
                    data["repository_identity"],
                    data.get("api_base") or "https://api.github.com",
                    data.get("default_branch"),
                    data.get("head_sha"),
                    data.get("last_sync_at"),
                    dumps_json(data.get("last_error")),
                    data.get("created_at") or now,
                    now,
                ),
            )
        return self.get_github_connection(data["project_id"])  # type: ignore[return-value]


    def get_github_connection(self, project_id: str) -> Optional[Dict[str, Any]]:
        row = self.db.fetchone(
            "SELECT * FROM github_connections WHERE project_id=?", (project_id,)
        )
        return self._row_github_connection(row) if row else None


    def list_github_connections(self) -> List[Dict[str, Any]]:
        rows = self.db.fetchall(
            "SELECT * FROM github_connections ORDER BY updated_at DESC"
        )
        return [self._row_github_connection(r) for r in rows]


    def upsert_execution_pr_link(self, data: Dict[str, Any]) -> Dict[str, Any]:
        now = utc_now()
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO execution_pr_links(
                  execution_id, project_id, repository_identity, pr_number,
                  expected_base_ref, expected_head_sha, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(execution_id) DO UPDATE SET
                  repository_identity=excluded.repository_identity,
                  pr_number=excluded.pr_number,
                  expected_base_ref=excluded.expected_base_ref,
                  expected_head_sha=excluded.expected_head_sha,
                  updated_at=excluded.updated_at
                """,
                (
                    data["execution_id"],
                    data["project_id"],
                    data["repository_identity"],
                    int(data["pr_number"]),
                    data.get("expected_base_ref"),
                    data.get("expected_head_sha"),
                    data.get("created_at") or now,
                    now,
                ),
            )
        return self.get_execution_pr_link(data["execution_id"])  # type: ignore[return-value]


    def get_execution_pr_link(self, execution_id: str) -> Optional[Dict[str, Any]]:
        row = self.db.fetchone(
            "SELECT * FROM execution_pr_links WHERE execution_id=?", (execution_id,)
        )
        return dict(row) if row else None


    def list_execution_pr_links(
        self, *, project_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        if project_id:
            rows = self.db.fetchall(
                "SELECT * FROM execution_pr_links WHERE project_id=? ORDER BY updated_at DESC",
                (project_id,),
            )
        else:
            rows = self.db.fetchall(
                "SELECT * FROM execution_pr_links ORDER BY updated_at DESC"
            )
        return [dict(r) for r in rows]


    def insert_github_observation(self, data: Dict[str, Any]) -> Dict[str, Any]:
        with self.db.transaction() as conn:
            # Mark previous observations for same target as stale.
            if data.get("execution_id"):
                conn.execute(
                    """
                    UPDATE github_observations SET stale=1
                    WHERE project_id=? AND execution_id=? AND stale=0
                    """,
                    (data["project_id"], data["execution_id"]),
                )
            elif data.get("pr_number") is not None:
                conn.execute(
                    """
                    UPDATE github_observations SET stale=1
                    WHERE project_id=? AND pr_number=? AND execution_id IS NULL AND stale=0
                    """,
                    (data["project_id"], data["pr_number"]),
                )
            else:
                conn.execute(
                    """
                    UPDATE github_observations SET stale=1
                    WHERE project_id=? AND pr_number IS NULL AND execution_id IS NULL AND stale=0
                    """,
                    (data["project_id"],),
                )
            conn.execute(
                """
                INSERT INTO github_observations(
                  observation_id, project_id, execution_id, repository_identity,
                  pr_number, evidence_class, payload_json, observed_at, stale
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    data["observation_id"],
                    data["project_id"],
                    data.get("execution_id"),
                    data["repository_identity"],
                    data.get("pr_number"),
                    data["evidence_class"],
                    dumps_json(data.get("payload") or {}),
                    data.get("observed_at") or utc_now(),
                ),
            )
        return self.get_github_observation(data["observation_id"])  # type: ignore[return-value]


    def get_github_observation(self, observation_id: str) -> Optional[Dict[str, Any]]:
        row = self.db.fetchone(
            "SELECT * FROM github_observations WHERE observation_id=?",
            (observation_id,),
        )
        return self._row_github_observation(row) if row else None


    def latest_github_observation(
        self,
        *,
        project_id: str,
        execution_id: Optional[str] = None,
        pr_number: Optional[int] = None,
        include_stale: bool = False,
    ) -> Optional[Dict[str, Any]]:
        clauses = ["project_id = ?"]
        params: List[Any] = [project_id]
        if execution_id:
            clauses.append("execution_id = ?")
            params.append(execution_id)
        if pr_number is not None:
            clauses.append("pr_number = ?")
            params.append(pr_number)
        if not include_stale:
            clauses.append("stale = 0")
        where = " AND ".join(clauses)
        row = self.db.fetchone(
            f"""
            SELECT * FROM github_observations
            WHERE {where}
            ORDER BY observed_at DESC, observation_id DESC
            LIMIT 1
            """,
            params,
        )
        return self._row_github_observation(row) if row else None


    def list_github_observations(
        self, *, project_id: str, limit: int = 50
    ) -> List[Dict[str, Any]]:
        rows = self.db.fetchall(
            """
            SELECT * FROM github_observations
            WHERE project_id=?
            ORDER BY observed_at DESC
            LIMIT ?
            """,
            (project_id, limit),
        )
        return [self._row_github_observation(r) for r in rows]


    def _row_github_connection(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "project_id": row["project_id"],
            "owner": row["owner"],
            "repo": row["repo"],
            "repository_identity": row["repository_identity"],
            "api_base": row["api_base"],
            "default_branch": row["default_branch"],
            "head_sha": row["head_sha"],
            "last_sync_at": row["last_sync_at"],
            "last_error": loads_json(row["last_error_json"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }


    def _row_github_observation(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "observation_id": row["observation_id"],
            "project_id": row["project_id"],
            "execution_id": row["execution_id"],
            "repository_identity": row["repository_identity"],
            "pr_number": row["pr_number"],
            "evidence_class": row["evidence_class"],
            "payload": dict(loads_json(row["payload_json"]) or {}),
            "observed_at": row["observed_at"],
            "stale": bool(row["stale"]),
        }


    def upsert_external_mapping(self, data: Dict[str, Any]) -> Dict[str, Any]:
        now = utc_now()
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO external_identity_mappings(
                  mapping_id, system_name, company_id, local_kind, local_id,
                  external_id, external_revision, correlation_id, last_sync_at,
                  evidence_class, payload_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(system_name, local_kind, local_id) DO UPDATE SET
                  company_id=excluded.company_id,
                  external_id=excluded.external_id,
                  external_revision=excluded.external_revision,
                  correlation_id=excluded.correlation_id,
                  last_sync_at=excluded.last_sync_at,
                  evidence_class=excluded.evidence_class,
                  payload_json=excluded.payload_json,
                  updated_at=excluded.updated_at
                """,
                (
                    data.get("mapping_id") or data["local_id"],
                    data["system_name"],
                    data.get("company_id"),
                    data["local_kind"],
                    data["local_id"],
                    data["external_id"],
                    data.get("external_revision"),
                    data.get("correlation_id"),
                    data.get("last_sync_at") or now,
                    data["evidence_class"],
                    dumps_json(data.get("payload") or {}),
                    data.get("created_at") or now,
                    now,
                ),
            )
        return self.get_external_mapping(
            data["system_name"], data["local_kind"], data["local_id"]
        )  # type: ignore[return-value]


    def get_external_mapping(
        self, system_name: str, local_kind: str, local_id: str
    ) -> Optional[Dict[str, Any]]:
        row = self.db.fetchone(
            """
            SELECT * FROM external_identity_mappings
            WHERE system_name=? AND local_kind=? AND local_id=?
            """,
            (system_name, local_kind, local_id),
        )
        return self._row_external_mapping(row) if row else None


    def list_external_mappings(
        self,
        *,
        system_name: Optional[str] = None,
        company_id: Optional[str] = None,
        local_kind: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        clauses: List[str] = []
        params: List[Any] = []
        if system_name:
            clauses.append("system_name = ?")
            params.append(system_name)
        if company_id:
            clauses.append("company_id = ?")
            params.append(company_id)
        if local_kind:
            clauses.append("local_kind = ?")
            params.append(local_kind)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self.db.fetchall(
            f"SELECT * FROM external_identity_mappings {where} ORDER BY updated_at DESC",
            params,
        )
        return [self._row_external_mapping(r) for r in rows]


    def _row_external_mapping(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "mapping_id": row["mapping_id"],
            "system_name": row["system_name"],
            "company_id": row["company_id"],
            "local_kind": row["local_kind"],
            "local_id": row["local_id"],
            "external_id": row["external_id"],
            "external_revision": row["external_revision"],
            "correlation_id": row["correlation_id"],
            "last_sync_at": row["last_sync_at"],
            "evidence_class": row["evidence_class"],
            "payload": dict(loads_json(row["payload_json"]) or {}),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }


    def insert_integration_observation(self, data: Dict[str, Any]) -> Dict[str, Any]:
        with self.db.transaction() as conn:
            conn.execute(
                """
                UPDATE integration_observations SET stale=1
                WHERE system_name=? AND IFNULL(project_id,'')=IFNULL(?, '')
                  AND IFNULL(company_id,'')=IFNULL(?, '') AND stale=0
                """,
                (
                    data["system_name"],
                    data.get("project_id"),
                    data.get("company_id"),
                ),
            )
            conn.execute(
                """
                INSERT INTO integration_observations(
                  observation_id, system_name, project_id, company_id,
                  evidence_class, payload_json, observed_at, stale
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    data["observation_id"],
                    data["system_name"],
                    data.get("project_id"),
                    data.get("company_id"),
                    data["evidence_class"],
                    dumps_json(data.get("payload") or {}),
                    data.get("observed_at") or utc_now(),
                ),
            )
        return self.get_integration_observation(data["observation_id"])  # type: ignore[return-value]


    def get_integration_observation(
        self, observation_id: str
    ) -> Optional[Dict[str, Any]]:
        row = self.db.fetchone(
            "SELECT * FROM integration_observations WHERE observation_id=?",
            (observation_id,),
        )
        return self._row_integration_observation(row) if row else None


    def latest_integration_observation(
        self,
        *,
        system_name: str,
        project_id: Optional[str] = None,
        company_id: Optional[str] = None,
        include_stale: bool = False,
    ) -> Optional[Dict[str, Any]]:
        clauses = ["system_name = ?"]
        params: List[Any] = [system_name]
        if project_id is not None:
            clauses.append("project_id = ?")
            params.append(project_id)
        if company_id is not None:
            clauses.append("company_id = ?")
            params.append(company_id)
        if not include_stale:
            clauses.append("stale = 0")
        row = self.db.fetchone(
            f"""
            SELECT * FROM integration_observations
            WHERE {' AND '.join(clauses)}
            ORDER BY observed_at DESC LIMIT 1
            """,
            params,
        )
        return self._row_integration_observation(row) if row else None


    def _row_integration_observation(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "observation_id": row["observation_id"],
            "system_name": row["system_name"],
            "project_id": row["project_id"],
            "company_id": row["company_id"],
            "evidence_class": row["evidence_class"],
            "payload": dict(loads_json(row["payload_json"]) or {}),
            "observed_at": row["observed_at"],
            "stale": bool(row["stale"]),
        }

