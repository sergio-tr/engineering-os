"""Project use cases."""

from __future__ import annotations

from typing import Callable, List, Optional

from engineering_os.domain.models import OperationalEvent, Project, new_id
from engineering_os.infrastructure.sqlite_repo import Repository


class ProjectService:
    def __init__(
        self,
        repo: Repository,
        *,
        emit: Callable[..., OperationalEvent],
    ) -> None:
        self._repo = repo
        self._emit = emit

    def create(
        self, name: str, repository_identity: str, *, project_id: Optional[str] = None
    ) -> Project:
        project = Project(
            project_id=project_id or new_id("proj"),
            name=name,
            repository_identity=repository_identity,
        )
        self._repo.upsert_project(project)
        self._emit(
            aggregate_type="project",
            aggregate_id=project.project_id,
            event_type="project.created",
            payload=project.to_dict(),
        )
        return project

    def list(self) -> List[Project]:
        return self._repo.list_projects()

    def get(self, project_id: str) -> Project:
        project = self._repo.get_project(project_id)
        if not project:
            raise KeyError(f"unknown project: {project_id}")
        return project
