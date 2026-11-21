"""Goal use cases."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from engineering_os.application.use_cases.projects import ProjectService
from engineering_os.domain.models import Approval, Goal, OperationalEvent, new_id
from engineering_os.domain.states import GOAL_TRANSITIONS, assert_transition
from engineering_os.infrastructure.sqlite_repo import Repository


class GoalService:
    def __init__(
        self,
        repo: Repository,
        *,
        projects: ProjectService,
        emit: Callable[..., OperationalEvent],
    ) -> None:
        self._repo = repo
        self._projects = projects
        self._emit = emit

    def create(
        self,
        project_id: str,
        title: str,
        description: str = "",
        *,
        priority: int = 100,
    ) -> Goal:
        self._projects.get(project_id)
        goal = Goal(
            goal_id=new_id("goal"),
            project_id=project_id,
            title=title,
            description=description,
            priority=priority,
            approval_state="PENDING",
            lifecycle_state="DRAFT",
        )
        self._repo.insert_goal(goal)
        self._emit(
            aggregate_type="goal",
            aggregate_id=goal.goal_id,
            event_type="goal.created",
            payload=goal.to_dict(),
        )
        return goal

    def require(self, goal_id: str) -> Goal:
        goal = self._repo.get_goal(goal_id)
        if not goal:
            raise KeyError(f"unknown goal: {goal_id}")
        return goal

    def submit_for_approval(self, goal_id: str) -> Goal:
        goal = self.require(goal_id)
        assert_transition(
            "goal", goal.lifecycle_state, "PENDING_APPROVAL", GOAL_TRANSITIONS
        )
        version = goal.version
        goal.lifecycle_state = "PENDING_APPROVAL"
        goal = self._repo.update_goal(goal, expected_version=version)
        approval = Approval(
            approval_id=new_id("appr"),
            requested_action="approve_goal",
            scope=f"goal:{goal.goal_id}",
            approver_reference="owner-synthetic",
            decision="PENDING",
            expires_at=(datetime.now(timezone.utc) + timedelta(days=7))
            .replace(microsecond=0)
            .isoformat(),
            audit_metadata={"synthetic": True},
            goal_id=goal.goal_id,
            project_id=goal.project_id,
        )
        self._repo.insert_approval(approval)
        self._emit(
            aggregate_type="goal",
            aggregate_id=goal.goal_id,
            event_type="goal.pending_approval",
            payload={"approval_id": approval.approval_id},
        )
        return goal
