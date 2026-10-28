"""Durable, bounded EventBridge Scheduler definitions for scan runs."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Protocol

from sovereign_shield.models.contracts import ScanRequest, ScanSchedule
from sovereign_shield.services.scan_lifecycle import query_entities, request_fingerprint

_RATE_PATTERN = re.compile(r"^rate\((\d+)\s+(minute|minutes|hour|hours|day|days)\)$")
_CRON_PATTERN = re.compile(r"^cron\(([^()\s]+\s+){5}[^()\s]+\)$")


class ScheduleStore(Protocol):
    """Persistence boundary for customer-owned schedule definitions."""

    def create(self, schedule: ScanSchedule) -> None:
        """Create a schedule once."""

    def get(self, schedule_id: str) -> ScanSchedule | None:
        """Load a schedule by its durable ID."""

    def save(self, schedule: ScanSchedule) -> None:
        """Update an existing schedule."""

    def delete(self, schedule_id: str) -> None:
        """Remove an existing schedule record."""

    def list_recent(self, *, limit: int, cursor: str | None = None) -> tuple[list[ScanSchedule], str | None]:
        """Return a newest-first page of schedules."""


class SchedulerClient(Protocol):
    """Minimal EventBridge Scheduler authority used by schedule management."""

    def upsert(self, schedule: ScanSchedule) -> str:
        """Create or update the AWS schedule and return its ARN."""

    def delete(self, schedule_id: str) -> None:
        """Delete the named AWS schedule."""


class InMemoryScheduleStore:
    """Deep-copying local/test schedule store."""

    def __init__(self) -> None:
        self._schedules: dict[str, ScanSchedule] = {}

    def create(self, schedule: ScanSchedule) -> None:
        if schedule.schedule_id in self._schedules:
            raise ValueError(f"Schedule already exists: {schedule.schedule_id}")
        self._schedules[schedule.schedule_id] = schedule.model_copy(deep=True)

    def get(self, schedule_id: str) -> ScanSchedule | None:
        schedule = self._schedules.get(schedule_id)
        return schedule.model_copy(deep=True) if schedule else None

    def save(self, schedule: ScanSchedule) -> None:
        if schedule.schedule_id not in self._schedules:
            raise KeyError(f"Unknown schedule: {schedule.schedule_id}")
        self._schedules[schedule.schedule_id] = schedule.model_copy(deep=True)

    def delete(self, schedule_id: str) -> None:
        if schedule_id not in self._schedules:
            raise KeyError(f"Unknown schedule: {schedule_id}")
        del self._schedules[schedule_id]

    def list_recent(self, *, limit: int, cursor: str | None = None) -> tuple[list[ScanSchedule], str | None]:
        schedules = sorted(self._schedules.values(), key=lambda schedule: schedule.created_at, reverse=True)
        start = int(cursor or 0)
        page = [schedule.model_copy(deep=True) for schedule in schedules[start : start + limit]]
        next_index = start + len(page)
        return page, (str(next_index) if next_index < len(schedules) else None)


class DynamoDBScheduleStore:
    """DynamoDB schedule adapter using `SCHEDULE#<id>` partition keys."""

    def __init__(self, *, runs_table: Any) -> None:
        self._runs_table = runs_table

    def create(self, schedule: ScanSchedule) -> None:
        self._runs_table.put_item(
            Item=_schedule_item(schedule),
            ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
        )

    def get(self, schedule_id: str) -> ScanSchedule | None:
        response = self._runs_table.get_item(Key={"pk": f"SCHEDULE#{schedule_id}", "sk": "SCHEDULE"})
        item = response.get("Item")
        return ScanSchedule.model_validate(item) if item else None

    def save(self, schedule: ScanSchedule) -> None:
        self._runs_table.put_item(
            Item=_schedule_item(schedule),
            ConditionExpression="attribute_exists(pk) AND attribute_exists(sk)",
        )

    def delete(self, schedule_id: str) -> None:
        self._runs_table.delete_item(
            Key={"pk": f"SCHEDULE#{schedule_id}", "sk": "SCHEDULE"},
            ConditionExpression="attribute_exists(pk) AND attribute_exists(sk)",
        )

    def list_recent(self, *, limit: int, cursor: str | None = None) -> tuple[list[ScanSchedule], str | None]:
        items, next_cursor = query_entities(self._runs_table, "scan_schedule", limit=limit, cursor=cursor)
        return [ScanSchedule.model_validate(item) for item in items], next_cursor


class EventBridgeSchedulerClient:
    """Boto3-compatible adapter that starts only the approved state machine."""

    def __init__(
        self,
        *,
        client: Any,
        schedule_group_name: str,
        state_machine_arn: str,
        scheduler_role_arn: str,
    ) -> None:
        self._client = client
        self._schedule_group_name = schedule_group_name
        self._state_machine_arn = state_machine_arn
        self._scheduler_role_arn = scheduler_role_arn

    def upsert(self, schedule: ScanSchedule) -> str:
        request = {
            "Name": _scheduler_name(schedule.schedule_id),
            "GroupName": self._schedule_group_name,
            "ScheduleExpression": schedule.schedule_expression,
            "FlexibleTimeWindow": {"Mode": "OFF"},
            "State": "ENABLED" if schedule.enabled else "DISABLED",
            "Target": {
                "Arn": self._state_machine_arn,
                "RoleArn": self._scheduler_role_arn,
                "Input": json.dumps({"scheduleId": schedule.schedule_id}, separators=(",", ":")),
            },
            "ActionAfterCompletion": "NONE",
        }
        if schedule.scheduler_arn:
            self._client.update_schedule(**request)
            return schedule.scheduler_arn
        response = self._client.create_schedule(**request)
        return str(response["ScheduleArn"])

    def delete(self, schedule_id: str) -> None:
        self._client.delete_schedule(
            Name=_scheduler_name(schedule_id),
            GroupName=self._schedule_group_name,
        )


class ScheduleService:
    """Creates, updates, disables, and deletes validated scan schedules."""

    def __init__(self, *, store: ScheduleStore, scheduler: SchedulerClient) -> None:
        self._store = store
        self._scheduler = scheduler

    def create(
        self,
        *,
        name: str,
        schedule_expression: str,
        request: ScanRequest,
        requester_subject: str = "",
        enabled: bool = True,
    ) -> ScanSchedule:
        validate_schedule_expression(schedule_expression)
        schedule = ScanSchedule(
            name=name.strip(),
            schedule_expression=schedule_expression.strip(),
            request=request,
            request_fingerprint=request_fingerprint(request),
            requester_subject=requester_subject,
            enabled=enabled,
        )
        self._store.create(schedule)
        try:
            scheduler_arn = self._scheduler.upsert(schedule)
        except Exception:
            self._store.delete(schedule.schedule_id)
            raise
        saved = _replace(schedule, scheduler_arn=scheduler_arn)
        self._store.save(saved)
        return saved

    def update(
        self,
        schedule_id: str,
        *,
        schedule_expression: str | None = None,
        request: ScanRequest | None = None,
        enabled: bool | None = None,
    ) -> ScanSchedule:
        current = self._required(schedule_id)
        expression = schedule_expression.strip() if schedule_expression is not None else current.schedule_expression
        validate_schedule_expression(expression)
        updated_request = request or current.request
        updated = _replace(
            current,
            schedule_expression=expression,
            request=updated_request,
            request_fingerprint=request_fingerprint(updated_request),
            enabled=current.enabled if enabled is None else enabled,
        )
        scheduler_arn = self._scheduler.upsert(updated)
        saved = _replace(updated, scheduler_arn=scheduler_arn)
        self._store.save(saved)
        return saved

    def delete(self, schedule_id: str) -> None:
        self._required(schedule_id)
        self._scheduler.delete(schedule_id)
        self._store.delete(schedule_id)

    def list_recent(self, *, limit: int, cursor: str | None = None) -> tuple[list[ScanSchedule], str | None]:
        """Return a newest-first page of schedule definitions."""

        return self._store.list_recent(limit=limit, cursor=cursor)

    def get(self, schedule_id: str) -> ScanSchedule:
        """Return a schedule definition for an authorized API response."""

        return self._required(schedule_id)

    def _required(self, schedule_id: str) -> ScanSchedule:
        schedule = self._store.get(schedule_id)
        if schedule is None:
            raise KeyError(f"Unknown schedule: {schedule_id}")
        return schedule


def validate_schedule_expression(expression: str) -> None:
    """Allow EventBridge cron or rate expressions no more frequent than hourly."""

    match = _RATE_PATTERN.fullmatch(expression.strip())
    if match:
        count = int(match.group(1))
        unit = match.group(2)
        if (unit.startswith("minute") and count < 60) or count < 1:
            raise ValueError("Scheduled scans may run no more frequently than once per hour.")
        return
    if _CRON_PATTERN.fullmatch(expression.strip()):
        return
    raise ValueError("Schedule expression must be a valid EventBridge rate or six-field cron expression.")


def _replace(schedule: ScanSchedule, **changes: Any) -> ScanSchedule:
    return schedule.model_copy(update={**changes, "updated_at": datetime.now(timezone.utc)})


def _scheduler_name(schedule_id: str) -> str:
    return f"sovereign-shield-{schedule_id}"


def _schedule_item(schedule: ScanSchedule) -> dict[str, Any]:
    return {
        "pk": f"SCHEDULE#{schedule.schedule_id}",
        "sk": "SCHEDULE",
        "entity_type": "scan_schedule",
        **schedule.model_dump(mode="json"),
    }
