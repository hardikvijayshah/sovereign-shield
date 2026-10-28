"""Tests for durable, rate-bounded scheduled scan definitions."""

from __future__ import annotations

import json

import pytest

from sovereign_shield.models.contracts import ScanRequest
from sovereign_shield.services.scheduling import (
    DynamoDBScheduleStore,
    EventBridgeSchedulerClient,
    InMemoryScheduleStore,
    ScheduleService,
    validate_schedule_expression,
)


def _request() -> ScanRequest:
    return ScanRequest(
        scan_regions=["eu-central-1"],
        services=["s3"],
        regulations=["gdpr"],
        idempotency_key="schedule-request-001",
    )


class _Scheduler:
    def __init__(self) -> None:
        self.upserts = []
        self.deleted = []

    def upsert(self, schedule):
        self.upserts.append(schedule)
        return f"arn:aws:scheduler:eu-central-1:123:schedule/group/{schedule.schedule_id}"

    def delete(self, schedule_id):
        self.deleted.append(schedule_id)


def test_schedule_service_persists_and_updates_explicitly_enabled_schedule():
    scheduler = _Scheduler()
    store = InMemoryScheduleStore()
    service = ScheduleService(store=store, scheduler=scheduler)

    created = service.create(
        name="Daily GDPR scan",
        schedule_expression="rate(1 day)",
        request=_request(),
        requester_subject="admin-123",
    )
    updated = service.update(created.schedule_id, enabled=False)

    assert created.scheduler_arn
    assert updated.enabled is False
    assert len(scheduler.upserts) == 2
    assert store.get(created.schedule_id).enabled is False


def test_schedule_service_deletes_the_scheduler_target_and_record():
    scheduler = _Scheduler()
    store = InMemoryScheduleStore()
    service = ScheduleService(store=store, scheduler=scheduler)
    created = service.create(name="Daily", schedule_expression="cron(0 6 * * ? *)", request=_request())

    service.delete(created.schedule_id)

    assert scheduler.deleted == [created.schedule_id]
    assert store.get(created.schedule_id) is None


@pytest.mark.parametrize("expression", ["rate(1 minute)", "rate(30 minutes)", "every day", "cron(0 6 * * *)"])
def test_schedule_expression_rejects_invalid_or_excessive_frequency(expression):
    with pytest.raises(ValueError):
        validate_schedule_expression(expression)


def test_eventbridge_scheduler_targets_only_the_approved_state_machine():
    class Client:
        def __init__(self) -> None:
            self.created = {}
            self.updated = {}

        def create_schedule(self, **kwargs):
            self.created = kwargs
            return {"ScheduleArn": "arn:aws:scheduler:eu-central-1:123:schedule/group/schedule"}

        def update_schedule(self, **kwargs):
            self.updated = kwargs

    client = Client()
    adapter = EventBridgeSchedulerClient(
        client=client,
        schedule_group_name="sovereign-shield",
        state_machine_arn="arn:aws:states:eu-central-1:123:stateMachine:scan",
        scheduler_role_arn="arn:aws:iam::123:role/scheduler",
    )
    schedule = ScheduleService(store=InMemoryScheduleStore(), scheduler=adapter).create(
        name="Daily",
        schedule_expression="rate(1 day)",
        request=_request(),
    )

    assert client.created["Target"]["Arn"].endswith(":stateMachine:scan")
    assert json.loads(client.created["Target"]["Input"]) == {"scheduleId": schedule.schedule_id}


def test_dynamodb_schedule_store_uses_stable_schedule_keys():
    class Table:
        def __init__(self) -> None:
            self.items = {}

        def put_item(self, *, Item, ConditionExpression):
            self.items[(Item["pk"], Item["sk"])] = Item

        def get_item(self, *, Key):
            item = self.items.get((Key["pk"], Key["sk"]))
            return {"Item": item} if item else {}

        def delete_item(self, *, Key, ConditionExpression):
            del self.items[(Key["pk"], Key["sk"])]

    scheduler = _Scheduler()
    table = Table()
    service = ScheduleService(store=DynamoDBScheduleStore(runs_table=table), scheduler=scheduler)
    created = service.create(name="Daily", schedule_expression="rate(1 day)", request=_request())

    assert ("SCHEDULE#" + created.schedule_id, "SCHEDULE") in table.items
