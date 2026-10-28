"""Tests for asynchronous scan submission, lifecycle, and bounded work units."""

from __future__ import annotations

import json

import pytest

from sovereign_shield.models.contracts import ScanRequest, ScanSchedule, ScanService, ScanStatus
from sovereign_shield.services.scan_lifecycle import (
    DeterministicScanWorkflow,
    DynamoDBScanRunStore,
    IdempotencyConflictError,
    InMemoryScanRunStore,
    ScanCoordinator,
    ScheduleNotRunnableError,
    StepFunctionsWorkflowStarter,
    WorkflowStartError,
    admit_scheduled_run,
    mark_run_failed,
    plan_work_items,
    request_fingerprint,
)
from sovereign_shield.services.scan_store import InMemoryScanStore


class _WorkflowStarter:
    def __init__(self, failure: Exception | None = None) -> None:
        self.failure = failure
        self.calls: list[tuple[str, str]] = []

    def start(self, *, scan_run_id: str, correlation_id: str) -> str:
        self.calls.append((scan_run_id, correlation_id))
        if self.failure:
            raise self.failure
        return f"arn:aws:states:eu-central-1:123:execution:sovereign-shield:{scan_run_id}"


def _request(**changes) -> ScanRequest:
    payload = {
        "scan_regions": ["eu-central-1"],
        "services": [ScanService.S3],
        "regulations": ["gdpr"],
        "data_categories": ["personal_data"],
        "idempotency_key": "customer-request-001",
    }
    payload.update(changes)
    return ScanRequest(**payload)


def _scanner(region: str, account_id: str) -> str:
    return json.dumps(
        {
            "resources": [
                {
                    "resource_name": "customer-data",
                    "resource_arn": "arn:aws:s3:::customer-data",
                    "region": region,
                    "encryption_at_rest": True,
                }
            ],
            "flows": [
                {
                    "resource_name": "customer-data",
                    "resource_arn": "arn:aws:s3:::customer-data",
                    "source_region": region,
                    "destination_regions": ["us-east-1"],
                    "flow_type": "replication",
                    "encryption_enabled": True,
                }
            ],
        }
    )


def test_coordinator_accepts_once_and_starts_minimal_workflow_payload():
    run_store = InMemoryScanRunStore()
    starter = _WorkflowStarter()
    coordinator = ScanCoordinator(run_store=run_store, workflow_starter=starter)

    first = coordinator.submit(_request(), account_id="123456789012", requester_subject="user-123")
    retry = coordinator.submit(_request(), account_id="123456789012", requester_subject="user-123")

    assert first.created is True
    assert first.run.status is ScanStatus.QUEUED
    assert first.run.execution_arn
    assert first.run.progress.planned_units == 1
    assert retry.created is False
    assert retry.run.scan_run_id == first.run.scan_run_id
    assert len(starter.calls) == 1


def test_coordinator_rejects_idempotency_key_reused_with_different_request():
    run_store = InMemoryScanRunStore()
    coordinator = ScanCoordinator(run_store=run_store, workflow_starter=_WorkflowStarter())
    coordinator.submit(_request(), requester_subject="user-123")

    with pytest.raises(IdempotencyConflictError):
        coordinator.submit(
            _request(scan_regions=["eu-west-1"]),
            requester_subject="user-123",
        )


def test_coordinator_marks_run_failed_when_workflow_cannot_start():
    run_store = InMemoryScanRunStore()
    coordinator = ScanCoordinator(
        run_store=run_store,
        workflow_starter=_WorkflowStarter(failure=RuntimeError("access denied")),
    )

    with pytest.raises(WorkflowStartError):
        coordinator.submit(_request(), requester_subject="user-123")

    stored_run = next(iter(run_store._runs.values()))
    assert stored_run.status is ScanStatus.FAILED
    assert stored_run.error_summary == "Workflow submission failed (RuntimeError)."


def test_planned_work_items_are_bounded_and_global_services_run_once():
    run_store = InMemoryScanRunStore()
    coordinator = ScanCoordinator(run_store=run_store, workflow_starter=_WorkflowStarter())
    submitted = coordinator.submit(
        _request(
            scan_regions=["eu-central-1", "eu-west-1"],
            services=[ScanService.S3, ScanService.CLOUDFRONT],
        )
    )

    items = plan_work_items(submitted.run)

    assert [(item.region, item.service) for item in items] == [
        ("eu-central-1", ScanService.S3),
        ("eu-central-1", ScanService.CLOUDFRONT),
        ("eu-west-1", ScanService.S3),
    ]


def test_reference_workflow_persists_findings_and_marks_run_complete():
    run_store = InMemoryScanRunStore()
    scan_store = InMemoryScanStore()
    coordinator = ScanCoordinator(run_store=run_store, workflow_starter=_WorkflowStarter())
    submitted = coordinator.submit(_request(), account_id="123456789012")
    workflow = DeterministicScanWorkflow(
        run_store=run_store,
        scan_store=scan_store,
        scanners={ScanService.S3: _scanner},
    )

    completed = workflow.execute(submitted.run.scan_run_id)

    assert completed.status is ScanStatus.COMPLETE
    assert completed.progress.completed_units == 1
    assert completed.progress.finding_count == 1
    assert completed.report is not None
    assert completed.report["object_key"].startswith(f"reports/{completed.scan_run_id}/")
    assert scan_store.get_run(completed.scan_run_id)["status"] == "complete"
    assert len(scan_store.get_findings(completed.scan_run_id)) == 1


def test_reference_workflow_preserves_coverage_gaps_as_partial_results():
    run_store = InMemoryScanRunStore()
    scan_store = InMemoryScanStore()
    coordinator = ScanCoordinator(run_store=run_store, workflow_starter=_WorkflowStarter())
    submitted = coordinator.submit(_request())
    workflow = DeterministicScanWorkflow(
        run_store=run_store,
        scan_store=scan_store,
        scanners={ScanService.S3: lambda **_: "not-json"},
    )

    completed = workflow.execute(submitted.run.scan_run_id)

    assert completed.status is ScanStatus.PARTIAL
    assert completed.progress.coverage_gap_count == 1
    assert scan_store.get_run(completed.scan_run_id)["status"] == "partial"


def test_cancellation_is_honored_before_worker_execution():
    run_store = InMemoryScanRunStore()
    scan_store = InMemoryScanStore()
    coordinator = ScanCoordinator(run_store=run_store, workflow_starter=_WorkflowStarter())
    submitted = coordinator.submit(_request())
    coordinator.request_cancellation(submitted.run.scan_run_id)
    workflow = DeterministicScanWorkflow(
        run_store=run_store,
        scan_store=scan_store,
        scanners={ScanService.S3: _scanner},
    )

    cancelled = workflow.execute(submitted.run.scan_run_id)

    assert cancelled.status is ScanStatus.CANCELLED
    assert scan_store.get_run(cancelled.scan_run_id) is None


def test_dynamodb_run_store_uses_conditional_writes_and_round_trips_run():
    class Table:
        def __init__(self) -> None:
            self.items: dict[tuple[str, str], dict] = {}
            self.conditions: list[str] = []

        def put_item(self, *, Item, ConditionExpression):
            self.conditions.append(ConditionExpression)
            self.items[(Item["pk"], Item["sk"])] = Item

        def get_item(self, *, Key):
            item = self.items.get((Key["pk"], Key["sk"]))
            return {"Item": item} if item else {}

    table = Table()
    store = DynamoDBScanRunStore(runs_table=table)
    coordinator = ScanCoordinator(run_store=store, workflow_starter=_WorkflowStarter())

    submitted = coordinator.submit(_request())
    stored = store.get(submitted.run.scan_run_id)

    assert stored is not None
    assert stored.request_fingerprint == submitted.run.request_fingerprint
    assert table.conditions == [
        "attribute_not_exists(pk) AND attribute_not_exists(sk)",
        "attribute_exists(pk) AND attribute_exists(sk)",
    ]


def test_step_functions_starter_submits_only_run_and_correlation_ids():
    class Client:
        def __init__(self) -> None:
            self.arguments = {}

        def start_execution(self, **kwargs):
            self.arguments = kwargs
            return {"executionArn": "arn:aws:states:eu-central-1:123:execution:workflow:run-123"}

    client = Client()
    starter = StepFunctionsWorkflowStarter(
        client=client,
        state_machine_arn="arn:aws:states:eu-central-1:123:stateMachine:workflow",
    )

    execution_arn = starter.start(scan_run_id="run-123", correlation_id="correlation-123")

    assert execution_arn.endswith(":run-123")
    assert client.arguments["name"] == "run-123"
    assert json.loads(client.arguments["input"]) == {
        "scanRunId": "run-123",
        "correlationId": "correlation-123",
    }


def _schedule(**changes) -> ScanSchedule:
    request = _request(idempotency_key=None)
    payload = {
        "name": "weekly",
        "schedule_expression": "rate(7 days)",
        "request": request,
        "request_fingerprint": request_fingerprint(request),
        "requester_subject": "admin-123",
    }
    payload.update(changes)
    return ScanSchedule(**payload)


def test_scheduled_admission_is_idempotent_per_workflow_execution():
    store = InMemoryScanRunStore()
    schedule = _schedule()
    execution_arn = "arn:aws:states:eu-central-1:123:execution:sovereign-shield:scheduled-1"

    first = admit_scheduled_run(schedule, run_store=store, account_id="123", execution_arn=execution_arn)
    retried = admit_scheduled_run(schedule, run_store=store, account_id="123", execution_arn=execution_arn)
    next_execution = admit_scheduled_run(
        schedule, run_store=store, account_id="123", execution_arn=f"{execution_arn}-next"
    )

    assert retried.scan_run_id == first.scan_run_id
    assert next_execution.scan_run_id != first.scan_run_id
    assert first.status == ScanStatus.QUEUED
    assert first.requester_subject == "admin-123"
    assert first.execution_arn == execution_arn
    assert first.progress.planned_units == 1


def test_scheduled_admission_rejects_disabled_or_altered_schedules():
    store = InMemoryScanRunStore()

    with pytest.raises(ScheduleNotRunnableError):
        admit_scheduled_run(_schedule(enabled=False), run_store=store, account_id="123", execution_arn="arn")
    with pytest.raises(ScheduleNotRunnableError):
        admit_scheduled_run(
            _schedule(request_fingerprint="tampered"), run_store=store, account_id="123", execution_arn="arn"
        )


def test_mark_run_failed_records_sanitized_error_and_preserves_terminal_runs():
    store = InMemoryScanRunStore()
    submission = ScanCoordinator(run_store=store, workflow_starter=_WorkflowStarter()).submit(_request())

    failed = mark_run_failed(store, submission.run.scan_run_id, error_code="States.Timeout <script>")
    again = mark_run_failed(store, submission.run.scan_run_id, error_code="Other")

    assert failed.status == ScanStatus.FAILED
    assert failed.error_summary == "Workflow execution failed (States.Timeoutscript)."
    assert failed.completed_at is not None
    assert again.error_summary == failed.error_summary


class _KeyedTable:
    """Shared fake DynamoDB table keyed like the deployed runs table."""

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], dict] = {}

    def put_item(self, *, Item, ConditionExpression=None):
        key = (Item["pk"], Item["sk"])
        if ConditionExpression and ConditionExpression.startswith("attribute_exists") and key not in self.items:
            raise AssertionError("conditional update of a missing item")
        self.items[key] = json.loads(json.dumps(Item))

    def get_item(self, *, Key):
        item = self.items.get((Key["pk"], Key["sk"]))
        return {"Item": item} if item else {}

    def update_item(self, *, Key, UpdateExpression, ConditionExpression, ExpressionAttributeValues):
        """Apply the progress-increment expression used by DynamoDBScanRunStore."""

        item = self.items.get((Key["pk"], Key["sk"]))
        if item is None:
            raise AssertionError("conditional update of a missing item")
        assert "status" not in UpdateExpression, "progress increments must never rewrite status"
        item["progress"]["completed_units"] += ExpressionAttributeValues[":completed"]
        item["progress"]["failed_units"] += ExpressionAttributeValues[":failed"]
        item["updated_at"] = ExpressionAttributeValues[":now"]


def test_dynamodb_workflow_keeps_run_record_separate_from_scan_summary():
    from sovereign_shield.services.scan_store import DynamoDBScanStore

    runs_table = _KeyedTable()
    findings_table = _KeyedTable()
    run_store = DynamoDBScanRunStore(runs_table=runs_table)
    submission = ScanCoordinator(run_store=run_store, workflow_starter=_WorkflowStarter()).submit(_request())
    workflow = DeterministicScanWorkflow(
        run_store=run_store,
        scan_store=DynamoDBScanStore(runs_table=runs_table, findings_table=findings_table),
        scanners={ScanService.S3: _scanner},
    )

    completed = workflow.execute(submission.run.scan_run_id)

    partition = f"RUN#{completed.scan_run_id}"
    assert completed.status == ScanStatus.COMPLETE
    assert run_store.get(completed.scan_run_id).request_fingerprint == submission.run.request_fingerprint
    assert runs_table.items[(partition, "RUN")]["entity_type"] == "scan_run"
    assert runs_table.items[(partition, "SUMMARY")]["entity_type"] == "scan_result_summary"
