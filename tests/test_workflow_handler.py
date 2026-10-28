"""Tests for the deployed asynchronous workflow Lambda entry point."""

from __future__ import annotations

import pytest

from sovereign_shield import workflow_handler
from sovereign_shield.models.contracts import ScanRequest, ScanRun, ScanSchedule, ScanStatus
from sovereign_shield.services.scan_lifecycle import InMemoryScanRunStore, request_fingerprint


class _Completed:
    scan_run_id = "run-123"
    status = ScanStatus.COMPLETE
    correlation_id = "correlation-123"

    class progress:
        finding_count = 2
        coverage_gap_count = 0


class _Workflow:
    def __init__(self) -> None:
        self.executed = []

    def execute(self, scan_run_id):
        self.executed.append(scan_run_id)
        return _Completed()


def test_workflow_handler_executes_only_previously_accepted_run(monkeypatch):
    workflow = _Workflow()
    monkeypatch.setattr(workflow_handler, "_get_workflow", lambda: workflow)

    response = workflow_handler.handler({"scanRunId": "run-123", "correlationId": "ignored"}, None)

    assert workflow.executed == ["run-123"]
    assert response == {
        "scanRunId": "run-123",
        "status": "complete",
        "correlationId": "correlation-123",
    }


def test_workflow_handler_rejects_unbounded_or_missing_input():
    with pytest.raises(ValueError, match="scanRunId"):
        workflow_handler.handler({"regions": ["eu-central-1"]}, None)
    with pytest.raises(ValueError, match="Unsupported"):
        workflow_handler.handler({"action": "scan", "scanRunId": "run-123"}, None)
    with pytest.raises(ValueError, match="executionArn"):
        workflow_handler.handler({"action": "admit_scheduled_run", "scheduleId": "schedule-123"}, None)


def test_workflow_handler_admits_scheduled_execution(monkeypatch):
    request = ScanRequest(scan_regions=["eu-central-1"], services=["s3"], regulations=["gdpr"])
    schedule = ScanSchedule(
        schedule_id="schedule-123",
        name="weekly",
        schedule_expression="rate(7 days)",
        request=request,
        request_fingerprint=request_fingerprint(request),
    )
    run_store = InMemoryScanRunStore()

    class _ScheduleStore:
        def __init__(self, *, runs_table):
            pass

        def get(self, schedule_id):
            return schedule if schedule_id == "schedule-123" else None

    monkeypatch.setenv("DEPLOYMENT_ACCOUNT_ID", "111111111111")
    monkeypatch.setattr(workflow_handler, "DynamoDBScheduleStore", _ScheduleStore)
    monkeypatch.setattr(workflow_handler, "_runs_table", lambda: None)
    monkeypatch.setattr(workflow_handler, "_get_run_store", lambda: run_store)

    response = workflow_handler.handler(
        {"action": "admit_scheduled_run", "scheduleId": "schedule-123", "executionArn": "arn:execution:1"},
        None,
    )

    admitted = run_store.get(response["scanRunId"])
    assert admitted is not None
    assert admitted.account_id == "111111111111"
    assert admitted.status == ScanStatus.QUEUED
    assert response["correlationId"] == admitted.correlation_id


def test_workflow_handler_marks_run_failed_after_workflow_error(monkeypatch):
    run_store = InMemoryScanRunStore()
    request = ScanRequest(scan_regions=["eu-central-1"], services=["s3"], regulations=["gdpr"])
    run = ScanRun(request=request, request_fingerprint=request_fingerprint(request))
    run_store.create(run)
    monkeypatch.setattr(workflow_handler, "_get_run_store", lambda: run_store)

    response = workflow_handler.handler(
        {"action": "mark_failed", "scanRunId": run.scan_run_id, "error": "States.Timeout"},
        None,
    )

    assert response == {"scanRunId": run.scan_run_id, "status": "failed"}
    assert run_store.get(run.scan_run_id).error_summary == "Workflow execution failed (States.Timeout)."


class _StepWorkflow:
    def __init__(self) -> None:
        self.calls = []

    def prepare(self, scan_run_id):
        from sovereign_shield.models.contracts import ScanService
        from sovereign_shield.services.scan_lifecycle import ScanWorkItem

        self.calls.append(("prepare", scan_run_id))
        run = type("Run", (), {"scan_run_id": scan_run_id, "status": ScanStatus.RUNNING})()
        return run, [ScanWorkItem(scan_run_id, "111", "eu-central-1", ScanService.S3)]

    def run_work_item(self, item):
        self.calls.append(("run_work_item", item))
        return "completed"

    def record_work_item_failure(self, item, *, error_code):
        self.calls.append(("record_work_item_failure", item, error_code))

    def finalize(self, scan_run_id):
        self.calls.append(("finalize", scan_run_id))
        return _Completed()


_ITEM = {"scanRunId": "run-123", "accountId": "111", "region": "eu-central-1", "service": "s3"}


def test_workflow_handler_routes_fan_out_steps(monkeypatch):
    workflow = _StepWorkflow()
    monkeypatch.setattr(workflow_handler, "_get_workflow", lambda: workflow)

    prepared = workflow_handler.handler({"action": "prepare", "scanRunId": "run-123"}, None)
    worked = workflow_handler.handler({"action": "execute_work_item", "workItem": _ITEM}, None)
    failed = workflow_handler.handler(
        {"action": "record_work_item_failure", "workItem": _ITEM, "error": "Sandbox.Timedout"}, None
    )
    finalized = workflow_handler.handler({"action": "finalize", "scanRunId": "run-123"}, None)

    assert prepared == {"scanRunId": "run-123", "status": "running", "workItems": [_ITEM], "maxConcurrency": 10}
    assert worked == {"outcome": "completed"}
    assert failed == {"outcome": "failed"}
    assert finalized["status"] == "complete"
    assert workflow.calls[2][2] == "Sandbox.Timedout"


def test_workflow_handler_rejects_malformed_work_items(monkeypatch):
    monkeypatch.setattr(workflow_handler, "_get_workflow", lambda: _StepWorkflow())

    with pytest.raises(ValueError, match="Work item"):
        workflow_handler.handler({"action": "execute_work_item", "workItem": {**_ITEM, "extra": 1}}, None)
    with pytest.raises(ValueError, match="Work item"):
        workflow_handler.handler({"action": "execute_work_item"}, None)
