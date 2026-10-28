"""Lambda entry point for asynchronous, deterministic scan workflow execution.

The scan state machine invokes this function with minimal events:

- ``{"action": "admit_scheduled_run", "scheduleId": ..., "executionArn": ...}``
  records the queued run for a schedule-started execution;
- ``{"action": "prepare", "scanRunId": ...}`` starts the run and returns its
  bounded work items for the Map state;
- ``{"action": "execute_work_item", "workItem": {...}}`` scans one
  account/region/service unit and stores its result;
- ``{"action": "record_work_item_failure", "workItem": {...}, "error": ...}``
  records a crashed or timed-out unit as a coverage gap;
- ``{"action": "finalize", "scanRunId": ...}`` aggregates, evaluates, reports,
  and ends the run;
- ``{"action": "mark_failed", "scanRunId": ..., "error": ...}`` records a
  workflow-level failure on the run.

``{"scanRunId": ...}`` with no action runs every step sequentially in one
invocation; it is retained for direct operator use.
"""

from __future__ import annotations

import logging
import os
from functools import lru_cache
from typing import Any

import boto3

from sovereign_shield.services import (
    CloudWatchScanMetricsPublisher,
    DeterministicScanWorkflow,
    DynamoDBScanRunStore,
    DynamoDBScanStore,
    DynamoDBScheduleStore,
    S3ReportStore,
    S3WorkItemResultStore,
    ScanOutcomeNotifier,
    ScanWorkItem,
    ScheduleNotRunnableError,
    SnsNotificationPublisher,
    admit_scheduled_run,
    mark_run_failed,
)
from sovereign_shield.services.accounts import AccountDirectory, DynamoDBAccountRegistry, OrganizationSettings

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Route a minimal state-machine event to its bounded workflow step."""

    action = event.get("action", "execute")
    if action == "admit_scheduled_run":
        return _admit_scheduled_run(event)
    if action == "prepare":
        return _prepare(event)
    if action == "execute_work_item":
        return _execute_work_item(event)
    if action == "record_work_item_failure":
        return _record_work_item_failure(event)
    if action == "finalize":
        scan_run_id = _required_field(event, "scanRunId")
        return _completed_response(_get_workflow().finalize(scan_run_id))
    if action == "mark_failed":
        return _mark_failed(event)
    if action != "execute":
        raise ValueError("Unsupported workflow action.")
    scan_run_id = _required_field(event, "scanRunId")
    return _completed_response(_get_workflow().execute(scan_run_id))


def _prepare(event: dict[str, Any]) -> dict[str, Any]:
    scan_run_id = _required_field(event, "scanRunId")
    run, items = _get_workflow().prepare(scan_run_id)
    logger.info("Prepared scan run %s with %s work items", run.scan_run_id, len(items))
    return {
        "scanRunId": run.scan_run_id,
        "status": run.status.value,
        "workItems": [item.to_payload() for item in items],
        # Read by the Map state's MaxConcurrencyPath, so concurrency is a launch parameter.
        "maxConcurrency": _scan_concurrency(),
    }


def _scan_concurrency() -> int:
    value = int(os.environ.get("SCAN_CONCURRENCY", "10"))
    if not 1 <= value <= 40:
        raise ValueError("SCAN_CONCURRENCY must be between 1 and 40.")
    return value


def _execute_work_item(event: dict[str, Any]) -> dict[str, Any]:
    item = ScanWorkItem.from_payload(event.get("workItem"))
    outcome = _get_workflow().run_work_item(item)
    logger.info("Work item %s/%s/%s: %s", item.scan_run_id, item.region, item.service.value, outcome)
    # Keep Map iteration output tiny; results are persisted, not returned.
    return {"outcome": outcome}


def _record_work_item_failure(event: dict[str, Any]) -> dict[str, Any]:
    item = ScanWorkItem.from_payload(event.get("workItem"))
    _get_workflow().record_work_item_failure(item, error_code=str(event.get("error") or ""))
    logger.info("Work item %s/%s/%s recorded as incomplete", item.scan_run_id, item.region, item.service.value)
    return {"outcome": "failed"}


def _completed_response(completed: Any) -> dict[str, Any]:
    logger.info(
        "Scan run %s ended with status=%s findings=%s coverage_gaps=%s",
        completed.scan_run_id,
        completed.status.value,
        completed.progress.finding_count,
        completed.progress.coverage_gap_count,
    )
    return {
        "scanRunId": completed.scan_run_id,
        "status": completed.status.value,
        "correlationId": completed.correlation_id,
    }


def _admit_scheduled_run(event: dict[str, Any]) -> dict[str, Any]:
    schedule_id = _required_field(event, "scheduleId")
    execution_arn = _required_field(event, "executionArn")
    if os.environ.get("SCHEDULED_SCANS_ENABLED", "true") != "true":
        # Schedules created before scheduling was disabled must not keep starting scans.
        raise ScheduleNotRunnableError("Scheduled scans are disabled for this deployment.")
    schedule = DynamoDBScheduleStore(runs_table=_runs_table()).get(schedule_id)
    if schedule is None:
        raise KeyError(f"Unknown schedule: {schedule_id}")
    try:
        targets = _account_directory().resolve_targets(list(schedule.request.account_ids))
    except ValueError as exc:
        raise ScheduleNotRunnableError(f"Scheduled accounts are not available: {exc}") from exc
    run = admit_scheduled_run(
        schedule,
        run_store=_get_run_store(),
        account_id=os.environ.get("DEPLOYMENT_ACCOUNT_ID", ""),
        execution_arn=execution_arn,
        target_account_ids=targets,
    )
    logger.info("Admitted scan run %s for schedule %s", run.scan_run_id, schedule_id)
    return {"scanRunId": run.scan_run_id, "correlationId": run.correlation_id}


def _mark_failed(event: dict[str, Any]) -> dict[str, Any]:
    scan_run_id = _required_field(event, "scanRunId")
    run = mark_run_failed(_get_run_store(), scan_run_id, error_code=str(event.get("error") or ""))
    logger.info("Scan run %s recorded as %s after workflow error", run.scan_run_id, run.status.value)
    return {"scanRunId": run.scan_run_id, "status": run.status.value}


@lru_cache
def _get_workflow() -> DeterministicScanWorkflow:
    """Construct the production workflow graph from deployment configuration."""

    s3 = boto3.client("s3")
    bucket_name = _required_environment("REPORTS_BUCKET")
    kms_key_id = os.environ.get("REPORTS_KMS_KEY_ID")
    return DeterministicScanWorkflow(
        run_store=_get_run_store(),
        scan_store=DynamoDBScanStore(
            runs_table=_runs_table(), findings_table=_findings_table(), retention_days=_retention_days()
        ),
        work_item_results=S3WorkItemResultStore(client=s3, bucket_name=bucket_name, kms_key_id=kms_key_id),
        report_store=S3ReportStore(client=s3, bucket_name=bucket_name, kms_key_id=kms_key_id),
        notifier=_notifier(),
        metrics_publisher=CloudWatchScanMetricsPublisher(client=boto3.client("cloudwatch")),
        account_eligible=_account_directory().is_scannable,
    )


@lru_cache
def _account_directory() -> AccountDirectory:
    settings = OrganizationSettings.from_environment(dict(os.environ))
    registry = DynamoDBAccountRegistry(runs_table=_runs_table()) if settings.organizations else None
    return AccountDirectory(settings=settings, registry=registry)


@lru_cache
def _get_run_store() -> DynamoDBScanRunStore:
    return DynamoDBScanRunStore(runs_table=_runs_table(), retention_days=_retention_days())


def _retention_days() -> int:
    return int(os.environ.get("FINDINGS_RETENTION_DAYS", "0"))


@lru_cache
def _runs_table() -> Any:
    return boto3.resource("dynamodb").Table(_required_environment("SCAN_RUNS_TABLE"))


@lru_cache
def _findings_table() -> Any:
    return boto3.resource("dynamodb").Table(_required_environment("FINDINGS_TABLE"))


def _notifier() -> ScanOutcomeNotifier | None:
    topic_arn = os.environ.get("NOTIFICATION_TOPIC_ARN")
    if not topic_arn:
        return None
    return ScanOutcomeNotifier(
        publisher=SnsNotificationPublisher(client=boto3.client("sns"), topic_arn=topic_arn)
    )


def _required_field(event: dict[str, Any], name: str) -> str:
    value = event.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"Workflow event must include {name}.")
    return value


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing required deployment configuration: {name}")
    return value
