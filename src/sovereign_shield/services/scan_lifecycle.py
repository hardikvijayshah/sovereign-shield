"""Durable scan-run lifecycle, idempotent submission, and bounded work planning."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from sovereign_shield.models.contracts import (
    DeterministicScanResult,
    EvaluationResult,
    ScanCoverageGap,
    ScanProgress,
    ScanRequest,
    ScanRun,
    ScanSchedule,
    ScanService,
    ScanStatus,
)
from sovereign_shield.services.operations import ScanMetricsPublisher, ScanOutcomeNotifier
from sovereign_shield.services.policy_evaluator import evaluate_scan
from sovereign_shield.services.reporting import (
    DeterministicReportGenerator,
    InMemoryReportStore,
    ReportStore,
)
from sovereign_shield.services.scan_engine import GLOBAL_SERVICES, Scanner, execute_scan
from sovereign_shield.services.scan_store import ScanStore


class RunAlreadyExistsError(Exception):
    """Raised when a concurrent request creates an existing scan-run ID."""


class IdempotencyConflictError(ValueError):
    """Raised when one idempotency key is reused for a different scan request."""


class InvalidStatusTransitionError(ValueError):
    """Raised when a caller attempts to skip or reverse the scan lifecycle."""


class WorkflowStartError(RuntimeError):
    """Raised when the coordinator cannot submit an accepted run to the workflow."""


class IndexUnavailableError(RuntimeError):
    """Raised while a newly added listing index is still backfilling after an upgrade."""


class ScheduleNotRunnableError(ValueError):
    """Raised when a scheduled execution references a disabled or altered schedule."""


class ScanRunStore(Protocol):
    """Control-plane persistence boundary for scan status and idempotency."""

    def create(self, run: ScanRun) -> None:
        """Create a queued run exactly once."""

    def get(self, scan_run_id: str) -> ScanRun | None:
        """Return a scan run by its durable identifier."""

    def save(self, run: ScanRun) -> None:
        """Persist an existing scan run after a valid state update."""

    def list_recent(self, *, limit: int, cursor: str | None = None) -> tuple[list[ScanRun], str | None]:
        """Return a newest-first page of scan runs."""

    def increment_progress(self, scan_run_id: str, *, completed_units: int, failed_units: int) -> None:
        """Atomically add work-unit counters without rewriting the run record.

        Parallel workers use this instead of `save`, so they can never
        overwrite a concurrent status change such as a cancellation request.
        """


class WorkflowStarter(Protocol):
    """The minimal authority the coordinator needs from Step Functions."""

    def start(self, *, scan_run_id: str, correlation_id: str) -> str:
        """Start a workflow and return its execution ARN."""


@dataclass(frozen=True)
class ScanSubmission:
    """Result of accepting a scan request without waiting for its execution."""

    run: ScanRun
    created: bool


@dataclass(frozen=True)
class ScanWorkItem:
    """One account/region/service discovery unit for a workflow Map state."""

    scan_run_id: str
    account_id: str
    region: str
    service: ScanService

    def to_payload(self) -> dict[str, str]:
        """Serialize to the minimal camelCase workflow contract."""

        return {
            "scanRunId": self.scan_run_id,
            "accountId": self.account_id,
            "region": self.region,
            "service": self.service.value,
        }

    @classmethod
    def from_payload(cls, payload: Any) -> ScanWorkItem:
        """Parse a workflow work item, rejecting missing or unexpected fields."""

        if not isinstance(payload, Mapping) or set(payload) != {"scanRunId", "accountId", "region", "service"}:
            raise ValueError("Work item must contain exactly scanRunId, accountId, region, and service.")
        return cls(
            scan_run_id=str(payload["scanRunId"]),
            account_id=str(payload["accountId"]),
            region=str(payload["region"]),
            service=ScanService(payload["service"]),
        )


class WorkItemResultStore(Protocol):
    """Durable per-unit scanner results, written by workers and read by finalize."""

    def put(self, item: ScanWorkItem, result: DeterministicScanResult) -> None:
        """Store, or idempotently overwrite, one unit's normalized result."""

    def get(self, item: ScanWorkItem) -> DeterministicScanResult | None:
        """Return one unit's result, or None if no worker recorded it."""


class InMemoryWorkItemResultStore:
    """Deep-copying local/test per-unit result store."""

    def __init__(self) -> None:
        self._results: dict[str, DeterministicScanResult] = {}

    def put(self, item: ScanWorkItem, result: DeterministicScanResult) -> None:
        self._results[work_item_result_key(item)] = result.model_copy(deep=True)

    def get(self, item: ScanWorkItem) -> DeterministicScanResult | None:
        result = self._results.get(work_item_result_key(item))
        return result.model_copy(deep=True) if result else None


class S3WorkItemResultStore:
    """S3 adapter for per-unit results.

    Results live in S3 rather than DynamoDB because one unit (for example,
    every bucket in a busy region) can exceed DynamoDB's 400 KB item limit.
    Keys are deterministic, so a retried worker overwrites its own result.
    """

    def __init__(self, *, client: Any, bucket_name: str, kms_key_id: str | None = None) -> None:
        self._client = client
        self._bucket_name = bucket_name
        self._kms_key_id = kms_key_id

    def put(self, item: ScanWorkItem, result: DeterministicScanResult) -> None:
        request: dict[str, Any] = {
            "Bucket": self._bucket_name,
            "Key": work_item_result_key(item),
            "Body": result.model_dump_json().encode("utf-8"),
            "ContentType": "application/json",
        }
        if self._kms_key_id:
            request.update({"ServerSideEncryption": "aws:kms", "SSEKMSKeyId": self._kms_key_id})
        self._client.put_object(**request)

    def get(self, item: ScanWorkItem) -> DeterministicScanResult | None:
        try:
            response = self._client.get_object(Bucket=self._bucket_name, Key=work_item_result_key(item))
        except Exception as exc:  # noqa: BLE001 - normalize the missing-object error across client versions
            if _error_code(exc) in {"NoSuchKey", "404"}:
                return None
            raise
        return DeterministicScanResult.model_validate_json(response["Body"].read())


def work_item_result_key(item: ScanWorkItem) -> str:
    """Deterministic object key under the transient `work/` prefix."""

    account = item.account_id or "deployment"
    return f"work/{item.scan_run_id}/{account}/{item.region}/{item.service.value}.json"


class InMemoryScanRunStore:
    """Deep-copying control-plane store used by unit tests and local execution."""

    def __init__(self) -> None:
        self._runs: dict[str, ScanRun] = {}

    def create(self, run: ScanRun) -> None:
        if run.scan_run_id in self._runs:
            raise RunAlreadyExistsError(run.scan_run_id)
        self._runs[run.scan_run_id] = run.model_copy(deep=True)

    def get(self, scan_run_id: str) -> ScanRun | None:
        run = self._runs.get(scan_run_id)
        return run.model_copy(deep=True) if run else None

    def save(self, run: ScanRun) -> None:
        if run.scan_run_id not in self._runs:
            raise KeyError(f"Unknown scan run: {run.scan_run_id}")
        self._runs[run.scan_run_id] = run.model_copy(deep=True)

    def list_recent(self, *, limit: int, cursor: str | None = None) -> tuple[list[ScanRun], str | None]:
        runs = sorted(self._runs.values(), key=lambda run: run.created_at, reverse=True)
        start = int(cursor or 0)
        page = [run.model_copy(deep=True) for run in runs[start : start + limit]]
        next_index = start + len(page)
        return page, (str(next_index) if next_index < len(runs) else None)

    def increment_progress(self, scan_run_id: str, *, completed_units: int, failed_units: int) -> None:
        run = self._runs[scan_run_id]
        progress = _progress(
            run.progress,
            completed_units=run.progress.completed_units + completed_units,
            failed_units=run.progress.failed_units + failed_units,
        )
        self._runs[scan_run_id] = _replace(run, progress=progress)


class DynamoDBScanRunStore:
    """DynamoDB control-plane adapter sharing the runs-table key contract.

    The supplied table must use the `pk` / `sk` keys documented in
    `DATA_PERSISTENCE_CONTRACT.md`. Create and save use conditional writes so a
    workflow cannot accidentally create a new run during a status update.
    """

    def __init__(self, *, runs_table: Any, retention_days: int = 0) -> None:
        self._runs_table = runs_table
        self._retention_days = retention_days

    def create(self, run: ScanRun) -> None:
        try:
            self._runs_table.put_item(
                Item=_run_record_item(run),
                ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
            )
        except Exception as exc:  # noqa: BLE001 - normalize conditional write implementation differences
            if _is_conditional_failure(exc):
                raise RunAlreadyExistsError(run.scan_run_id) from exc
            raise

    def get(self, scan_run_id: str) -> ScanRun | None:
        response = self._runs_table.get_item(Key={"pk": f"RUN#{scan_run_id}", "sk": "RUN"})
        item = response.get("Item")
        return ScanRun.model_validate(item) if item else None

    def save(self, run: ScanRun) -> None:
        item = _run_record_item(run)
        if run.status in _TERMINAL_STATUSES:
            # A finished run expires with its evidence and findings; active runs never do.
            from sovereign_shield.services.scan_store import with_expiry

            item = with_expiry(item, self._retention_days)
        self._runs_table.put_item(
            Item=item,
            ConditionExpression="attribute_exists(pk) AND attribute_exists(sk)",
        )

    def list_recent(self, *, limit: int, cursor: str | None = None) -> tuple[list[ScanRun], str | None]:
        items, next_cursor = query_entities(self._runs_table, "scan_run", limit=limit, cursor=cursor)
        return [ScanRun.model_validate(item) for item in items], next_cursor

    def increment_progress(self, scan_run_id: str, *, completed_units: int, failed_units: int) -> None:
        self._runs_table.update_item(
            Key={"pk": f"RUN#{scan_run_id}", "sk": "RUN"},
            UpdateExpression=(
                "SET progress.completed_units = progress.completed_units + :completed, "
                "progress.failed_units = progress.failed_units + :failed, updated_at = :now"
            ),
            ConditionExpression="attribute_exists(pk) AND attribute_exists(sk)",
            ExpressionAttributeValues={
                ":completed": completed_units,
                ":failed": failed_units,
                ":now": datetime.now(timezone.utc).isoformat(),
            },
        )


class StepFunctionsWorkflowStarter:
    """Boto3-compatible Step Functions adapter with a minimal workflow input."""

    def __init__(self, *, client: Any, state_machine_arn: str) -> None:
        self._client = client
        self._state_machine_arn = state_machine_arn

    def start(self, *, scan_run_id: str, correlation_id: str) -> str:
        response = self._client.start_execution(
            stateMachineArn=self._state_machine_arn,
            name=scan_run_id,
            input=json.dumps(
                {"scanRunId": scan_run_id, "correlationId": correlation_id},
                separators=(",", ":"),
            ),
        )
        return str(response["executionArn"])


class ScanCoordinator:
    """Accepts validated work, records it, and starts a workflow without blocking."""

    def __init__(self, *, run_store: ScanRunStore, workflow_starter: WorkflowStarter) -> None:
        self._run_store = run_store
        self._workflow_starter = workflow_starter

    def submit(
        self,
        request: ScanRequest,
        *,
        account_id: str = "",
        requester_subject: str = "",
        correlation_id: str | None = None,
        target_account_ids: list[str] | None = None,
    ) -> ScanSubmission:
        """Create or return an idempotent queued run, then start its workflow."""

        planned = plan_work_items_for_request(request, "planning", account_id, target_account_ids)
        if len(planned) > MAX_WORK_UNITS:
            raise ValueError(
                f"This scan would need {len(planned)} account/region/service units; the limit is {MAX_WORK_UNITS}. "
                "Select fewer accounts, regions, or services."
            )

        fingerprint = request_fingerprint(request)
        scan_run_id = _scan_run_id(account_id, requester_subject, request)
        existing = self._run_store.get(scan_run_id) if request.idempotency_key else None
        if existing is not None:
            if existing.request_fingerprint != fingerprint:
                raise IdempotencyConflictError(
                    "The idempotency key was already used with a different scan request."
                )
            return ScanSubmission(run=existing, created=False)

        run = ScanRun(
            scan_run_id=scan_run_id,
            account_id=account_id,
            request=request,
            request_fingerprint=fingerprint,
            requester_subject=requester_subject,
            correlation_id=correlation_id or str(uuid.uuid4()),
            target_account_ids=list(target_account_ids or []),
            progress=ScanProgress(planned_units=len(planned)),
        )
        try:
            self._run_store.create(run)
        except RunAlreadyExistsError:
            existing = self._run_store.get(scan_run_id)
            if existing is None:
                raise
            if existing.request_fingerprint != fingerprint:
                raise IdempotencyConflictError(
                    "The idempotency key was already used with a different scan request."
                ) from None
            return ScanSubmission(run=existing, created=False)

        try:
            execution_arn = self._workflow_starter.start(
                scan_run_id=run.scan_run_id,
                correlation_id=run.correlation_id,
            )
        except Exception as exc:  # noqa: BLE001 - preserves a durable failed acceptance
            failed = _transition(run, ScanStatus.FAILED, error_summary=_safe_error_summary(exc))
            self._run_store.save(failed)
            raise WorkflowStartError("Unable to start scan workflow.") from exc

        started = _replace(run, execution_arn=execution_arn)
        self._run_store.save(started)
        return ScanSubmission(run=started, created=True)

    def request_cancellation(self, scan_run_id: str) -> ScanRun:
        """Record a cancellation request; workers honor it at safe boundaries."""

        run = self._required_run(scan_run_id)
        if run.status in _TERMINAL_STATUSES:
            return run
        cancelled = _transition(run, ScanStatus.CANCEL_REQUESTED)
        self._run_store.save(cancelled)
        return cancelled

    def _required_run(self, scan_run_id: str) -> ScanRun:
        run = self._run_store.get(scan_run_id)
        if run is None:
            raise KeyError(f"Unknown scan run: {scan_run_id}")
        return run


class DeterministicScanWorkflow:
    """Deterministic scan workflow, executed as bounded steps.

    The deployed state machine calls :meth:`prepare`, then
    :meth:`run_work_item` once per account/region/service through a Map state
    (or :meth:`record_work_item_failure` if that worker crashed), then
    :meth:`finalize`. :meth:`execute` runs the same steps sequentially for
    local use and tests.
    """

    def __init__(
        self,
        *,
        run_store: ScanRunStore,
        scan_store: ScanStore,
        scanners: Mapping[ScanService, Scanner] | None = None,
        work_item_results: WorkItemResultStore | None = None,
        report_generator: DeterministicReportGenerator | None = None,
        report_store: ReportStore | None = None,
        notifier: ScanOutcomeNotifier | None = None,
        metrics_publisher: ScanMetricsPublisher | None = None,
        account_eligible: Callable[[str], bool] | None = None,
    ) -> None:
        self._run_store = run_store
        self._scan_store = scan_store
        self._scanners = scanners
        self._account_eligible = account_eligible
        self._work_item_results = work_item_results or InMemoryWorkItemResultStore()
        self._report_generator = report_generator or DeterministicReportGenerator()
        self._report_store = report_store or InMemoryReportStore()
        self._notifier = notifier
        self._metrics_publisher = metrics_publisher

    def execute_work_item(self, item: ScanWorkItem) -> DeterministicScanResult:
        """Run one validated work item without mutating run-level status."""

        run = self._required_run(item.scan_run_id)
        _require_in_scope(run, item)
        scoped_request = run.request.model_copy(
            update={"scan_regions": [item.region], "services": [item.service]}
        )
        return execute_scan(
            scoped_request,
            account_id=item.account_id,
            scan_run_id=item.scan_run_id,
            scanners=self._scanners,
        )

    def prepare(self, scan_run_id: str) -> tuple[ScanRun, list[ScanWorkItem]]:
        """Move a queued run to RUNNING and return its bounded work items.

        A cancelled-before-start run returns no items. Re-preparing a running
        run returns the same items, so a retried step is harmless.
        """

        run = self._required_run(scan_run_id)
        if run.status == ScanStatus.CANCEL_REQUESTED:
            return self._save(_transition(run, ScanStatus.CANCELLED)), []
        if run.status == ScanStatus.RUNNING:
            return run, plan_work_items(run)
        if run.status != ScanStatus.QUEUED:
            raise InvalidStatusTransitionError(
                f"Only queued runs can begin execution; current status is {run.status.value}."
            )
        run = self._save(_transition(run, ScanStatus.VALIDATING))
        run = self._save(_transition(run, ScanStatus.RUNNING))
        return run, plan_work_items(run)

    def run_work_item(self, item: ScanWorkItem) -> str:
        """Scan one unit, store its result, and count it.

        Returns ``completed``, ``failed`` (the scanner raised; the unit is
        recorded as a coverage gap), or ``skipped`` (the run is no longer
        running, for example after a cancellation request).
        """

        run = self._required_run(item.scan_run_id)
        _require_in_scope(run, item)
        if run.status != ScanStatus.RUNNING:
            return "skipped"
        if item.account_id != run.account_id and self._account_eligible and not self._account_eligible(item.account_id):
            # Excluded, removed, or no longer reachable since the run was accepted.
            self._work_item_results.put(
                item,
                _failure_result(run, item, "account_not_eligible",
                                "The account was excluded or is no longer onboarded; it was not scanned."),
            )
            self._run_store.increment_progress(item.scan_run_id, completed_units=1, failed_units=0)
            return "excluded"
        try:
            result = self.execute_work_item(item)
            outcome = "completed"
        except Exception as exc:  # noqa: BLE001 - worker errors become visible coverage gaps
            result = _worker_failure_result(
                run, item, f"Worker failed before returning normalized evidence ({type(exc).__name__})."
            )
            outcome = "failed"
        self._work_item_results.put(item, result)
        self._run_store.increment_progress(
            item.scan_run_id, completed_units=1, failed_units=int(outcome == "failed")
        )
        return outcome

    def record_work_item_failure(self, item: ScanWorkItem, *, error_code: str) -> None:
        """Record a unit whose worker crashed or timed out as a coverage gap.

        A result the worker already stored is never replaced.
        """

        run = self._required_run(item.scan_run_id)
        _require_in_scope(run, item)
        if self._work_item_results.get(item) is not None:
            return
        safe_code = _safe_error_code(error_code)
        self._work_item_results.put(
            item, _worker_failure_result(run, item, f"Worker did not complete ({safe_code}).")
        )
        self._run_store.increment_progress(item.scan_run_id, completed_units=1, failed_units=1)

    def finalize(self, scan_run_id: str) -> ScanRun:
        """Aggregate stored unit results, evaluate, report, and end the run."""

        run = self._required_run(scan_run_id)
        if run.status in _TERMINAL_STATUSES:
            return run
        if run.status == ScanStatus.CANCEL_REQUESTED:
            return self._save(_transition(run, ScanStatus.CANCELLED))
        if run.status != ScanStatus.RUNNING:
            raise InvalidStatusTransitionError(
                f"Only running runs can be finalized; current status is {run.status.value}."
            )

        items = plan_work_items(run)
        results: list[DeterministicScanResult] = []
        missing: list[ScanCoverageGap] = []
        failed_units = 0
        for item in items:
            stored = self._work_item_results.get(item)
            if stored is None:
                missing.append(
                    _worker_gap(item, "work_item_result_missing", "No worker recorded a result for this unit.")
                )
                failed_units += 1
                continue
            if any(gap.code in _WORKER_GAP_CODES for gap in stored.coverage_gaps):
                failed_units += 1
            results.append(stored)

        # Counters are recomputed from durable results: retried workers may
        # have incremented them more than once.
        run = self._save(
            _replace(
                run,
                progress=_progress(run.progress, completed_units=len(items), failed_units=failed_units),
            )
        )
        aggregate = _aggregate_results(run, results, missing)
        try:
            self._scan_store.save_scan_result(aggregate)
            run = self._save(_transition(self._required_run(scan_run_id), ScanStatus.EVALUATING))
            evaluation = evaluate_scan(aggregate, store=self._scan_store)
            run = self._save(_transition(run, ScanStatus.REPORTING))
            report, content = self._report_generator.generate(
                scan=aggregate,
                evaluation=evaluation,
                requested_mode=run.request.report_generation_mode,
            )
            report = self._report_store.write(report, content)
            terminal_status = ScanStatus.PARTIAL if aggregate.coverage_gaps else ScanStatus.COMPLETE
            completed = self._save(
                _transition(
                    run,
                    terminal_status,
                    progress=_progress(
                        run.progress,
                        resource_count=len(aggregate.resources),
                        flow_count=len(aggregate.flows),
                        finding_count=evaluation.total_findings,
                        coverage_gap_count=len(aggregate.coverage_gaps),
                    ),
                    report=report.model_dump(mode="json"),
                )
            )
        except Exception as exc:  # noqa: BLE001 - persist terminal state before propagating workflow failure
            failed = self._save(
                _transition(
                    self._required_run(scan_run_id),
                    ScanStatus.FAILED,
                    error_summary=f"Workflow processing failed ({type(exc).__name__}).",
                )
            )
            self._publish_outcome(failed, None)
            raise

        self._publish_outcome(completed, evaluation)
        return completed

    def execute(self, scan_run_id: str) -> ScanRun:
        """Run prepare, every work item, and finalize sequentially."""

        run, items = self.prepare(scan_run_id)
        for item in items:
            current = self._required_run(scan_run_id)
            if current.status == ScanStatus.CANCEL_REQUESTED:
                return self._save(_transition(current, ScanStatus.CANCELLED))
            self.run_work_item(item)
        return self.finalize(scan_run_id) if items else run

    def _required_run(self, scan_run_id: str) -> ScanRun:
        run = self._run_store.get(scan_run_id)
        if run is None:
            raise KeyError(f"Unknown scan run: {scan_run_id}")
        return run

    def _save(self, run: ScanRun) -> ScanRun:
        self._run_store.save(run)
        return run

    def _publish_outcome(self, run: ScanRun, evaluation: EvaluationResult | None) -> None:
        """Operational delivery must never change an already durable scan outcome."""

        try:
            if self._notifier is not None:
                self._notifier.notify(run=run, evaluation=evaluation)
            if self._metrics_publisher is not None:
                self._metrics_publisher.publish(run=run, evaluation=evaluation)
        except Exception:  # noqa: BLE001 - alarm delivery cannot turn a completed scan into a failure
            return


def admit_scheduled_run(
    schedule: ScanSchedule,
    *,
    run_store: ScanRunStore,
    account_id: str,
    execution_arn: str,
    target_account_ids: list[str] | None = None,
) -> ScanRun:
    """Record the queued run for a schedule-started workflow execution.

    The run ID is derived from the schedule and execution so a retried
    admission step returns the same run instead of creating a duplicate.
    """

    if not schedule.enabled:
        raise ScheduleNotRunnableError("The schedule is disabled.")
    if schedule.request_fingerprint != request_fingerprint(schedule.request):
        raise ScheduleNotRunnableError("The stored schedule request does not match its fingerprint.")

    scan_run_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"schedule|{schedule.schedule_id}|{execution_arn}"))
    run = ScanRun(
        scan_run_id=scan_run_id,
        account_id=account_id,
        request=schedule.request,
        request_fingerprint=schedule.request_fingerprint,
        requester_subject=schedule.requester_subject,
        execution_arn=execution_arn,
        target_account_ids=list(target_account_ids or []),
        progress=ScanProgress(
            planned_units=len(
                plan_work_items_for_request(schedule.request, scan_run_id, account_id, target_account_ids)
            )
        ),
    )
    try:
        run_store.create(run)
    except RunAlreadyExistsError:
        existing = run_store.get(scan_run_id)
        if existing is None:
            raise
        return existing
    return run


def mark_run_failed(run_store: ScanRunStore, scan_run_id: str, *, error_code: str) -> ScanRun:
    """Record a workflow-level failure without overwriting a terminal outcome.

    Only a sanitized error name is stored; workflow error causes can contain
    AWS response text and are never persisted.
    """

    run = run_store.get(scan_run_id)
    if run is None:
        raise KeyError(f"Unknown scan run: {scan_run_id}")
    if run.status in _TERMINAL_STATUSES:
        return run
    failed = _transition(
        run, ScanStatus.FAILED, error_summary=f"Workflow execution failed ({_safe_error_code(error_code)})."
    )
    run_store.save(failed)
    return failed


_WORKER_GAP_CODES = {"worker_exception", "worker_incomplete", "work_item_result_missing"}


def _require_in_scope(run: ScanRun, item: ScanWorkItem) -> None:
    if item.scan_run_id != run.scan_run_id or item.account_id not in target_accounts(run):
        raise ValueError("Work item account does not match its scan run.")
    if item.region not in run.request.scan_regions or item.service not in run.request.services:
        raise ValueError("Work item is outside the accepted scan scope.")


def _worker_gap(item: ScanWorkItem, code: str, message: str) -> ScanCoverageGap:
    return ScanCoverageGap(
        account_id=item.account_id,
        region=item.region,
        service=item.service,
        code=code,
        message=message,
        retryable=True,
    )


def _worker_failure_result(run: ScanRun, item: ScanWorkItem, message: str) -> DeterministicScanResult:
    code = "worker_exception" if message.startswith("Worker failed") else "worker_incomplete"
    return _failure_result(run, item, code, message)


def _failure_result(run: ScanRun, item: ScanWorkItem, code: str, message: str) -> DeterministicScanResult:
    return DeterministicScanResult(
        scan_run_id=run.scan_run_id,
        account_id=run.account_id,
        request=run.request.model_copy(update={"scan_regions": [item.region], "services": [item.service]}),
        status=ScanStatus.PARTIAL,
        coverage_gaps=[_worker_gap(item, code, message)],
    )


def _safe_error_code(error_code: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "", error_code)[:64] or "Unknown"


MAX_WORK_UNITS = 1000
"""Upper bound on account x region x service units per run (Map state history limits)."""


def target_accounts(run: ScanRun) -> list[str]:
    """Accounts a run scans; runs accepted before multi-account support scan only their own account."""

    return list(run.target_account_ids) or [run.account_id]


def plan_work_items(run: ScanRun) -> list[ScanWorkItem]:
    """Create stable bounded units, invoking global services only once per account."""

    return plan_work_items_for_request(run.request, run.scan_run_id, run.account_id, target_accounts(run))


def plan_work_items_for_request(
    request: ScanRequest,
    scan_run_id: str,
    account_id: str,
    account_ids: list[str] | None = None,
) -> list[ScanWorkItem]:
    items: list[ScanWorkItem] = []
    for target_account in account_ids or [account_id]:
        for region_index, region in enumerate(request.scan_regions):
            for service in request.services:
                if service in GLOBAL_SERVICES and region_index > 0:
                    continue
                items.append(
                    ScanWorkItem(
                        scan_run_id=scan_run_id,
                        account_id=target_account,
                        region=region,
                        service=service,
                    )
                )
    return items


def request_fingerprint(request: ScanRequest) -> str:
    """Hash canonical request JSON so idempotency key reuse is safe to compare."""

    payload = request.model_dump(mode="json")
    # Requests without explicit accounts hash exactly as they did before
    # account_ids existed, so stored schedules and idempotency keys stay valid.
    if not payload.get("account_ids"):
        payload.pop("account_ids", None)
    canonical_request = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()


def _scan_run_id(account_id: str, requester_subject: str, request: ScanRequest) -> str:
    if not request.idempotency_key:
        return str(uuid.uuid4())
    namespace_input = "|".join((account_id, requester_subject, request.idempotency_key))
    return str(uuid.uuid5(uuid.NAMESPACE_URL, namespace_input))


def _aggregate_results(
    run: ScanRun,
    results: list[DeterministicScanResult],
    worker_failures: list[ScanCoverageGap],
) -> DeterministicScanResult:
    started_at = run.started_at or run.created_at
    aggregate = DeterministicScanResult(
        scan_run_id=run.scan_run_id,
        account_id=run.account_id,
        request=run.request,
        status=ScanStatus.COMPLETE,
        started_at=started_at,
    )
    resource_ids: set[str] = set()
    flow_ids: set[str] = set()
    for result in results:
        for resource in result.resources:
            if resource.evidence_id not in resource_ids:
                aggregate.resources.append(resource)
                resource_ids.add(resource.evidence_id)
        for flow in result.flows:
            if flow.evidence_id not in flow_ids:
                aggregate.flows.append(flow)
                flow_ids.add(flow.evidence_id)
        aggregate.coverage_gaps.extend(result.coverage_gaps)

    aggregate.coverage_gaps.extend(worker_failures)
    aggregate.completed_at = datetime.now(timezone.utc)
    aggregate.status = ScanStatus.PARTIAL if aggregate.coverage_gaps else ScanStatus.COMPLETE
    return aggregate


def _progress(progress: ScanProgress, **changes: int) -> ScanProgress:
    return progress.model_copy(update=changes)


def _replace(run: ScanRun, **changes: Any) -> ScanRun:
    return run.model_copy(update={**changes, "updated_at": datetime.now(timezone.utc)})


def _transition(run: ScanRun, target: ScanStatus, **changes: Any) -> ScanRun:
    if target not in _ALLOWED_TRANSITIONS[run.status]:
        raise InvalidStatusTransitionError(
            f"Cannot transition scan run from {run.status.value} to {target.value}."
        )
    timestamp_changes: dict[str, Any] = {"status": target}
    if target == ScanStatus.RUNNING and run.started_at is None:
        timestamp_changes["started_at"] = datetime.now(timezone.utc)
    if target in _TERMINAL_STATUSES and run.completed_at is None:
        timestamp_changes["completed_at"] = datetime.now(timezone.utc)
    return _replace(run, **timestamp_changes, **changes)


def _safe_error_summary(exc: Exception) -> str:
    return f"Workflow submission failed ({type(exc).__name__})."


def _run_record_item(run: ScanRun) -> dict[str, Any]:
    """Serialize only JSON-native fields for DynamoDB's resource API."""

    payload = run.model_dump(mode="json")
    return {
        "pk": f"RUN#{run.scan_run_id}",
        "sk": "RUN",
        "entity_type": "scan_run",
        **payload,
    }


ENTITY_INDEX_NAME = "by-entity-created"


def query_entities(
    table: Any, entity_type: str, *, limit: int, cursor: str | None = None
) -> tuple[list[dict[str, Any]], str | None]:
    """Newest-first page of one entity type from the runs table's sparse index.

    Only records carrying both ``entity_type`` and ``created_at`` (scan runs and
    schedules) are in the index; evidence and findings never appear in it.
    """

    from boto3.dynamodb.conditions import Key

    query: dict[str, Any] = {
        "IndexName": ENTITY_INDEX_NAME,
        "KeyConditionExpression": Key("entity_type").eq(entity_type),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if cursor:
        query["ExclusiveStartKey"] = _decode_index_cursor(cursor, entity_type)
    try:
        response = table.query(**query)
    except Exception as exc:  # noqa: BLE001 - normalize the backfill error across client versions
        if _error_code(exc) == "ValidationException" and "backfilling" in str(exc).lower():
            raise IndexUnavailableError("The listing index is still being built.") from exc
        raise
    last_key = response.get("LastEvaluatedKey")
    return response.get("Items", []), (_encode_index_cursor(last_key) if last_key else None)


def _encode_index_cursor(key: dict[str, Any]) -> str:
    serialized = json.dumps(key, separators=(",", ":"), sort_keys=True, default=str)
    return base64.urlsafe_b64encode(serialized.encode("utf-8")).decode("ascii")


def _decode_index_cursor(cursor: str, entity_type: str) -> dict[str, Any]:
    try:
        key = json.loads(base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("Invalid cursor.") from exc
    if (
        not isinstance(key, dict)
        or set(key) != {"pk", "sk", "entity_type", "created_at"}
        or key["entity_type"] != entity_type
    ):
        raise ValueError("Invalid cursor.")
    return key


def _is_conditional_failure(exc: Exception) -> bool:
    return _error_code(exc) == "ConditionalCheckFailedException"


def _error_code(exc: Exception) -> str:
    response = getattr(exc, "response", {})
    return str(response.get("Error", {}).get("Code", "")) if isinstance(response, dict) else ""


_TERMINAL_STATUSES = {ScanStatus.COMPLETE, ScanStatus.PARTIAL, ScanStatus.FAILED, ScanStatus.CANCELLED}
_ACTIVE_EXITS = {ScanStatus.FAILED, ScanStatus.CANCEL_REQUESTED, ScanStatus.CANCELLED}
_ALLOWED_TRANSITIONS: dict[ScanStatus, set[ScanStatus]] = {
    ScanStatus.QUEUED: {ScanStatus.VALIDATING} | _ACTIVE_EXITS,
    ScanStatus.VALIDATING: {ScanStatus.RUNNING} | _ACTIVE_EXITS,
    ScanStatus.RUNNING: {ScanStatus.EVALUATING} | _ACTIVE_EXITS,
    ScanStatus.EVALUATING: {ScanStatus.REPORTING, ScanStatus.COMPLETE, ScanStatus.PARTIAL} | _ACTIVE_EXITS,
    ScanStatus.REPORTING: {ScanStatus.COMPLETE, ScanStatus.PARTIAL} | _ACTIVE_EXITS,
    ScanStatus.CANCEL_REQUESTED: {ScanStatus.CANCELLED, ScanStatus.FAILED},
    ScanStatus.COMPLETE: set(),
    ScanStatus.PARTIAL: set(),
    ScanStatus.FAILED: set(),
    ScanStatus.CANCELLED: set(),
}
