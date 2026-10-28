"""Tests for the prepare -> per-unit workers -> finalize workflow used by the Map state."""

from __future__ import annotations

import json

import pytest

from sovereign_shield.models.contracts import DeterministicScanResult, ScanRequest, ScanService, ScanStatus
from sovereign_shield.services.scan_lifecycle import (
    DeterministicScanWorkflow,
    InMemoryScanRunStore,
    InMemoryWorkItemResultStore,
    S3WorkItemResultStore,
    ScanCoordinator,
    ScanWorkItem,
    work_item_result_key,
)
from sovereign_shield.services.scan_store import InMemoryScanStore


class _Starter:
    def start(self, *, scan_run_id: str, correlation_id: str) -> str:
        return f"arn:aws:states:eu-central-1:123:execution:sm:{scan_run_id}"


def _scanner(region: str, account_id: str) -> str:
    return json.dumps(
        {
            "resources": [
                {
                    "resource_name": f"data-{region}",
                    "resource_arn": f"arn:aws:s3:::data-{region}",
                    "region": region,
                    "encryption_at_rest": True,
                }
            ],
            "flows": [],
        }
    )


def _failing_scanner(region: str, account_id: str) -> str:
    raise RuntimeError("scanner exploded")


def _setup(scanners=None, regions=("eu-central-1", "eu-west-1")):
    run_store = InMemoryScanRunStore()
    scan_store = InMemoryScanStore()
    results = InMemoryWorkItemResultStore()
    request = ScanRequest(
        scan_regions=list(regions),
        services=[ScanService.S3],
        regulations=["gdpr"],
        data_categories=["personal_data"],
    )
    run = ScanCoordinator(run_store=run_store, workflow_starter=_Starter()).submit(request, account_id="111").run
    workflow = DeterministicScanWorkflow(
        run_store=run_store,
        scan_store=scan_store,
        scanners=scanners or {ScanService.S3: _scanner},
        work_item_results=results,
    )
    return workflow, run_store, scan_store, results, run


def test_units_run_independently_in_any_order_and_finalize_aggregates_them():
    workflow, run_store, _, results, run = _setup()

    prepared, items = workflow.prepare(run.scan_run_id)
    assert prepared.status == ScanStatus.RUNNING
    assert [item.region for item in items] == ["eu-central-1", "eu-west-1"]

    for item in reversed(items):
        assert workflow.run_work_item(item) == "completed"
    assert run_store.get(run.scan_run_id).progress.completed_units == 2

    completed = workflow.finalize(run.scan_run_id)
    assert completed.status == ScanStatus.COMPLETE
    assert completed.progress.resource_count == 2
    assert all(results.get(item) is not None for item in items)


def test_crashed_worker_becomes_a_coverage_gap_and_the_run_is_partial():
    workflow, run_store, _, _, run = _setup()
    _, items = workflow.prepare(run.scan_run_id)

    workflow.run_work_item(items[0])
    workflow.record_work_item_failure(items[1], error_code="Sandbox.Timedout")
    completed = workflow.finalize(run.scan_run_id)

    assert completed.status == ScanStatus.PARTIAL
    assert completed.progress.completed_units == 2
    assert completed.progress.failed_units == 1
    assert completed.progress.resource_count == 1
    assert completed.progress.coverage_gap_count == 1


def test_scanner_exception_is_normalized_into_a_completed_unit_with_a_gap():
    workflow, _, _, results, run = _setup(scanners={ScanService.S3: _failing_scanner})
    _, items = workflow.prepare(run.scan_run_id)

    assert workflow.run_work_item(items[0]) == "completed"
    assert results.get(items[0]).coverage_gaps


def test_worker_exception_outside_the_scanner_is_recorded_as_a_failed_unit(monkeypatch):
    from sovereign_shield.services import scan_lifecycle

    workflow, _, _, results, run = _setup()
    _, items = workflow.prepare(run.scan_run_id)

    def broken_engine(*args, **kwargs):
        raise MemoryError("engine failure")

    monkeypatch.setattr(scan_lifecycle, "execute_scan", broken_engine)

    assert workflow.run_work_item(items[0]) == "failed"
    gap = results.get(items[0]).coverage_gaps[0]
    assert gap.code == "worker_exception"
    assert "MemoryError" in gap.message


def test_failure_recording_never_replaces_a_stored_result():
    workflow, _, _, results, run = _setup()
    _, items = workflow.prepare(run.scan_run_id)

    workflow.run_work_item(items[0])
    workflow.record_work_item_failure(items[0], error_code="States.TaskFailed")

    assert results.get(items[0]).coverage_gaps == []
    assert len(results.get(items[0]).resources) == 1


def test_missing_unit_results_are_visible_gaps_not_silent_omissions():
    workflow, _, _, _, run = _setup()
    _, items = workflow.prepare(run.scan_run_id)

    workflow.run_work_item(items[0])
    completed = workflow.finalize(run.scan_run_id)

    assert completed.status == ScanStatus.PARTIAL
    assert completed.progress.failed_units == 1


def test_retried_worker_overwrites_its_result_and_finalize_corrects_counters():
    workflow, run_store, _, _, run = _setup()
    _, items = workflow.prepare(run.scan_run_id)

    for item in items:
        workflow.run_work_item(item)
    workflow.run_work_item(items[0])
    assert run_store.get(run.scan_run_id).progress.completed_units == 3

    completed = workflow.finalize(run.scan_run_id)
    assert completed.progress.completed_units == 2
    assert completed.progress.resource_count == 2


def test_cancellation_during_fan_out_skips_remaining_units_and_cancels():
    workflow, run_store, scan_store, _, run = _setup()
    coordinator = ScanCoordinator(run_store=run_store, workflow_starter=_Starter())
    _, items = workflow.prepare(run.scan_run_id)

    workflow.run_work_item(items[0])
    coordinator.request_cancellation(run.scan_run_id)

    assert workflow.run_work_item(items[1]) == "skipped"
    assert workflow.finalize(run.scan_run_id).status == ScanStatus.CANCELLED
    assert scan_store.get_run(run.scan_run_id) is None


def test_progress_increments_never_overwrite_a_cancellation_request():
    workflow, run_store, _, _, run = _setup()
    _, items = workflow.prepare(run.scan_run_id)
    ScanCoordinator(run_store=run_store, workflow_starter=_Starter()).request_cancellation(run.scan_run_id)

    run_store.increment_progress(run.scan_run_id, completed_units=1, failed_units=0)

    assert run_store.get(run.scan_run_id).status == ScanStatus.CANCEL_REQUESTED


def test_prepare_is_idempotent_and_rejects_finished_runs():
    workflow, _, _, _, run = _setup()

    _, first = workflow.prepare(run.scan_run_id)
    _, again = workflow.prepare(run.scan_run_id)
    assert first == again

    for item in first:
        workflow.run_work_item(item)
    workflow.finalize(run.scan_run_id)
    with pytest.raises(ValueError, match="queued"):
        workflow.prepare(run.scan_run_id)
    assert workflow.finalize(run.scan_run_id).status == ScanStatus.COMPLETE


def test_out_of_scope_work_items_are_rejected():
    workflow, _, _, _, run = _setup()
    workflow.prepare(run.scan_run_id)

    with pytest.raises(ValueError, match="scope"):
        workflow.run_work_item(ScanWorkItem(run.scan_run_id, "111", "us-east-1", ScanService.S3))
    with pytest.raises(ValueError, match="account"):
        workflow.run_work_item(ScanWorkItem(run.scan_run_id, "999", "eu-central-1", ScanService.S3))


def test_work_item_payload_round_trips_and_rejects_unexpected_fields():
    item = ScanWorkItem("run-1", "111", "eu-central-1", ScanService.SNS_SQS)

    assert ScanWorkItem.from_payload(item.to_payload()) == item
    with pytest.raises(ValueError):
        ScanWorkItem.from_payload({**item.to_payload(), "regions": ["us-east-1"]})
    with pytest.raises(ValueError):
        ScanWorkItem.from_payload({**item.to_payload(), "service": "iam"})


class _S3Client:
    class _Missing(Exception):
        response = {"Error": {"Code": "NoSuchKey"}}

    def __init__(self) -> None:
        self.objects: dict[str, dict] = {}

    def put_object(self, **kwargs):
        self.objects[kwargs["Key"]] = kwargs

    def get_object(self, *, Bucket, Key):
        if Key not in self.objects:
            raise self._Missing()

        class _Body:
            def __init__(self, data: bytes) -> None:
                self._data = data

            def read(self) -> bytes:
                return self._data

        return {"Body": _Body(self.objects[Key]["Body"])}


def test_s3_result_store_encrypts_round_trips_and_reports_missing_results():
    client = _S3Client()
    store = S3WorkItemResultStore(client=client, bucket_name="reports", kms_key_id="arn:aws:kms:key")
    item = ScanWorkItem("run-1", "111", "eu-central-1", ScanService.S3)
    result = DeterministicScanResult(
        scan_run_id="run-1",
        account_id="111",
        request=ScanRequest(scan_regions=["eu-central-1"], services=[ScanService.S3], regulations=["gdpr"]),
    )

    assert store.get(item) is None
    store.put(item, result)

    written = client.objects["work/run-1/111/eu-central-1/s3.json"]
    assert written["ServerSideEncryption"] == "aws:kms"
    assert written["SSEKMSKeyId"] == "arn:aws:kms:key"
    assert store.get(item).scan_run_id == "run-1"
    assert work_item_result_key(item).startswith("work/run-1/")
