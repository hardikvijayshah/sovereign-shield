"""Tests for the transport-neutral asynchronous scan API service."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from sovereign_shield.services.scan_api import ScanApiService
from sovereign_shield.services.scan_lifecycle import InMemoryScanRunStore, ScanCoordinator
from sovereign_shield.services.scan_store import InMemoryScanStore
from sovereign_shield.services.scheduling import InMemoryScheduleStore, ScheduleService


class _Starter:
    def start(self, *, scan_run_id: str, correlation_id: str) -> str:
        return f"arn:aws:states:eu-central-1:123:execution:workflow:{scan_run_id}"


class _Scheduler:
    def upsert(self, schedule) -> str:
        return f"arn:aws:scheduler:eu-central-1:123:schedule/group/{schedule.schedule_id}"

    def delete(self, schedule_id: str) -> None:
        return None


def _api() -> ScanApiService:
    run_store = InMemoryScanRunStore()
    return ScanApiService(
        coordinator=ScanCoordinator(run_store=run_store, workflow_starter=_Starter()),
        run_store=run_store,
        findings_reader=InMemoryScanStore(),
        schedule_service=ScheduleService(store=InMemoryScheduleStore(), scheduler=_Scheduler()),
    )


def _payload(**changes) -> dict:
    payload = {
        "scanRegions": ["eu-central-1"],
        "services": ["s3"],
        "regulations": ["gdpr"],
        "dataCategories": ["personal_data"],
        "idempotencyKey": "api-request-001",
    }
    payload.update(changes)
    return payload


def test_create_scan_accepts_documented_payload_and_returns_queued_response():
    response = _api().create_scan(
        _payload(),
        account_id="123456789012",
        requester_subject="user-123",
        correlation_id="correlation-123",
    )

    assert response["status"] == "queued"
    assert response["created"] is True
    assert response["correlationId"] == "correlation-123"
    assert response["scanRunId"]


def test_create_scan_rejects_unknown_or_ambiguous_input_fields():
    api = _api()

    with pytest.raises(ValidationError):
        api.create_scan(_payload(unexpected="value"))

    with pytest.raises(ValueError, match="Duplicate request field"):
        api.create_scan(_payload(scan_regions=["eu-central-1"]))


def test_status_and_cancellation_return_only_polling_safe_run_fields():
    api = _api()
    created = api.create_scan(_payload())

    status = api.get_scan(created["scanRunId"])
    cancelled = api.cancel_scan(created["scanRunId"])

    assert status["status"] == "queued"
    assert "requestFingerprint" not in status
    assert cancelled["status"] == "cancel_requested"
    assert cancelled["progress"]["planned_units"] == 1


def test_findings_are_paged_and_missing_runs_are_not_exposed():
    run_store = InMemoryScanRunStore()
    finding_store = InMemoryScanStore()
    api = ScanApiService(
        coordinator=ScanCoordinator(run_store=run_store, workflow_starter=_Starter()),
        run_store=run_store,
        findings_reader=finding_store,
    )
    created = api.create_scan(_payload())
    finding_store.findings[created["scanRunId"]] = [{"finding_id": str(number)} for number in range(3)]

    first_page = api.get_findings(created["scanRunId"], limit=2)
    second_page = api.get_findings(created["scanRunId"], limit=2, cursor=first_page["nextCursor"])

    assert [finding["finding_id"] for finding in first_page["findings"]] == ["0", "1"]
    assert [finding["finding_id"] for finding in second_page["findings"]] == ["2"]
    assert second_page["nextCursor"] is None

    with pytest.raises(KeyError):
        api.get_findings("missing-run")


def test_findings_page_size_is_bounded():
    api = _api()
    created = api.create_scan(_payload())

    with pytest.raises(ValueError, match="limit"):
        api.get_findings(created["scanRunId"], limit=101)


def test_schedule_api_creates_updates_and_deletes_a_durable_schedule():
    api = _api()
    schedule = api.create_schedule(
        {
            "name": "Daily GDPR scan",
            "scheduleExpression": "rate(1 day)",
            "scanRequest": _payload(),
        },
        requester_subject="admin-123",
    )
    updated = api.update_schedule(schedule["scheduleId"], {"enabled": False})

    assert schedule["enabled"] is True
    assert updated["enabled"] is False
    api.delete_schedule(schedule["scheduleId"])

    with pytest.raises(KeyError):
        api.update_schedule(schedule["scheduleId"], {"enabled": True})

    with pytest.raises(ValueError, match="boolean"):
        api.create_schedule(
            {
                "name": "Invalid",
                "scheduleExpression": "rate(1 day)",
                "scanRequest": _payload(),
                "enabled": "false",
            },
            requester_subject="admin-123",
        )
