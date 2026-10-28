"""Service-level tests for the console-facing v1 API additions."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sovereign_shield.models.contracts import ScanRequest, ScanService
from sovereign_shield.services.audit import (
    AuditEvent,
    AuditOutcome,
    AuditRecorder,
    DynamoDBAuditLog,
    InMemoryAuditLog,
    validate_month,
)
from sovereign_shield.services.authorization import RequestPrincipal, allowed_actions
from sovereign_shield.services.scan_api import DeploymentSettings, S3ReportLinkSigner, ScanApiService
from sovereign_shield.services.scan_lifecycle import (
    DynamoDBScanRunStore,
    InMemoryScanRunStore,
    ScanCoordinator,
    query_entities,
)
from sovereign_shield.services.scan_store import InMemoryScanStore, validate_finding_filters
from sovereign_shield.services.scheduling import InMemoryScheduleStore, ScheduleService

ADMIN = RequestPrincipal("admin-1", frozenset({"SovereignShieldAdministrators"}))
AUDITOR = RequestPrincipal("auditor-1", frozenset({"SovereignShieldAuditors"}))


class _Starter:
    def start(self, *, scan_run_id: str, correlation_id: str) -> str:
        return f"arn:aws:states:eu-central-1:111:execution:sm:{scan_run_id}"


class _Scheduler:
    def upsert(self, schedule):
        return f"arn:aws:scheduler:eu-central-1:111:schedule/group/{schedule.schedule_id}"

    def delete(self, schedule_id):
        return None


class _Signer:
    def __init__(self) -> None:
        self.calls = []

    def sign(self, *, object_key, filename, expires_in):
        self.calls.append((object_key, filename, expires_in))
        return f"https://signed.example/{object_key}"


def _api(*, signer=None, settings=None, findings=None):
    run_store = InMemoryScanRunStore()
    scan_store = findings or InMemoryScanStore()
    api = ScanApiService(
        coordinator=ScanCoordinator(run_store=run_store, workflow_starter=_Starter()),
        run_store=run_store,
        findings_reader=scan_store,
        schedule_service=ScheduleService(store=InMemoryScheduleStore(), scheduler=_Scheduler()),
        report_links=signer,
        settings=settings,
    )
    return api, run_store


def _scan_payload(**changes):
    payload = {"scanRegions": ["eu-central-1"], "services": ["s3"], "regulations": ["gdpr"]}
    payload.update(changes)
    return payload


def test_configuration_reports_choices_roles_and_admin_only_settings():
    settings = DeploymentSettings(
        account_id="111", region="eu-central-1", administrator_settings={"reportRetentionDays": 365}
    )
    api, _ = _api(settings=settings)

    admin_view = api.get_configuration(ADMIN)
    auditor_view = api.get_configuration(AUDITOR)

    assert admin_view["caller"]["roles"] == ["administrator"]
    assert "start_scan" in admin_view["caller"]["allowedActions"]
    assert "start_scan" not in auditor_view["caller"]["allowedActions"]
    assert admin_view["settings"] == {"reportRetentionDays": 365}
    assert "settings" not in auditor_view
    choices = admin_view["scanChoices"]
    assert "eu-central-1" in choices["regions"]
    assert not any(region.startswith(("cn-", "us-gov-")) for region in choices["regions"])
    assert {"id": "cloudfront", "global": True} in choices["services"]
    assert any(regulation["id"] == "gdpr" for regulation in choices["regulations"])
    assert "personal_data" in choices["dataCategories"]
    assert admin_view["deployment"]["rulePackVersion"]


def test_allowed_actions_are_empty_without_a_subject():
    assert allowed_actions(RequestPrincipal("", frozenset({"SovereignShieldAdministrators"}))) == []


def test_scan_list_is_newest_first_paginated_and_includes_request_summary():
    api, _ = _api()
    first = api.create_scan(_scan_payload(), requester_subject="admin-1")
    second = api.create_scan(_scan_payload(scanRegions=["eu-west-1"]), requester_subject="admin-1")

    page = api.list_scans(limit=1)
    rest = api.list_scans(limit=1, cursor=page["nextCursor"])

    assert page["scans"][0]["scanRunId"] == second["scanRunId"]
    assert rest["scans"][0]["scanRunId"] == first["scanRunId"]
    assert rest["nextCursor"] is None
    assert page["scans"][0]["request"]["scanRegions"] == ["eu-west-1"]
    assert page["scans"][0]["requesterSubject"] == "admin-1"
    with pytest.raises(ValueError):
        api.list_scans(limit=500)


def test_schedule_list_returns_definitions_without_fingerprints():
    api, _ = _api()
    api.create_schedule(
        {"name": "weekly", "scheduleExpression": "rate(7 days)", "scanRequest": _scan_payload()},
        requester_subject="admin-1",
    )

    listed = api.list_schedules()

    assert listed["schedules"][0]["name"] == "weekly"
    assert listed["schedules"][0]["request"]["services"] == ["s3"]
    assert "request_fingerprint" not in str(listed)


def test_report_includes_short_lived_download_link_when_configured():
    signer = _Signer()
    api, run_store = _api(signer=signer)
    run_id = api.create_scan(_scan_payload())["scanRunId"]
    run = run_store.get(run_id)
    run_store.save(run.model_copy(update={"report": {"object_key": f"reports/{run_id}/r.md"}}))

    response = api.get_report(run_id)

    assert response["download"]["url"] == f"https://signed.example/reports/{run_id}/r.md"
    expires_at = datetime.fromisoformat(response["download"]["expiresAt"])
    assert expires_at - datetime.now(timezone.utc) <= timedelta(minutes=5)
    assert signer.calls[0][1] == f"sovereign-shield-{run_id}.md"


def test_report_without_signer_returns_metadata_only():
    api, run_store = _api()
    run_id = api.create_scan(_scan_payload())["scanRunId"]
    run_store.save(run_store.get(run_id).model_copy(update={"report": {"object_key": "reports/x/r.md"}}))

    assert api.get_report(run_id)["download"] is None


def test_s3_report_signer_only_signs_report_objects_as_attachments():
    class Client:
        def __init__(self):
            self.arguments = None

        def generate_presigned_url(self, operation, Params, ExpiresIn):
            self.arguments = (operation, Params, ExpiresIn)
            return "https://bucket.s3.eu-central-1.amazonaws.com/signed"

    client = Client()
    signer = S3ReportLinkSigner(client=client, bucket_name="reports-bucket")

    signer.sign(object_key="reports/run/r.md", filename="r.md", expires_in=timedelta(minutes=5))

    operation, params, expires = client.arguments
    assert operation == "get_object"
    assert params["ResponseContentDisposition"] == 'attachment; filename="r.md"'
    assert expires == 300
    with pytest.raises(ValueError):
        signer.sign(object_key="work/run/x.json", filename="x", expires_in=timedelta(minutes=5))


def test_findings_filters_are_allowlisted_and_applied():
    store = InMemoryScanStore()
    store.findings["run-1"] = [
        {"finding_id": "a", "severity": "critical", "region": "eu-west-1", "rule_id": "r1"},
        {"finding_id": "b", "severity": "low", "region": "eu-west-1", "rule_id": "r2"},
    ]
    api, run_store = _api(findings=store)
    request = ScanRequest(scan_regions=["eu-west-1"], services=[ScanService.S3])
    from sovereign_shield.models.contracts import ScanRun
    from sovereign_shield.services.scan_lifecycle import request_fingerprint

    run_store.create(ScanRun(scan_run_id="run-1", request=request, request_fingerprint=request_fingerprint(request)))

    page = api.get_findings("run-1", filters={"severity": "critical"})

    assert [finding["finding_id"] for finding in page["findings"]] == ["a"]
    with pytest.raises(ValueError):
        validate_finding_filters({"pk": "RUN#other"})
    with pytest.raises(ValueError):
        validate_finding_filters({"severity": "x" * 200})


class _QueryTable:
    def __init__(self, response):
        self.response = response
        self.queries = []

    def query(self, **kwargs):
        self.queries.append(kwargs)
        return self.response


def test_entity_index_query_is_newest_first_and_validates_cursors():
    key = {"pk": "RUN#1", "sk": "RUN", "entity_type": "scan_run", "created_at": "2026-10-26T00:00:00+00:00"}
    table = _QueryTable({"Items": [], "LastEvaluatedKey": key})

    _, cursor = query_entities(table, "scan_run", limit=10)
    query_entities(table, "scan_run", limit=10, cursor=cursor)

    assert table.queries[0]["IndexName"] == "by-entity-created"
    assert table.queries[0]["ScanIndexForward"] is False
    assert table.queries[1]["ExclusiveStartKey"] == key
    with pytest.raises(ValueError):
        query_entities(table, "scan_schedule", limit=10, cursor=cursor)
    with pytest.raises(ValueError):
        query_entities(table, "scan_run", limit=10, cursor="not-base64!")


def test_dynamodb_run_store_lists_through_the_entity_index():
    table = _QueryTable({"Items": []})
    DynamoDBScanRunStore(runs_table=table).list_recent(limit=5)

    assert table.queries[0]["Limit"] == 5


def test_audit_recorder_swallows_write_failures():
    class Broken(InMemoryAuditLog):
        def record(self, event):
            raise RuntimeError("down")

    AuditRecorder(Broken()).record(
        actor_subject="u", action="scan.start", target_type="scan", outcome=AuditOutcome.SUCCEEDED
    )


def test_dynamodb_audit_log_is_append_only_and_month_partitioned():
    class Table:
        def __init__(self):
            self.puts = []
            self.queries = []

        def put_item(self, **kwargs):
            self.puts.append(kwargs)

        def query(self, **kwargs):
            self.queries.append(kwargs)
            return {"Items": [{**self.puts[0]["Item"]}]}

    table = Table()
    log = DynamoDBAuditLog(table=table)
    event = AuditEvent(
        occurred_at=datetime(2026, 10, 26, 9, 0, tzinfo=timezone.utc),
        actor_subject="admin-1",
        action="schedule.delete",
        target_type="schedule",
        target_id="s-1",
        outcome=AuditOutcome.SUCCEEDED,
    )

    log.record(event)
    events, _ = log.list_month("2026-10", limit=10)

    item = table.puts[0]["Item"]
    assert item["pk"] == "AUDIT#2026-10"
    assert item["sk"].startswith("2026-10-26T09:00:00")
    assert table.puts[0]["ConditionExpression"] == "attribute_not_exists(pk) AND attribute_not_exists(sk)"
    assert table.queries[0]["ScanIndexForward"] is False
    assert events[0].target_id == "s-1"


@pytest.mark.parametrize("month", ["2026-13", "26-10", "2026-1", "2026-10-01", ""])
def test_audit_month_is_validated(month):
    with pytest.raises(ValueError):
        validate_month(month)


def test_findings_responses_carry_read_only_guidance():
    store = InMemoryScanStore()
    store.findings["run-1"] = [{"finding_id": "a", "category": "encryption_at_rest_missing", "service": "rds"}]
    api, run_store = _api(findings=store)
    from sovereign_shield.models.contracts import ScanRun
    from sovereign_shield.services.scan_lifecycle import request_fingerprint

    request = ScanRequest(scan_regions=["eu-west-1"], services=[ScanService.RDS])
    run_store.create(ScanRun(scan_run_id="run-1", request=request, request_fingerprint=request_fingerprint(request)))

    finding = api.get_findings("run-1")["findings"][0]

    assert "does not make changes" in finding["guidance"]["notice"]
    assert finding["guidance"]["steps"][-1].startswith("For RDS")


def test_backfilling_index_is_reported_as_temporarily_unavailable():
    from sovereign_shield.services.scan_lifecycle import IndexUnavailableError

    class Backfilling(Exception):
        response = {"Error": {"Code": "ValidationException"}}

        def __str__(self):
            return "Cannot read from backfilling global secondary index: by-entity-created"

    class Table:
        def query(self, **kwargs):
            raise Backfilling()

    with pytest.raises(IndexUnavailableError):
        query_entities(Table(), "scan_run", limit=5)
