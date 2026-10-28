"""Transport tests for the asynchronous v1 Lambda routes."""

from __future__ import annotations

import json

import pytest

from sovereign_shield import lambda_handler
from sovereign_shield.services.audit import AuditRecorder, InMemoryAuditLog


@pytest.fixture(autouse=True)
def audit_log(monkeypatch):
    log = InMemoryAuditLog()
    monkeypatch.setattr(lambda_handler, "_get_audit_log", lambda: log)
    monkeypatch.setattr(lambda_handler, "_get_audit_recorder", lambda: AuditRecorder(log))
    return log


class _Api:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple, dict]] = []

    def create_scan(self, *args, **kwargs):
        self.calls.append(("create_scan", args, kwargs))
        return {"scanRunId": "run-123", "status": "queued", "correlationId": "correlation-123", "created": True}

    def get_scan(self, scan_run_id):
        self.calls.append(("get_scan", (scan_run_id,), {}))
        return {"scanRunId": scan_run_id, "status": "running"}

    def cancel_scan(self, scan_run_id):
        self.calls.append(("cancel_scan", (scan_run_id,), {}))
        return {"scanRunId": scan_run_id, "status": "cancel_requested"}

    def get_findings(self, scan_run_id, *, limit, cursor, filters=None):
        self.calls.append(("get_findings", (scan_run_id,), {"limit": limit, "cursor": cursor, "filters": filters}))
        return {"scanRunId": scan_run_id, "findings": [], "nextCursor": None}

    def get_report(self, scan_run_id):
        self.calls.append(("get_report", (scan_run_id,), {}))
        return {"scanRunId": scan_run_id, "report": {"object_key": "reports/run-123/report.md"}}

    def create_schedule(self, payload, *, requester_subject):
        self.calls.append(("create_schedule", (payload,), {"requester_subject": requester_subject}))
        return {"scheduleId": "schedule-123", "enabled": True}

    def update_schedule(self, schedule_id, payload):
        self.calls.append(("update_schedule", (schedule_id, payload), {}))
        return {"scheduleId": schedule_id, "enabled": False}

    def delete_schedule(self, schedule_id):
        self.calls.append(("delete_schedule", (schedule_id,), {}))


def _event(path: str, method: str, groups: list[str] | None = None, **changes):
    event = {
        "rawPath": path,
        "requestContext": {
            "http": {"method": method},
            "authorizer": {
                "jwt": {
                    "claims": {
                        "sub": "user-123",
                        "cognito:groups": groups or ["SovereignShieldAdministrators"],
                    }
                }
            },
        },
    }
    event.update(changes)
    return event


def test_v1_create_returns_accepted_and_uses_jwt_subject(monkeypatch):
    api = _Api()
    monkeypatch.setattr(lambda_handler, "_get_v1_api_service", lambda: api)
    event = _event(
        "/v1/scans",
        "POST",
        body=json.dumps({"scanRegions": ["eu-central-1"], "idempotencyKey": "request-123"}),
        headers={"x-correlation-id": "correlation-123"},
    )

    response = lambda_handler.handler(event, None)

    assert response["statusCode"] == 202
    assert json.loads(response["body"])["scanRunId"] == "run-123"
    assert api.calls[0][0] == "create_scan"
    assert api.calls[0][2]["requester_subject"] == "user-123"


def test_v1_routes_status_cancellation_and_findings(monkeypatch):
    api = _Api()
    monkeypatch.setattr(lambda_handler, "_get_v1_api_service", lambda: api)

    status = lambda_handler.handler(_event("/v1/scans/run-123", "GET"), None)
    cancellation = lambda_handler.handler(_event("/v1/scans/run-123/cancel", "POST"), None)
    findings = lambda_handler.handler(
        _event("/v1/scans/run-123/findings", "GET", queryStringParameters={"limit": "25", "cursor": "page-2"}),
        None,
    )
    report = lambda_handler.handler(_event("/v1/scans/run-123/report", "GET"), None)

    assert status["statusCode"] == 200
    assert cancellation["statusCode"] == 202
    assert findings["statusCode"] == 200
    assert report["statusCode"] == 200
    assert api.calls[-2] == ("get_findings", ("run-123",), {"limit": 25, "cursor": "page-2", "filters": {}})
    assert api.calls[-1] == ("get_report", ("run-123",), {})


def test_v1_rejects_invalid_requests_without_internal_error_details(monkeypatch):
    class RejectingApi(_Api):
        def create_scan(self, *args, **kwargs):
            raise ValueError("details that must not reach the caller")

    monkeypatch.setattr(lambda_handler, "_get_v1_api_service", lambda: RejectingApi())

    response = lambda_handler.handler(_event("/v1/scans", "POST", body="{}"), None)

    assert response["statusCode"] == 400
    assert json.loads(response["body"]) == {"error": "Invalid request."}


def test_v1_allows_auditors_to_read_but_not_start_or_cancel_scans(monkeypatch):
    api = _Api()
    monkeypatch.setattr(lambda_handler, "_get_v1_api_service", lambda: api)
    auditor = ["SovereignShieldAuditors"]

    status = lambda_handler.handler(_event("/v1/scans/run-123", "GET", groups=auditor), None)
    start = lambda_handler.handler(_event("/v1/scans", "POST", groups=auditor, body="{}"), None)
    cancel = lambda_handler.handler(_event("/v1/scans/run-123/cancel", "POST", groups=auditor), None)

    assert status["statusCode"] == 200
    assert start["statusCode"] == 403
    assert cancel["statusCode"] == 403


def test_v1_schedule_routes_require_administrator_role(monkeypatch):
    api = _Api()
    monkeypatch.setattr(lambda_handler, "_get_v1_api_service", lambda: api)
    admin = ["SovereignShieldAdministrators"]
    payload = json.dumps({"name": "Daily", "scheduleExpression": "rate(1 day)", "scanRequest": {}})

    create = lambda_handler.handler(_event("/v1/schedules", "POST", groups=admin, body=payload), None)
    update = lambda_handler.handler(_event("/v1/schedules/schedule-123", "PATCH", groups=admin, body="{}"), None)
    delete = lambda_handler.handler(_event("/v1/schedules/schedule-123", "DELETE", groups=admin, body="{}"), None)
    forbidden = lambda_handler.handler(
        _event("/v1/schedules", "POST", groups=["SovereignShieldAuditors"], body=payload),
        None,
    )

    assert create["statusCode"] == 201
    assert update["statusCode"] == 200
    assert delete["statusCode"] == 204
    assert forbidden["statusCode"] == 403


class _ListingApi(_Api):
    def list_scans(self, *, limit, cursor):
        self.calls.append(("list_scans", (), {"limit": limit, "cursor": cursor}))
        return {"scans": [], "nextCursor": None}

    def list_schedules(self, *, limit, cursor):
        self.calls.append(("list_schedules", (), {"limit": limit, "cursor": cursor}))
        return {"schedules": [], "nextCursor": None}

    def get_configuration(self, principal):
        self.calls.append(("get_configuration", (principal.subject,), {}))
        return {"caller": {"subject": principal.subject}}


def test_v1_listing_and_configuration_routes_are_open_to_auditors(monkeypatch):
    api = _ListingApi()
    monkeypatch.setattr(lambda_handler, "_get_v1_api_service", lambda: api)
    auditor = ["SovereignShieldAuditors"]

    scans = lambda_handler.handler(
        _event("/v1/scans", "GET", groups=auditor, queryStringParameters={"limit": "5"}), None
    )
    schedules = lambda_handler.handler(_event("/v1/schedules", "GET", groups=auditor), None)
    configuration = lambda_handler.handler(_event("/v1/configuration", "GET", groups=auditor), None)

    assert [scans["statusCode"], schedules["statusCode"], configuration["statusCode"]] == [200, 200, 200]
    assert api.calls[0] == ("list_scans", (), {"limit": 5, "cursor": None})


def test_v1_findings_filters_are_mapped_and_unknown_parameters_rejected(monkeypatch):
    api = _Api()
    monkeypatch.setattr(lambda_handler, "_get_v1_api_service", lambda: api)

    filtered = lambda_handler.handler(
        _event(
            "/v1/scans/run-123/findings",
            "GET",
            queryStringParameters={"severity": "critical", "ruleId": "gdpr-1", "region": "eu-west-1"},
        ),
        None,
    )
    rejected = lambda_handler.handler(
        _event("/v1/scans/run-123/findings", "GET", queryStringParameters={"pk": "RUN#other"}), None
    )

    assert filtered["statusCode"] == 200
    assert api.calls[-1][2]["filters"] == {"severity": "critical", "rule_id": "gdpr-1", "region": "eu-west-1"}
    assert rejected["statusCode"] == 400


def test_v1_audit_log_is_administrator_only_and_records_mutations_and_denials(monkeypatch, audit_log):
    api = _Api()
    monkeypatch.setattr(lambda_handler, "_get_v1_api_service", lambda: api)
    auditor = ["SovereignShieldAuditors"]

    lambda_handler.handler(_event("/v1/scans", "POST", body=json.dumps({"scanRegions": ["eu-central-1"]})), None)
    lambda_handler.handler(_event("/v1/scans", "POST", groups=auditor, body="{}"), None)
    lambda_handler.handler(_event("/v1/scans/run-123/report", "GET", groups=auditor), None)
    lambda_handler.handler(_event("/v1/scans/run-123", "GET"), None)

    denied = lambda_handler.handler(_event("/v1/audit-events", "GET", groups=auditor), None)
    listed = lambda_handler.handler(_event("/v1/audit-events", "GET"), None)

    events = json.loads(listed["body"])["events"]
    assert denied["statusCode"] == 403
    assert listed["statusCode"] == 200
    assert {(event["action"], event["outcome"]) for event in events} == {
        ("scan.start", "succeeded"),
        ("scan.start", "denied"),
        ("report.view", "succeeded"),
        ("audit.list", "denied"),
    }
    started = next(event for event in events if event["action"] == "scan.start" and event["outcome"] == "succeeded")
    assert started["targetId"] == "run-123"
    assert started["actorSubject"] == "user-123"


def test_v1_audit_write_failure_never_fails_the_request(monkeypatch):
    class BrokenLog(InMemoryAuditLog):
        def record(self, event):
            raise RuntimeError("table unavailable")

    api = _Api()
    monkeypatch.setattr(lambda_handler, "_get_v1_api_service", lambda: api)
    monkeypatch.setattr(lambda_handler, "_get_audit_recorder", lambda: AuditRecorder(BrokenLog()))

    response = lambda_handler.handler(_event("/v1/scans/run-123/cancel", "POST"), None)

    assert response["statusCode"] == 202


def test_v1_malformed_bodies_and_identifiers_are_rejected(monkeypatch):
    api = _Api()
    monkeypatch.setattr(lambda_handler, "_get_v1_api_service", lambda: api)

    not_json = lambda_handler.handler(_event("/v1/scans", "POST", body="{not json"), None)
    not_object = lambda_handler.handler(_event("/v1/scans", "POST", body="[1, 2]"), None)
    bad_identifier = lambda_handler.handler(_event("/v1/scans/run%2F..%2Fx", "GET"), None)

    assert not_json["statusCode"] == 400
    assert not_object["statusCode"] == 400
    assert bad_identifier["statusCode"] == 404
    assert api.calls == []


def test_v1_listing_during_index_backfill_returns_503_with_retry_after(monkeypatch):
    from sovereign_shield.services.scan_lifecycle import IndexUnavailableError

    class BackfillingApi(_Api):
        def list_scans(self, *, limit, cursor):
            raise IndexUnavailableError("building")

    monkeypatch.setattr(lambda_handler, "_get_v1_api_service", lambda: BackfillingApi())

    response = lambda_handler.handler(_event("/v1/scans", "GET"), None)

    assert response["statusCode"] == 503
    assert response["headers"]["Retry-After"] == "60"



def test_authorization_denials_are_logged_with_the_route_only(monkeypatch, caplog):
    monkeypatch.setattr(lambda_handler, "_get_v1_api_service", lambda: _Api())

    with caplog.at_level("WARNING"):
        lambda_handler.handler(_event("/v1/scans", "POST", groups=["SovereignShieldAuditors"], body="{}"), None)

    denial = [record.getMessage() for record in caplog.records if "AUTHORIZATION_DENIED" in record.getMessage()]
    assert denial == ["AUTHORIZATION_DENIED route=scan.start"]
    assert "user-123" not in denial[0]
