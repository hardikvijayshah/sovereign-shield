"""Tests for release-time runtime pieces: custom resources, readiness, retention, scheduling switch."""

from __future__ import annotations

import io
import json
import zipfile

import pytest

from sovereign_shield import deployment_handler, readiness_handler, workflow_handler
from sovereign_shield.services.scan_api import DeploymentSettings, SchedulingDisabledError
from sovereign_shield.services.scan_store import with_expiry


class _FakeS3:
    def __init__(self, existing: dict[str, bytes] | None = None, bundle: bytes = b"") -> None:
        self.objects: dict[str, dict] = {key: {"Body": body} for key, body in (existing or {}).items()}
        self.bundle = bundle
        self.deleted: list[str] = []
        self.batch_deletes: list[list[dict]] = []

    def get_object(self, *, Bucket, Key):
        return {"Body": io.BytesIO(self.bundle)}

    def put_object(self, **kwargs):
        self.objects[kwargs["Key"]] = kwargs

    def delete_object(self, *, Bucket, Key):
        self.deleted.append(Key)
        self.objects.pop(Key, None)

    def delete_objects(self, *, Bucket, Delete):
        self.batch_deletes.append(Delete["Objects"])

    def get_paginator(self, name):
        s3 = self

        class _Paginator:
            def paginate(self, **kwargs):
                if name == "list_objects_v2":
                    return [{"Contents": [{"Key": key} for key in s3.objects]}]
                return [
                    {
                        "Versions": [{"Key": "reports/a.md", "VersionId": "1"}],
                        "DeleteMarkers": [{"Key": "reports/a.md", "VersionId": "2"}],
                    }
                ]

        return _Paginator()


class _FakeCloudFront:
    def __init__(self) -> None:
        self.invalidations: list[dict] = []

    def create_invalidation(self, **kwargs):
        self.invalidations.append(kwargs)


def _bundle(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, body in files.items():
            archive.writestr(name, body)
    return buffer.getvalue()


def test_console_publication_uploads_bundle_writes_config_prunes_and_invalidates():
    s3 = _FakeS3(
        existing={"assets/old-123.js": b"old"},
        bundle=_bundle({"index.html": b"<html>", "assets/index-abc.js": b"js"}),
    )
    cloudfront = _FakeCloudFront()

    deployment_handler._console_publication(
        "Update",
        {
            "SourceBucket": "artifacts",
            "SourceKey": "releases/1.0.0/console.zip",
            "TargetBucket": "console",
            "DistributionId": "E123",
            "Config": json.dumps({"apiUrl": "https://api.example.com"}),
        },
        clients=(s3, cloudfront),
    )

    assert s3.objects["index.html"]["CacheControl"] == "no-cache"
    assert s3.objects["index.html"]["ContentType"] == "text/html"
    assert s3.objects["assets/index-abc.js"]["CacheControl"].endswith("immutable")
    assert json.loads(s3.objects["config.json"]["Body"]) == {"apiUrl": "https://api.example.com"}
    assert s3.deleted == ["assets/old-123.js"]
    assert cloudfront.invalidations[0]["InvalidationBatch"]["Paths"]["Items"] == ["/*"]


@pytest.mark.parametrize("name", ["../escape.html", "/abs.html", "assets/../../x", "a//b"])
def test_console_bundle_rejects_paths_that_escape_the_bucket_root(name):
    s3 = _FakeS3(bundle=_bundle({name: b"x"}))

    with pytest.raises(ValueError, match="Unsafe path"):
        deployment_handler.publish_bundle(s3, "console", s3.bundle, {})


def test_bucket_emptier_deletes_all_versions_only_on_delete():
    s3 = _FakeS3()

    deployment_handler._bucket_emptier("Update", {"BucketName": "reports"}, s3=s3)
    assert s3.batch_deletes == []

    deployment_handler._bucket_emptier("Delete", {"BucketName": "reports"}, s3=s3)
    assert {entry["VersionId"] for entry in s3.batch_deletes[0]} == {"1", "2"}


def test_custom_resource_always_reports_back_to_cloudformation(monkeypatch):
    responses = []
    monkeypatch.setattr(
        deployment_handler, "_respond", lambda event, status, physical_id, **kwargs: responses.append((status, kwargs))
    )
    event = {
        "RequestType": "Create",
        "ResourceType": "Custom::Unknown",
        "LogicalResourceId": "Thing",
        "RequestId": "req-1",
        "StackId": "stack",
        "ResponseURL": "https://example.invalid",
    }

    deployment_handler.handler(event, None)

    assert responses[0][0] == "FAILED"
    assert "Unsupported resource type" in responses[0][1]["reason"]


def test_custom_resource_response_is_a_put_with_the_documented_fields():
    captured = {}

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def opener(request, timeout):
        captured["method"] = request.get_method()
        captured["body"] = json.loads(request.data)
        return _Response()

    event = {"StackId": "s", "RequestId": "r", "LogicalResourceId": "L", "ResponseURL": "https://cfn.example/x"}
    deployment_handler._respond(event, "SUCCESS", "phys-1", data={"A": "1"}, opener=opener)

    assert captured["method"] == "PUT"
    assert captured["body"]["PhysicalResourceId"] == "phys-1"
    assert captured["body"]["Data"] == {"A": "1"}


def test_readiness_reports_failures_and_treats_disabled_regions_as_warnings(monkeypatch):
    for name, value in {
        "SCAN_RUNS_TABLE": "runs",
        "FINDINGS_TABLE": "findings",
        "AUDIT_TABLE": "audit",
        "REPORTS_BUCKET": "reports",
        "DATA_KEY_ARN": "arn:key",
        "SCAN_STATE_MACHINE_ARN": "arn:sm",
        "USER_POOL_ID": "pool",
        "CONSOLE_CLIENT_ID": "client",
        "DEFAULT_SCAN_REGIONS": "eu-west-1,me-south-1",
        "AWS_REGION": "eu-west-1",
    }.items():
        monkeypatch.setenv(name, value)

    class _Denied(Exception):
        response = {"Error": {"Code": "UnrecognizedClientException"}}

    class _Client:
        def __init__(self, service, region):
            self.service, self.region = service, region

        def __getattr__(self, operation):
            def call(**kwargs):
                if self.region == "me-south-1":
                    raise _Denied()
                if operation == "describe_table":
                    return {"Table": {"TableStatus": "ACTIVE", "GlobalSecondaryIndexes": [{"IndexStatus": "ACTIVE"}]}}
                if operation == "describe_key":
                    return {"KeyMetadata": {"KeyState": "Enabled"}}
                if operation == "describe_user_pool_client":
                    return {"UserPoolClient": {"AllowedOAuthFlows": ["implicit"]}}
                return {}

            return call

    report = readiness_handler.handler({}, None, client_factory=_Client)

    results = {entry["check"]: entry["result"] for entry in report["checks"]}
    assert results["table:scan_runs_table"] == "pass"
    assert results["identity:console-client"] == "fail"
    assert results["scanner:s3:me-south-1"] == "warning"
    assert results["scanner:s3:eu-west-1"] == "pass"
    assert report["ready"] is False


def test_retention_adds_ttl_only_when_configured():
    assert "expires_at" not in with_expiry({"pk": "x"}, 0)
    assert with_expiry({"pk": "x"}, 30)["expires_at"] > 0


def test_terminal_runs_expire_but_active_runs_never_do():
    from sovereign_shield.models.contracts import ScanRequest, ScanRun, ScanStatus
    from sovereign_shield.services.scan_lifecycle import DynamoDBScanRunStore, request_fingerprint

    class Table:
        def __init__(self):
            self.items = []

        def put_item(self, *, Item, ConditionExpression):
            self.items.append(Item)

    table = Table()
    store = DynamoDBScanRunStore(runs_table=table, retention_days=30)
    request = ScanRequest(scan_regions=["eu-west-1"])
    run = ScanRun(request=request, request_fingerprint=request_fingerprint(request), status=ScanStatus.RUNNING)

    store.save(run)
    store.save(run.model_copy(update={"status": ScanStatus.COMPLETE}))

    assert "expires_at" not in table.items[0]
    assert "expires_at" in table.items[1]


def test_disabled_scheduling_blocks_schedule_creation_and_reports_it_in_configuration():
    from tests.test_console_api import ADMIN, _api

    api, _ = _api(settings=DeploymentSettings(scheduled_scans_enabled=False, default_scan_regions=("eu-west-1",)))

    with pytest.raises(SchedulingDisabledError):
        api.create_schedule(
            {"name": "n", "scheduleExpression": "rate(1 day)", "scanRequest": {}}, requester_subject="a"
        )
    choices = api.get_configuration(ADMIN)["scanChoices"]
    assert choices["scheduledScansEnabled"] is False
    assert choices["defaultRegions"] == ["eu-west-1"]


def test_disabled_scheduling_stops_existing_schedules_from_starting_scans(monkeypatch):
    monkeypatch.setenv("SCHEDULED_SCANS_ENABLED", "false")

    with pytest.raises(ValueError, match="disabled"):
        workflow_handler.handler(
            {"action": "admit_scheduled_run", "scheduleId": "s-1", "executionArn": "arn:exec"}, None
        )


def test_prepare_rejects_out_of_range_concurrency(monkeypatch):
    monkeypatch.setenv("SCAN_CONCURRENCY", "99")

    with pytest.raises(ValueError, match="SCAN_CONCURRENCY"):
        workflow_handler._scan_concurrency()


def test_readiness_checks_the_organization_and_stack_set_in_organization_mode(monkeypatch):
    for name, value in {
        "SCAN_RUNS_TABLE": "runs", "FINDINGS_TABLE": "findings", "AUDIT_TABLE": "audit",
        "REPORTS_BUCKET": "reports", "DATA_KEY_ARN": "arn:key", "SCAN_STATE_MACHINE_ARN": "arn:sm",
        "USER_POOL_ID": "pool", "CONSOLE_CLIENT_ID": "client", "DEFAULT_SCAN_REGIONS": "eu-west-1",
        "AWS_REGION": "eu-west-1", "ORGANIZATION_MODE": "AWS_ORGANIZATIONS", "ORGANIZATION_ID": "o-expected123",
        "STACK_SET_NAME": "sovereign-shield-member-x", "STACK_SET_CALL_AS": "DELEGATED_ADMIN",
    }.items():
        monkeypatch.setenv(name, value)
    calls = []

    class _Client:
        def __init__(self, service, region):
            self.service = service

        def __getattr__(self, operation):
            def call(**kwargs):
                calls.append((self.service, operation, kwargs))
                if operation == "describe_organization":
                    return {"Organization": {"Id": "o-other456789"}}
                if operation == "describe_table":
                    return {"Table": {"TableStatus": "ACTIVE"}}
                if operation == "describe_key":
                    return {"KeyMetadata": {"KeyState": "Enabled"}}
                if operation == "describe_user_pool_client":
                    return {"UserPoolClient": {"AllowedOAuthFlows": ["code"]}}
                return {}

            return call

    report = readiness_handler.handler({}, None, client_factory=_Client)
    results = {entry["check"]: entry for entry in report["checks"]}

    assert results["organization:membership"]["result"] == "fail"
    assert "OrganizationIdMismatch" in results["organization:membership"]["detail"]
    assert results["organization:member-role-stackset"]["result"] == "pass"
    assert ("cloudformation", "describe_stack_set",
            {"StackSetName": "sovereign-shield-member-x", "CallAs": "DELEGATED_ADMIN"}) in calls
