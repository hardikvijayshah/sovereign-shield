"""End-to-end (in-process) tests for multi-account scans and the accounts API."""

from __future__ import annotations

import json

import pytest

from sovereign_shield import lambda_handler
from sovereign_shield.models.contracts import ScanRequest, ScanService, ScanStatus
from sovereign_shield.services.accounts import (
    AccountDirectory,
    AccountStatus,
    InMemoryAccountRegistry,
    MemberAccount,
    OrganizationSettings,
)
from sovereign_shield.services.audit import AuditRecorder, InMemoryAuditLog
from sovereign_shield.services.scan_api import DeploymentSettings, ScanApiService
from sovereign_shield.services.scan_lifecycle import (
    MAX_WORK_UNITS,
    DeterministicScanWorkflow,
    InMemoryScanRunStore,
    ScanCoordinator,
    plan_work_items,
    request_fingerprint,
)
from sovereign_shield.services.scan_store import InMemoryScanStore
from sovereign_shield.services.scheduling import InMemoryScheduleStore, ScheduleService

CENTRAL, A, B, C = "111111111111", "222222222222", "333333333333", "444444444444"


class _Starter:
    def start(self, *, scan_run_id, correlation_id):
        return f"arn:aws:states:eu-west-1:{CENTRAL}:execution:sm:{scan_run_id}"


class _Scheduler:
    def upsert(self, schedule):
        return "arn:schedule"

    def delete(self, schedule_id):
        return None


def _directory(max_accounts: int = 10) -> tuple[AccountDirectory, InMemoryAccountRegistry]:
    registry = InMemoryAccountRegistry()
    registry.save(MemberAccount(account_id=A, status=AccountStatus.ONBOARDED, name="payments",
                                organizational_unit_id="ou-prod"))
    registry.save(MemberAccount(account_id=B, status=AccountStatus.ONBOARDED, name="analytics",
                                organizational_unit_id="ou-prod"))
    registry.save(MemberAccount(account_id=C, status=AccountStatus.FAILED, name="broken"))
    settings = OrganizationSettings(
        mode="AWS_ORGANIZATIONS", deployment_account_id=CENTRAL, organization_id="o-abcdef1234",
        target_ou_ids=("ou-prod",), max_accounts_per_scan=max_accounts,
    )
    return AccountDirectory(settings=settings, registry=registry), registry


def _api(directory=None, syncs=None):
    run_store = InMemoryScanRunStore()
    api = ScanApiService(
        coordinator=ScanCoordinator(run_store=run_store, workflow_starter=_Starter()),
        run_store=run_store,
        findings_reader=InMemoryScanStore(),
        schedule_service=ScheduleService(store=InMemoryScheduleStore(), scheduler=_Scheduler()),
        settings=DeploymentSettings(account_id=CENTRAL),
        accounts=directory,
        trigger_account_sync=(lambda: syncs.append(True)) if syncs is not None else None,
    )
    return api, run_store


def _scanner_for(account_ids_seen):
    def scanner(region: str, account_id: str) -> str:
        account_ids_seen.append(account_id)
        return json.dumps({
            "resources": [{"resource_name": f"data-{account_id}", "resource_arn": f"arn:aws:s3:::data-{account_id}",
                           "region": region, "encryption_at_rest": False}],
            "flows": [],
        })

    return scanner


def test_multi_account_scan_fans_out_per_account_and_attributes_findings():
    directory, _ = _directory()
    api, run_store = _api(directory)
    accepted = api.create_scan(
        {"scanRegions": ["eu-west-1"], "services": ["s3"], "regulations": ["gdpr"], "accountIds": [A, B]},
        account_id=CENTRAL,
    )
    run = run_store.get(accepted["scanRunId"])
    assert run.target_account_ids == [A, B]
    assert {item.account_id for item in plan_work_items(run)} == {A, B}

    seen: list[str] = []
    scan_store = InMemoryScanStore()
    workflow = DeterministicScanWorkflow(
        run_store=run_store, scan_store=scan_store, scanners={ScanService.S3: _scanner_for(seen)},
        account_eligible=directory.is_scannable,
    )
    completed = workflow.execute(run.scan_run_id)

    assert completed.status == ScanStatus.COMPLETE
    assert sorted(seen) == [A, B]
    findings = scan_store.get_findings(run.scan_run_id)
    assert {finding["account_id"] for finding in findings} == {A, B}
    response = api.get_scan(run.scan_run_id)
    assert response["targetAccountIds"] == [A, B]
    assert response["request"]["accountIds"] == [A, B]


def test_an_account_excluded_after_acceptance_is_skipped_as_a_coverage_gap():
    directory, registry = _directory()
    api, run_store = _api(directory)
    run_id = api.create_scan({"scanRegions": ["eu-west-1"], "services": ["s3"], "accountIds": [A, B]},
                             account_id=CENTRAL)["scanRunId"]
    directory.set_administrator_exclusion(B, excluded=True, note="Under review")

    seen: list[str] = []
    completed = DeterministicScanWorkflow(
        run_store=run_store, scan_store=InMemoryScanStore(), scanners={ScanService.S3: _scanner_for(seen)},
        account_eligible=directory.is_scannable,
    ).execute(run_id)

    assert seen == [A]
    assert completed.status == ScanStatus.PARTIAL
    assert completed.progress.coverage_gap_count == 1


def test_scans_reject_accounts_that_are_not_onboarded_and_respect_the_account_limit():
    directory, _ = _directory(max_accounts=2)
    api, _ = _api(directory)

    with pytest.raises(ValueError, match="not onboarded"):
        api.create_scan({"scanRegions": ["eu-west-1"], "accountIds": [A, C]}, account_id=CENTRAL)
    with pytest.raises(ValueError, match="at most 2"):
        api.create_scan({"scanRegions": ["eu-west-1"]}, account_id=CENTRAL)  # central + A + B


def test_scans_are_bounded_to_the_work_unit_limit():
    many = [f"{index:012d}" for index in range(1, 46)]
    registry = InMemoryAccountRegistry()
    for account_id in many:
        registry.save(MemberAccount(account_id=account_id, status=AccountStatus.ONBOARDED))
    settings = OrganizationSettings(mode="AWS_ORGANIZATIONS", deployment_account_id=CENTRAL,
                                    max_accounts_per_scan=200)
    api, _ = _api(AccountDirectory(settings=settings, registry=registry))
    regions = ["eu-west-1", "eu-central-1", "us-east-1", "us-west-2"]

    with pytest.raises(ValueError, match=str(MAX_WORK_UNITS)):
        api.create_scan({"scanRegions": regions, "accountIds": many}, account_id=CENTRAL)  # 45 x (4 x 6 + 2)


def test_schedules_validate_their_account_selection():
    directory, _ = _directory()
    api, _ = _api(directory)

    with pytest.raises(ValueError, match="not onboarded"):
        api.create_schedule(
            {"name": "weekly", "scheduleExpression": "rate(7 days)",
             "scanRequest": {"scanRegions": ["eu-west-1"], "accountIds": [C]}},
            requester_subject="admin",
        )


def test_fingerprints_of_requests_without_accounts_are_unchanged_by_multi_account_support():
    request = ScanRequest(scan_regions=["eu-west-1"], services=[ScanService.S3], regulations=["gdpr"])
    legacy_payload = request.model_dump(mode="json")
    legacy_payload.pop("account_ids")
    import hashlib

    legacy = hashlib.sha256(json.dumps(legacy_payload, separators=(",", ":"), sort_keys=True).encode()).hexdigest()
    assert request_fingerprint(request) == legacy
    assert request_fingerprint(request.model_copy(update={"account_ids": [A]})) != legacy


def test_configuration_reports_organization_mode_and_account_counts():
    from sovereign_shield.services.authorization import RequestPrincipal

    directory, _ = _directory()
    api, _ = _api(directory)

    organization = api.get_configuration(RequestPrincipal("admin", frozenset({"SovereignShieldAdministrators"})))[
        "organization"
    ]

    assert organization["mode"] == "AWS_ORGANIZATIONS"
    assert organization["scannableAccountIds"] == [CENTRAL, A, B]
    assert organization["accountsByStatus"] == {"deployment_account": 1, "failed": 1, "onboarded": 2}
    assert organization["maxWorkUnits"] == MAX_WORK_UNITS


# ── HTTP transport ──────────────────────────────────────────


@pytest.fixture
def transport(monkeypatch):
    directory, registry = _directory()
    syncs: list[bool] = []
    api, _ = _api(directory, syncs)
    log = InMemoryAuditLog()
    monkeypatch.setattr(lambda_handler, "_get_v1_api_service", lambda: api)
    monkeypatch.setattr(lambda_handler, "_get_audit_log", lambda: log)
    monkeypatch.setattr(lambda_handler, "_get_audit_recorder", lambda: AuditRecorder(log))
    return registry, syncs, log


def _event(path, method, groups=("SovereignShieldAdministrators",), body=None):
    event = {
        "rawPath": path,
        "requestContext": {"http": {"method": method},
                           "authorizer": {"jwt": {"claims": {"sub": "user-1", "cognito:groups": list(groups)}}}},
    }
    if body is not None:
        event["body"] = json.dumps(body)
    return event


def test_accounts_routes_list_sync_and_exclude_with_role_checks_and_audit(transport):
    registry, syncs, log = transport
    auditor = ("SovereignShieldAuditors",)

    listed = lambda_handler.handler(_event("/v1/accounts", "GET", groups=auditor), None)
    denied_sync = lambda_handler.handler(_event("/v1/accounts/sync", "POST", groups=auditor), None)
    sync = lambda_handler.handler(_event("/v1/accounts/sync", "POST"), None)
    excluded = lambda_handler.handler(
        _event(f"/v1/accounts/{A}", "PATCH", body={"excluded": True, "note": "Pending review"}), None
    )
    denied_patch = lambda_handler.handler(
        _event(f"/v1/accounts/{A}", "PATCH", groups=auditor, body={"excluded": False}), None
    )

    accounts = json.loads(listed["body"])["accounts"]
    assert listed["statusCode"] == 200
    assert {account["accountId"]: account["status"] for account in accounts}[C] == "failed"
    assert denied_sync["statusCode"] == 403 and denied_patch["statusCode"] == 403
    assert sync["statusCode"] == 202 and syncs == [True]
    assert excluded["statusCode"] == 200
    assert registry.get(A).status == AccountStatus.EXCLUDED
    actions = {(event.action, event.outcome.value) for event in log.events}
    assert {("accounts.sync", "succeeded"), ("accounts.update", "succeeded"),
            ("accounts.sync", "denied"), ("accounts.update", "denied")} <= actions


def test_reincluding_a_configuration_excluded_account_returns_conflict(transport, monkeypatch):
    registry, _, _ = transport
    registry.save(MemberAccount(account_id=B, status=AccountStatus.EXCLUDED, exclusion_reason="denylist"))

    response = lambda_handler.handler(_event(f"/v1/accounts/{B}", "PATCH", body={"excluded": False}), None)

    assert response["statusCode"] == 409


def test_findings_can_be_filtered_by_account(transport):
    response = lambda_handler.handler(
        {**_event("/v1/scans/run-1/findings", "GET"), "queryStringParameters": {"accountId": A}}, None
    )
    # Unknown run in this fixture -> 404, proving the parameter is accepted rather than rejected (400).
    assert response["statusCode"] == 404


def test_single_account_deployments_list_only_their_own_account(monkeypatch):
    api, _ = _api(directory=None)
    monkeypatch.setattr(lambda_handler, "_get_v1_api_service", lambda: api)
    monkeypatch.setattr(lambda_handler, "_get_audit_recorder", lambda: AuditRecorder(InMemoryAuditLog()))

    response = lambda_handler.handler(_event("/v1/accounts", "GET"), None)

    body = json.loads(response["body"])
    assert body["organizationMode"] == "SINGLE_ACCOUNT"
    assert [account["accountId"] for account in body["accounts"]] == [CENTRAL]


def test_scheduled_runs_resolve_accounts_at_admission_and_reject_ineligible_ones(monkeypatch):
    from sovereign_shield import workflow_handler
    from sovereign_shield.models.contracts import ScanSchedule

    directory, _ = _directory()
    run_store = InMemoryScanRunStore()

    def schedule_for(accounts):
        request = ScanRequest(scan_regions=["eu-west-1"], services=[ScanService.S3], account_ids=accounts)
        return ScanSchedule(schedule_id="s-1", name="weekly", schedule_expression="rate(7 days)",
                            request=request, request_fingerprint=request_fingerprint(request))

    class _Store:
        schedule = None

        def __init__(self, *, runs_table):
            pass

        def get(self, schedule_id):
            return _Store.schedule

    monkeypatch.setenv("SCHEDULED_SCANS_ENABLED", "true")
    monkeypatch.setenv("DEPLOYMENT_ACCOUNT_ID", CENTRAL)
    monkeypatch.setattr(workflow_handler, "DynamoDBScheduleStore", _Store)
    monkeypatch.setattr(workflow_handler, "_runs_table", lambda: None)
    monkeypatch.setattr(workflow_handler, "_get_run_store", lambda: run_store)
    monkeypatch.setattr(workflow_handler, "_account_directory", lambda: directory)

    _Store.schedule = schedule_for([A, B])
    admitted = workflow_handler.handler(
        {"action": "admit_scheduled_run", "scheduleId": "s-1", "executionArn": "arn:exec:1"}, None
    )
    assert run_store.get(admitted["scanRunId"]).target_account_ids == [A, B]

    _Store.schedule = schedule_for([C])
    with pytest.raises(ValueError, match="not available"):
        workflow_handler.handler({"action": "admit_scheduled_run", "scheduleId": "s-1", "executionArn": "arn:exec:2"},
                                 None)


def test_onboarding_probe_always_uses_fresh_member_role_credentials(monkeypatch):
    from sovereign_shield import onboarding_handler
    from sovereign_shield.tools import aws_scanner

    issued = []

    def fake_credentials(account_id):
        issued.append(account_id)
        return {"AccessKeyId": "a", "SecretAccessKey": "s", "SessionToken": "t"}

    class _Sts:
        def get_caller_identity(self):
            return {"Account": A}

    monkeypatch.setattr(aws_scanner, "_assumed_credentials", {A: {"stale": True}})
    monkeypatch.setattr(aws_scanner, "member_role_credentials", fake_credentials)
    monkeypatch.setattr(onboarding_handler.boto3, "client", lambda *args, **kwargs: _Sts())

    onboarding_handler.probe_member_role(A)

    assert issued == [A]
    assert A not in aws_scanner._assumed_credentials
