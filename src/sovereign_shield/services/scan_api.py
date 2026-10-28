"""Transport-neutral API service for asynchronous scan operations."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from sovereign_shield.models.contracts import ReportGenerationMode, ScanRequest, ScanRun, ScanService
from sovereign_shield.regulations import ALL_REGULATIONS
from sovereign_shield.services.accounts import AccountDirectory, OrganizationSettings, account_response
from sovereign_shield.services.authorization import RequestPrincipal, allowed_actions, roles_for
from sovereign_shield.services.guidance import guidance_for
from sovereign_shield.services.policy_evaluator import RULE_PACK_VERSION
from sovereign_shield.services.scan_engine import GLOBAL_SERVICES
from sovereign_shield.services.scan_lifecycle import MAX_WORK_UNITS, ScanCoordinator, ScanRunStore, target_accounts
from sovereign_shield.services.scheduling import ScheduleService

# Commercial-partition regions offered for scanning. GovCloud and China are
# excluded until tested (plan.md section 2.2). Opt-in regions that are not
# enabled in an account surface as coverage gaps rather than failures.
COMMERCIAL_SCAN_REGIONS = (
    "af-south-1", "ap-east-1", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
    "ap-south-1", "ap-south-2", "ap-southeast-1", "ap-southeast-2", "ap-southeast-3",
    "ap-southeast-4", "ca-central-1", "eu-central-1", "eu-central-2", "eu-north-1",
    "eu-south-1", "eu-south-2", "eu-west-1", "eu-west-2", "eu-west-3", "il-central-1",
    "me-central-1", "me-south-1", "sa-east-1", "us-east-1", "us-east-2", "us-west-1",
    "us-west-2",
)
REPORT_LINK_TTL = timedelta(minutes=5)


class FindingsReader(Protocol):
    """Read-only findings pagination boundary shared by API adapters."""

    def get_findings_page(
        self,
        scan_run_id: str,
        *,
        limit: int,
        cursor: str | None = None,
        filters: dict[str, str] | None = None,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Return one server-side page of stored finding records."""


class ReportLinkSigner(Protocol):
    """Issues short-lived, read-only links to one private report object."""

    def sign(self, *, object_key: str, filename: str, expires_in: timedelta) -> str:
        """Return a pre-signed download URL."""


class S3ReportLinkSigner:
    """S3 pre-signed GET URLs that force download as an attachment."""

    def __init__(self, *, client: Any, bucket_name: str) -> None:
        self._client = client
        self._bucket_name = bucket_name

    def sign(self, *, object_key: str, filename: str, expires_in: timedelta) -> str:
        if not object_key.startswith("reports/"):
            raise ValueError("Only report objects can be shared.")
        return str(
            self._client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self._bucket_name,
                    "Key": object_key,
                    "ResponseContentDisposition": f'attachment; filename="{filename}"',
                },
                ExpiresIn=int(expires_in.total_seconds()),
            )
        )


@dataclass(frozen=True)
class DeploymentSettings:
    """Safe, read-only deployment facts surfaced by GET /v1/configuration."""

    account_id: str = ""
    region: str = ""
    release_version: str = "development"
    operations_dashboard_url: str = ""
    administrator_settings: dict[str, Any] = field(default_factory=dict)
    scheduled_scans_enabled: bool = True
    default_scan_regions: tuple[str, ...] = ()


class SchedulingDisabledError(RuntimeError):
    """Raised when an administrator creates a schedule but the deployment disables scheduled scans."""


class ScanApiService:
    """Implements the public behavior of the v1 scan API without HTTP coupling."""

    def __init__(
        self,
        *,
        coordinator: ScanCoordinator,
        run_store: ScanRunStore,
        findings_reader: FindingsReader,
        schedule_service: ScheduleService | None = None,
        report_links: ReportLinkSigner | None = None,
        settings: DeploymentSettings | None = None,
        accounts: AccountDirectory | None = None,
        trigger_account_sync: Callable[[], None] | None = None,
    ) -> None:
        self._coordinator = coordinator
        self._run_store = run_store
        self._findings_reader = findings_reader
        self._schedule_service = schedule_service
        self._report_links = report_links
        self._settings = settings or DeploymentSettings()
        self._accounts = accounts
        self._trigger_account_sync = trigger_account_sync

    def list_accounts(self) -> dict[str, Any]:
        """Onboarding state of every account this deployment may scan."""

        accounts = self._account_directory().list_accounts()
        return {
            "organizationMode": self._account_directory().settings.mode,
            "accounts": [account_response(account) for account in accounts],
        }

    def request_account_sync(self) -> dict[str, Any]:
        """Start an onboarding sync in the background; results appear on the accounts list."""

        if self._trigger_account_sync is None:
            raise RuntimeError("Account sync is not configured.")
        self._trigger_account_sync()
        return {"syncRequested": True}

    def update_account(self, account_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Exclude or re-include a member account (administrators; audited)."""

        _reject_unknown_fields(payload, {"excluded", "note"})
        excluded = _optional_bool(payload.get("excluded"), default=None)
        if excluded is None:
            raise ValueError("excluded is required.")
        note = payload.get("note", "")
        if not isinstance(note, str) or len(note) > 256:
            raise ValueError("note must be a string of at most 256 characters.")
        account = self._account_directory().set_administrator_exclusion(account_id, excluded=excluded, note=note)
        return account_response(account)

    def _account_directory(self) -> AccountDirectory:
        if self._accounts is None:
            return AccountDirectory(
                settings=OrganizationSettings(deployment_account_id=self._settings.account_id), registry=None
            )
        return self._accounts

    def _resolve_accounts(self, request: ScanRequest, account_id: str) -> list[str] | None:
        if self._accounts is None:
            return None
        return self._accounts.resolve_targets(list(request.account_ids))

    def get_configuration(self, principal: RequestPrincipal) -> dict[str, Any]:
        """Return supported scan choices and the caller's roles; no secrets or ARNs."""

        regulations = [
            {
                "id": regulation.id,
                "name": regulation.name,
                "jurisdiction": regulation.jurisdiction,
                "dataCategories": sorted(
                    {category for constraint in regulation.constraints for category in constraint.data_categories}
                ),
            }
            for regulation in ALL_REGULATIONS.regulations
        ]
        response: dict[str, Any] = {
            "caller": {
                "subject": principal.subject,
                "roles": roles_for(principal),
                "allowedActions": allowed_actions(principal),
            },
            "scanChoices": {
                "regions": list(COMMERCIAL_SCAN_REGIONS),
                "maxRegions": 25,
                "services": [
                    {"id": service.value, "global": service in GLOBAL_SERVICES} for service in ScanService
                ],
                "regulations": regulations,
                "dataCategories": sorted({c for regulation in regulations for c in regulation["dataCategories"]}),
                "reportGenerationModes": [ReportGenerationMode.DETERMINISTIC_ONLY.value],
                "minimumScheduleInterval": "rate(1 hour)",
                "defaultRegions": [
                    region for region in self._settings.default_scan_regions if region in COMMERCIAL_SCAN_REGIONS
                ],
                "scheduledScansEnabled": self._settings.scheduled_scans_enabled,
            },
            "organization": self._organization_summary(),
            "deployment": {
                "accountId": self._settings.account_id,
                "region": self._settings.region,
                "releaseVersion": self._settings.release_version,
                "rulePackVersion": RULE_PACK_VERSION,
                "operationsDashboardUrl": self._settings.operations_dashboard_url,
            },
        }
        if "administrator" in response["caller"]["roles"]:
            response["settings"] = dict(self._settings.administrator_settings)
        return response

    def _organization_summary(self) -> dict[str, Any]:
        directory = self._account_directory()
        settings = directory.settings
        accounts = directory.list_accounts()
        counts: dict[str, int] = {}
        for account in accounts:
            counts[account.status.value] = counts.get(account.status.value, 0) + 1
        return {
            "mode": settings.mode,
            "organizationId": settings.organization_id,
            "targetOrganizationalUnitIds": list(settings.target_ou_ids),
            "maxAccountsPerScan": settings.max_accounts_per_scan if settings.organizations else 1,
            "maxWorkUnits": MAX_WORK_UNITS,
            "accountsByStatus": dict(sorted(counts.items())),
            "scannableAccountIds": [account.account_id for account in accounts if account.scannable],
        }

    def list_scans(self, *, limit: int = 20, cursor: str | None = None) -> dict[str, Any]:
        """Return a newest-first page of scan runs."""

        _require_limit(limit)
        runs, next_cursor = self._run_store.list_recent(limit=limit, cursor=cursor)
        return {"scans": [_scan_run_response(run) for run in runs], "nextCursor": next_cursor}

    def list_schedules(self, *, limit: int = 50, cursor: str | None = None) -> dict[str, Any]:
        """Return a newest-first page of schedule definitions."""

        _require_limit(limit)
        schedules, next_cursor = self._schedule_manager().list_recent(limit=limit, cursor=cursor)
        return {"schedules": [_schedule_response(schedule) for schedule in schedules], "nextCursor": next_cursor}

    def create_scan(
        self,
        payload: dict[str, Any],
        *,
        account_id: str = "",
        requester_subject: str = "",
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        """Validate and accept a scan request without awaiting its work."""

        request = ScanRequest.model_validate(_normalize_request_payload(payload))
        submission = self._coordinator.submit(
            request,
            account_id=account_id,
            requester_subject=requester_subject,
            correlation_id=correlation_id,
            target_account_ids=self._resolve_accounts(request, account_id),
        )
        return {
            "scanRunId": submission.run.scan_run_id,
            "status": submission.run.status.value,
            "correlationId": submission.run.correlation_id,
            "created": submission.created,
        }

    def get_scan(self, scan_run_id: str) -> dict[str, Any]:
        """Return bounded scan-run state suitable for polling."""

        run = self._required_run(scan_run_id)
        return _scan_run_response(run)

    def cancel_scan(self, scan_run_id: str) -> dict[str, Any]:
        """Request safe cancellation; this does not interrupt an AWS call."""

        run = self._coordinator.request_cancellation(scan_run_id)
        return _scan_run_response(run)

    def get_findings(
        self,
        scan_run_id: str,
        *,
        limit: int = 50,
        cursor: str | None = None,
        filters: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Return a bounded, optionally filtered page of persisted findings."""

        self._required_run(scan_run_id)
        _require_limit(limit)
        findings, next_cursor = self._findings_reader.get_findings_page(
            scan_run_id,
            limit=limit,
            cursor=cursor,
            filters=filters,
        )
        return {
            "scanRunId": scan_run_id,
            "findings": [{**finding, "guidance": guidance_for(finding)} for finding in findings],
            "nextCursor": next_cursor,
        }

    def get_report(self, scan_run_id: str) -> dict[str, Any]:
        """Return report metadata and, when configured, a short-lived download link."""

        run = self._required_run(scan_run_id)
        if run.report is None:
            raise KeyError(f"No report available for scan run: {scan_run_id}")
        response: dict[str, Any] = {"scanRunId": scan_run_id, "report": run.report, "download": None}
        if self._report_links is not None:
            expires_at = datetime.now(timezone.utc) + REPORT_LINK_TTL
            response["download"] = {
                "url": self._report_links.sign(
                    object_key=str(run.report["object_key"]),
                    filename=f"sovereign-shield-{scan_run_id}.md",
                    expires_in=REPORT_LINK_TTL,
                ),
                "expiresAt": expires_at.isoformat(),
            }
        return response

    def create_schedule(
        self,
        payload: dict[str, Any],
        *,
        requester_subject: str,
    ) -> dict[str, Any]:
        """Create an explicitly enabled schedule from a versioned scan request."""

        if not self._settings.scheduled_scans_enabled:
            raise SchedulingDisabledError("Scheduled scans are disabled for this deployment.")
        allowed_fields = {"name", "scheduleExpression", "scanRequest", "enabled"}
        _reject_unknown_fields(payload, allowed_fields)
        try:
            name = str(payload["name"])
            schedule_expression = str(payload["scheduleExpression"])
            request_payload = payload["scanRequest"]
        except KeyError as exc:
            raise ValueError(f"Missing required schedule field: {exc.args[0]}.") from exc
        if not isinstance(request_payload, dict):
            raise ValueError("scanRequest must be an object.")
        scheduled_request = ScanRequest.model_validate(_normalize_request_payload(request_payload))
        # Validate the account selection now; it is resolved again at every run.
        self._resolve_accounts(scheduled_request, self._settings.account_id)
        schedule = self._schedule_manager().create(
            name=name,
            schedule_expression=schedule_expression,
            request=scheduled_request,
            requester_subject=requester_subject,
            enabled=_optional_bool(payload.get("enabled"), default=True),
        )
        return _schedule_response(schedule)

    def update_schedule(self, schedule_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Update only explicitly supported schedule fields."""

        allowed_fields = {"scheduleExpression", "scanRequest", "enabled"}
        _reject_unknown_fields(payload, allowed_fields)
        request_payload = payload.get("scanRequest")
        if request_payload is not None and not isinstance(request_payload, dict):
            raise ValueError("scanRequest must be an object.")
        schedule = self._schedule_manager().update(
            schedule_id,
            schedule_expression=payload.get("scheduleExpression"),
            request=(
                ScanRequest.model_validate(_normalize_request_payload(request_payload))
                if request_payload is not None
                else None
            ),
            enabled=_optional_bool(payload.get("enabled"), default=None),
        )
        return _schedule_response(schedule)

    def delete_schedule(self, schedule_id: str) -> None:
        """Delete the EventBridge schedule and its durable definition."""

        self._schedule_manager().delete(schedule_id)

    def _required_run(self, scan_run_id: str) -> ScanRun:
        run = self._run_store.get(scan_run_id)
        if run is None:
            raise KeyError(f"Unknown scan run: {scan_run_id}")
        return run

    def _schedule_manager(self) -> ScheduleService:
        if self._schedule_service is None:
            raise RuntimeError("Schedule management is not configured.")
        return self._schedule_service


def _normalize_request_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Accept the documented camelCase API fields, rejecting ambiguous extras."""

    aliases = {
        "schemaVersion": "schema_version",
        "scanRegions": "scan_regions",
        "reportGenerationMode": "report_generation_mode",
        "idempotencyKey": "idempotency_key",
        "dataCategories": "data_categories",
        "accountIds": "account_ids",
    }
    normalized: dict[str, Any] = {}
    for key, value in payload.items():
        normalized_key = aliases.get(key, key)
        if normalized_key in normalized:
            raise ValueError(f"Duplicate request field: {normalized_key}.")
        normalized[normalized_key] = value
    return normalized


def _scan_run_response(run: ScanRun) -> dict[str, Any]:
    """Avoid returning internal request fingerprints or full persisted evidence."""

    return {
        "scanRunId": run.scan_run_id,
        "status": run.status.value,
        "correlationId": run.correlation_id,
        "executionArn": run.execution_arn,
        "progress": run.progress.model_dump(mode="json"),
        "errorSummary": run.error_summary,
        "createdAt": run.created_at.isoformat(),
        "updatedAt": run.updated_at.isoformat(),
        "startedAt": run.started_at.isoformat() if run.started_at else None,
        "completedAt": run.completed_at.isoformat() if run.completed_at else None,
        "report": run.report,
        "request": _request_summary(run.request),
        "requesterSubject": run.requester_subject,
        "targetAccountIds": target_accounts(run),
    }


def _request_summary(request: ScanRequest) -> dict[str, Any]:
    return {
        "scanRegions": list(request.scan_regions),
        "services": [service.value for service in request.services],
        "regulations": list(request.regulations),
        "dataCategories": list(request.data_categories),
        "reportGenerationMode": request.report_generation_mode.value,
        "accountIds": list(request.account_ids),
    }


def _require_limit(limit: int) -> None:
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100.")


def _schedule_response(schedule) -> dict[str, Any]:
    return {
        "scheduleId": schedule.schedule_id,
        "name": schedule.name,
        "scheduleExpression": schedule.schedule_expression,
        "enabled": schedule.enabled,
        "request": _request_summary(schedule.request),
        "requesterSubject": schedule.requester_subject,
        "schedulerArn": schedule.scheduler_arn,
        "createdAt": schedule.created_at.isoformat(),
        "updatedAt": schedule.updated_at.isoformat(),
    }


def _reject_unknown_fields(payload: dict[str, Any], allowed_fields: set[str]) -> None:
    unknown_fields = sorted(set(payload) - allowed_fields)
    if unknown_fields:
        raise ValueError(f"Unknown request field: {unknown_fields[0]}.")


def _optional_bool(value: Any, *, default: bool | None) -> bool | None:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ValueError("enabled must be a boolean.")
    return value


__all__ = ["DeploymentSettings", "S3ReportLinkSigner", "ScanApiService", "SchedulingDisabledError"]
