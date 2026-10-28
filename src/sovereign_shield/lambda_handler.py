"""AWS Lambda handler for Sovereign Shield — API Gateway + direct invocation compatible."""

from __future__ import annotations

import json
import logging
import os
import traceback
from functools import lru_cache
from typing import Any

from sovereign_shield.services import (
    DeploymentSettings,
    DynamoDBScanRunStore,
    DynamoDBScanStore,
    DynamoDBScheduleStore,
    EventBridgeSchedulerClient,
    S3ReportLinkSigner,
    ScanApiService,
    ScanCoordinator,
    ScheduleService,
    StepFunctionsWorkflowStarter,
)
from sovereign_shield.services.accounts import AccountDirectory, DynamoDBAccountRegistry, OrganizationSettings
from sovereign_shield.services.audit import (
    AuditOutcome,
    AuditRecorder,
    DynamoDBAuditLog,
    InMemoryAuditLog,
    audit_event_response,
    current_month,
)
from sovereign_shield.services.authorization import (
    ApiAction,
    AuthorizationError,
    authorize,
    principal_from_claims,
)
from sovereign_shield.services.scan_api import SchedulingDisabledError
from sovereign_shield.services.scan_lifecycle import IndexUnavailableError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Allow-Methods": "POST,OPTIONS",
}
# v1 routes sit behind an HTTP API whose CORS policy allows only configured
# console origins, so the function must not add its own wildcard headers.
V1_HEADERS = {"Content-Type": "application/json"}


def handler(event, context):
    """Lambda handler supporting API Gateway proxy, direct invocation, and EventBridge.

    API Gateway POST body / direct event format:
    {
        "action": "scan" | "chat" | "check_violations" | "generate_scp" | "generate_remediation",
        "accounts": "123456789012,234567890123",
        "regions": "us-east-1,eu-west-1",
        "regulations": "gdpr,dpdp",
        "prompt": "...",
        "scan_results": {...},
        "violations": {...},
        "prohibited_regions": "...",
        "allowed_services": "...",
        "policy_name": "..."
    }
    """
    if _http_method(event) == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    if _request_path(event).startswith("/v1/"):
        return _handle_v1_request(event)
    body = _parse_event(event)

    action = body.get("action", "scan")

    try:
        if action == "scan":
            result = _handle_scan(body)
        elif action == "chat":
            result = _handle_chat(body)
        elif action == "check_violations":
            result = _handle_check_violations(body)
        elif action == "generate_scp":
            result = _handle_generate_scp(body)
        elif action == "generate_remediation":
            result = _handle_generate_remediation(body)
        else:
            return _response(400, {"error": f"Unknown action: {action}"})

        return _response(200, result)

    except Exception as e:
        logger.error("Handler error: %s\n%s", e, traceback.format_exc())
        return _response(500, {"error": str(e)})


def _handle_v1_request(event: dict[str, Any]) -> dict[str, Any]:
    """Route asynchronous v1 API paths without falling back to legacy actions."""

    path = _request_path(event).rstrip("/")
    method = _http_method(event)
    principal = _request_principal(event)
    correlation_id = _correlation_id(event) or ""
    audit = _get_audit_recorder()
    route = _match_route(method, path)
    if route is None:
        return _v1_response(404, {"error": "Unknown API route."})
    name, action, target_id = route
    try:
        authorize(principal, action)
    except AuthorizationError:
        # Route name only: subjects and claims stay out of logs. Counted by a metric filter.
        logger.warning("AUTHORIZATION_DENIED route=%s", name)
        audit.record(
            actor_subject=principal.subject, action=name, target_type=_target_type(name),
            target_id=target_id, outcome=AuditOutcome.DENIED, correlation_id=correlation_id,
        )
        return _v1_response(403, {"error": "Not authorized."})

    api = _get_v1_api_service()
    parameters = event.get("queryStringParameters") or {}
    try:
        status, response = _dispatch(name, api, event, parameters, principal, target_id)
    except KeyError:
        return _v1_response(404, {"error": "Not found."})
    except PermissionError:
        # Account rule violations (for example, re-including a denylisted account).
        # Authorization was already enforced before dispatch.
        return _v1_response(409, {"error": "The account's exclusion is set by deployment configuration."})
    except SchedulingDisabledError:
        return _v1_response(409, {"error": "Scheduled scans are disabled for this deployment."})
    except IndexUnavailableError:
        # After an upgrade adds an index, DynamoDB backfills it before queries succeed.
        message = "Listing is temporarily unavailable while the stack finishes upgrading."
        response = _v1_response(503, {"error": message})
        response["headers"] = {**response["headers"], "Retry-After": "60"}
        return response
    except (TypeError, ValueError) as exc:
        logger.info("Rejected v1 request %s: %s", name, type(exc).__name__)
        if name in _AUDITED_ROUTES:
            audit.record(
                actor_subject=principal.subject, action=name, target_type=_target_type(name),
                target_id=target_id, outcome=AuditOutcome.REJECTED, correlation_id=correlation_id,
            )
        return _v1_response(400, {"error": "Invalid request."})
    except Exception:  # noqa: BLE001 - never return AWS internals to the API caller
        logger.exception("v1 API request failed")
        return _v1_response(500, {"error": "Request could not be processed."})

    if name in _AUDITED_ROUTES:
        audit.record(
            actor_subject=principal.subject,
            action=name,
            target_type=_target_type(name),
            target_id=target_id or str(response.get("scanRunId") or response.get("scheduleId") or ""),
            outcome=AuditOutcome.SUCCEEDED,
            correlation_id=correlation_id,
            details=_audit_details(name, response),
        )
    return _v1_response(status, response)


# (route name, method, path pattern, required action). `{id}` matches one segment.
_ROUTES: tuple[tuple[str, str, str, ApiAction], ...] = (
    ("configuration.view", "GET", "/v1/configuration", ApiAction.VIEW_CONFIGURATION),
    ("scan.list", "GET", "/v1/scans", ApiAction.VIEW_SCAN),
    ("scan.start", "POST", "/v1/scans", ApiAction.START_SCAN),
    ("scan.view", "GET", "/v1/scans/{id}", ApiAction.VIEW_SCAN),
    ("scan.cancel", "POST", "/v1/scans/{id}/cancel", ApiAction.CANCEL_SCAN),
    ("findings.list", "GET", "/v1/scans/{id}/findings", ApiAction.VIEW_FINDINGS),
    ("report.view", "GET", "/v1/scans/{id}/report", ApiAction.VIEW_REPORT),
    ("schedule.list", "GET", "/v1/schedules", ApiAction.VIEW_SCHEDULES),
    ("schedule.create", "POST", "/v1/schedules", ApiAction.MANAGE_SCHEDULE),
    ("schedule.update", "PATCH", "/v1/schedules/{id}", ApiAction.MANAGE_SCHEDULE),
    ("schedule.delete", "DELETE", "/v1/schedules/{id}", ApiAction.MANAGE_SCHEDULE),
    ("audit.list", "GET", "/v1/audit-events", ApiAction.VIEW_AUDIT_LOG),
    ("accounts.list", "GET", "/v1/accounts", ApiAction.VIEW_ACCOUNTS),
    ("accounts.sync", "POST", "/v1/accounts/sync", ApiAction.MANAGE_ACCOUNTS),
    ("accounts.update", "PATCH", "/v1/accounts/{id}", ApiAction.MANAGE_ACCOUNTS),
)
# Mutations and report-link issuance are audited; reads of lists are not.
_AUDITED_ROUTES = frozenset(
    {
        "scan.start", "scan.cancel", "schedule.create", "schedule.update", "schedule.delete", "report.view",
        "accounts.sync", "accounts.update",
    }
)
_FINDING_FILTER_PARAMETERS = {
    "severity": "severity",
    "ruleId": "rule_id",
    "region": "region",
    "service": "service",
    "findingState": "finding_state",
    "accountId": "account_id",
}


def _match_route(method: str, path: str) -> tuple[str, ApiAction, str] | None:
    segments = path.split("/")
    for name, route_method, pattern, action in _ROUTES:
        pattern_segments = pattern.split("/")
        if method != route_method or len(segments) != len(pattern_segments):
            continue
        target_id = ""
        for segment, expected in zip(segments, pattern_segments):
            if expected == "{id}":
                if not _is_identifier(segment):
                    break
                target_id = segment
            elif segment != expected:
                break
        else:
            return name, action, target_id
    return None


def _dispatch(
    name: str,
    api: ScanApiService,
    event: dict[str, Any],
    parameters: dict[str, str],
    principal: Any,
    target_id: str,
) -> tuple[int, dict[str, Any]]:
    if name == "configuration.view":
        return 200, api.get_configuration(principal)
    if name == "scan.list":
        return 200, api.list_scans(limit=_limit(parameters, 20), cursor=parameters.get("cursor"))
    if name == "scan.start":
        return 202, api.create_scan(
            _v1_body(event),
            account_id=os.environ.get("DEPLOYMENT_ACCOUNT_ID", ""),
            requester_subject=principal.subject,
            correlation_id=_correlation_id(event),
        )
    if name == "scan.view":
        return 200, api.get_scan(target_id)
    if name == "scan.cancel":
        return 202, api.cancel_scan(target_id)
    if name == "findings.list":
        unknown = set(parameters) - {"limit", "cursor", *_FINDING_FILTER_PARAMETERS}
        if unknown:
            raise ValueError("Unsupported query parameter.")
        filters = {
            field: parameters[parameter]
            for parameter, field in _FINDING_FILTER_PARAMETERS.items()
            if parameters.get(parameter)
        }
        return 200, api.get_findings(
            target_id, limit=_limit(parameters, 50), cursor=parameters.get("cursor"), filters=filters
        )
    if name == "report.view":
        return 200, api.get_report(target_id)
    if name == "schedule.list":
        return 200, api.list_schedules(limit=_limit(parameters, 50), cursor=parameters.get("cursor"))
    if name == "schedule.create":
        return 201, api.create_schedule(_v1_body(event), requester_subject=principal.subject)
    if name == "schedule.update":
        return 200, api.update_schedule(target_id, _v1_body(event))
    if name == "schedule.delete":
        api.delete_schedule(target_id)
        return 204, {}
    if name == "accounts.list":
        return 200, api.list_accounts()
    if name == "accounts.sync":
        return 202, api.request_account_sync()
    if name == "accounts.update":
        return 200, api.update_account(target_id, _v1_body(event))
    if name == "audit.list":
        month = parameters.get("month") or current_month()
        events, next_cursor = _get_audit_log().list_month(
            month, limit=_limit(parameters, 50), cursor=parameters.get("cursor")
        )
        return 200, {
            "month": month,
            "events": [audit_event_response(audit_event) for audit_event in events],
            "nextCursor": next_cursor,
        }
    raise KeyError(name)


def _target_type(route_name: str) -> str:
    return route_name.split(".")[0]


def _audit_details(route_name: str, response: dict[str, Any]) -> dict[str, str]:
    if route_name == "scan.start":
        return {"created": str(response.get("created", "")).lower()}
    if route_name in {"schedule.create", "schedule.update"}:
        return {"enabled": str(response.get("enabled", "")).lower()}
    if route_name == "report.view":
        return {"downloadLinkIssued": str(bool(response.get("download"))).lower()}
    if route_name == "accounts.update":
        return {"excluded": str(response.get("administratorExcluded", "")).lower()}
    return {}


def _limit(parameters: dict[str, str], default: int) -> int:
    raw = parameters.get("limit")
    if raw is None:
        return default
    if not raw.isdigit():
        raise ValueError("limit must be an integer.")
    return int(raw)


def _is_identifier(segment: str) -> bool:
    return 1 <= len(segment) <= 64 and all(character.isalnum() or character == "-" for character in segment)


def _v1_body(event: dict[str, Any]) -> dict[str, Any]:
    """Parse a v1 JSON object body strictly; never fall back to the raw event."""

    raw = event.get("body")
    if raw in (None, ""):
        return {}
    if event.get("isBase64Encoded"):
        import base64

        raw = base64.b64decode(raw).decode("utf-8")
    try:
        body = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError("Request body must be JSON.") from exc
    if not isinstance(body, dict):
        raise ValueError("Request body must be a JSON object.")
    return body


@lru_cache
def _get_v1_api_service() -> ScanApiService:
    """Build the production adapter graph from deployed resource references."""

    import boto3
    from botocore.config import Config

    runs_table_name = _required_environment("SCAN_RUNS_TABLE")
    findings_table_name = _required_environment("FINDINGS_TABLE")
    state_machine_arn = _required_environment("SCAN_STATE_MACHINE_ARN")
    dynamodb = boto3.resource("dynamodb")
    runs_table = dynamodb.Table(runs_table_name)
    findings_table = dynamodb.Table(findings_table_name)
    retention_days = int(os.environ.get("FINDINGS_RETENTION_DAYS", "0"))
    run_store = DynamoDBScanRunStore(runs_table=runs_table, retention_days=retention_days)
    reports_bucket = os.environ.get("REPORTS_BUCKET")
    report_links = (
        S3ReportLinkSigner(
            # SigV4 with a regional endpoint is required for KMS-encrypted objects.
            client=boto3.client(
                "s3",
                region_name=os.environ.get("AWS_REGION"),
                config=Config(signature_version="s3v4", s3={"addressing_style": "virtual"}),
            ),
            bucket_name=reports_bucket,
        )
        if reports_bucket
        else None
    )
    return ScanApiService(
        coordinator=ScanCoordinator(
            run_store=run_store,
            workflow_starter=StepFunctionsWorkflowStarter(
                client=boto3.client("stepfunctions"),
                state_machine_arn=state_machine_arn,
            ),
        ),
        run_store=run_store,
        findings_reader=DynamoDBScanStore(
            runs_table=runs_table, findings_table=findings_table, retention_days=retention_days
        ),
        schedule_service=ScheduleService(
            store=DynamoDBScheduleStore(runs_table=runs_table),
            scheduler=EventBridgeSchedulerClient(
                client=boto3.client("scheduler"),
                schedule_group_name=_required_environment("SCHEDULE_GROUP_NAME"),
                state_machine_arn=state_machine_arn,
                scheduler_role_arn=_required_environment("SCHEDULER_ROLE_ARN"),
            ),
        ),
        report_links=report_links,
        accounts=_account_directory(runs_table),
        trigger_account_sync=_trigger_account_sync,
        settings=DeploymentSettings(
            account_id=os.environ.get("DEPLOYMENT_ACCOUNT_ID", ""),
            region=os.environ.get("AWS_REGION", ""),
            release_version=os.environ.get("RELEASE_VERSION", "development"),
            operations_dashboard_url=os.environ.get("OPERATIONS_DASHBOARD_URL", ""),
            administrator_settings=json.loads(os.environ.get("ADMINISTRATOR_SETTINGS", "{}")),
            scheduled_scans_enabled=os.environ.get("SCHEDULED_SCANS_ENABLED", "true") == "true",
            default_scan_regions=tuple(
                region for region in os.environ.get("DEFAULT_SCAN_REGIONS", "").split(",") if region
            ),
        ),
    )


def _account_directory(runs_table: Any) -> AccountDirectory:
    settings = OrganizationSettings.from_environment(dict(os.environ))
    registry = DynamoDBAccountRegistry(runs_table=runs_table) if settings.organizations else None
    return AccountDirectory(settings=settings, registry=registry)


def _trigger_account_sync() -> None:
    import boto3

    boto3.client("lambda").invoke(
        FunctionName=_required_environment("ONBOARDING_FUNCTION_NAME"), InvocationType="Event", Payload=b"{}"
    )


@lru_cache
def _get_audit_log() -> Any:
    table_name = os.environ.get("AUDIT_TABLE")
    if not table_name:
        logger.warning("AUDIT_TABLE is not configured; audit events are kept in memory only.")
        return InMemoryAuditLog()
    import boto3

    return DynamoDBAuditLog(table=boto3.resource("dynamodb").Table(table_name))


@lru_cache
def _get_audit_recorder() -> AuditRecorder:
    return AuditRecorder(_get_audit_log())


def _parse_event(event: dict) -> dict:
    """Extract request body from API Gateway proxy event or direct invocation."""
    if "body" in event and isinstance(event["body"], str):
        try:
            return json.loads(event["body"])
        except (json.JSONDecodeError, TypeError):
            return event
    return event


def _request_path(event: dict[str, Any]) -> str:
    return str(event.get("rawPath") or event.get("path") or "")


def _http_method(event: dict[str, Any]) -> str:
    request_context = event.get("requestContext") or {}
    return str(
        event.get("httpMethod")
        or (request_context.get("http") or {}).get("method")
        or ""
    ).upper()


def _request_principal(event: dict[str, Any]):
    claims = (((event.get("requestContext") or {}).get("authorizer") or {}).get("jwt") or {}).get(
        "claims", {}
    )
    return principal_from_claims(claims if isinstance(claims, dict) else {})


def _correlation_id(event: dict[str, Any]) -> str | None:
    headers = event.get("headers") or {}
    return headers.get("x-correlation-id") or headers.get("X-Correlation-Id")


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing required deployment configuration: {name}")
    return value


def _v1_response(status_code: int, body: dict) -> dict:
    return {
        "statusCode": status_code,
        "headers": V1_HEADERS,
        "body": json.dumps(body, default=str),
    }


def _response(status_code: int, body: dict) -> dict:
    return {
        "statusCode": status_code,
        "headers": CORS_HEADERS,
        "body": json.dumps(body, default=str),
    }


def _get_orchestrator():
    from sovereign_shield.agents.orchestrator import create_orchestrator

    model_id = os.environ.get("BEDROCK_MODEL_ID")
    model_region = os.environ.get("BEDROCK_REGION", "us-east-1")
    return create_orchestrator(model_id=model_id, region=model_region)


def _handle_scan(body: dict) -> dict:
    accounts = body.get("accounts", os.environ.get("SCAN_ACCOUNTS", ""))
    regions = body.get("regions", os.environ.get("SCAN_REGIONS", "us-east-1,eu-west-1"))
    regulations = body.get("regulations", "")

    prompt = (
        f"Run a complete sovereignty compliance scan.\n"
        f"Regions: {regions}\n"
        f"Accounts: {accounts}\n"
        f"Regulations: {regulations or 'all'}\n"
        f"Execute the full pipeline: jurisdiction profiling, data flow scanning, "
        f"violation detection, remediation planning, and report generation."
    )

    logger.info("Running scan: regions=%s, regulations=%s", regions, regulations)
    orchestrator = _get_orchestrator()
    result = orchestrator(prompt)
    return {"action": "scan", "result": str(result)}


def _handle_chat(body: dict) -> dict:
    prompt = body.get("prompt", "")
    if not prompt:
        raise ValueError("Missing 'prompt' field")

    orchestrator = _get_orchestrator()
    result = orchestrator(prompt)
    return {"action": "chat", "result": str(result)}


def _handle_check_violations(body: dict) -> dict:
    from sovereign_shield.tools.violation_detector import check_violations

    scan_results = body.get("scan_results")
    regulations = body.get("regulations", "")

    if not scan_results:
        raise ValueError("Missing 'scan_results' field")

    from sovereign_shield.tools.invocation import invoke_tool

    result_str = invoke_tool(
        check_violations,
        scan_results_json=json.dumps(scan_results) if isinstance(scan_results, dict) else scan_results,
        applicable_regulations=regulations,
    )
    return {"action": "check_violations", **json.loads(result_str)}


def _handle_generate_scp(body: dict) -> dict:
    from sovereign_shield.tools.remediation import generate_scp_policy

    prohibited_regions = body.get("prohibited_regions", "")
    allowed_services = body.get("allowed_services", "s3,rds,dynamodb,kms,sns,sqs,lambda,ec2")
    policy_name = body.get("policy_name", "SovereignShieldRegionRestriction")

    if not prohibited_regions:
        raise ValueError("Missing 'prohibited_regions' field")

    from sovereign_shield.tools.invocation import invoke_tool

    result_str = invoke_tool(
        generate_scp_policy,
        prohibited_regions=prohibited_regions,
        allowed_services=allowed_services,
        policy_name=policy_name,
    )
    return {"action": "generate_scp", **json.loads(result_str)}


def _handle_generate_remediation(body: dict) -> dict:
    from sovereign_shield.tools.remediation import generate_remediation_plan

    violations = body.get("violations")
    if not violations:
        raise ValueError("Missing 'violations' field")

    from sovereign_shield.tools.invocation import invoke_tool

    result_str = invoke_tool(
        generate_remediation_plan,
        violations_json=json.dumps(violations) if isinstance(violations, dict) else violations,
    )
    return {"action": "generate_remediation", **json.loads(result_str)}
