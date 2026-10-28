"""Non-mutating post-deployment readiness check (plan.md section 8.4).

Invoked by the ``PostDeployValidationCommand`` stack output. It describes the
stack's own resources and performs a read-only scanner permission dry run in
each default scan region. It never starts a scan or changes any resource.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

# One cheap, read-only call per scanned service, matching tools/aws_scanner.py.
_SCANNER_PROBES: dict[str, Callable[[Any], Any]] = {
    "s3": lambda client: client.list_buckets(MaxBuckets=1),
    "rds": lambda client: client.describe_db_instances(MaxRecords=20),
    "dynamodb": lambda client: client.list_tables(Limit=1),
    "kms": lambda client: client.list_keys(Limit=1),
    "sns": lambda client: client.list_topics(),
    "ec2": lambda client: client.describe_transit_gateways(MaxResults=5),
}
_GLOBAL_PROBES: dict[str, Callable[[Any], Any]] = {
    "cloudfront": lambda client: client.list_distributions(MaxItems="1"),
    "lambda": lambda client: client.list_functions(MaxItems=1),
}


def handler(event: dict[str, Any], context: Any, *, client_factory: Callable[..., Any] | None = None) -> dict[str, Any]:
    make_client = client_factory or _boto3_client
    region = os.environ.get("AWS_REGION", "")
    checks: list[dict[str, str]] = []

    def check(name: str, probe: Callable[[], Any], *, warning: bool = False) -> None:
        try:
            probe()
            checks.append({"check": name, "result": "pass"})
        except Exception as exc:  # noqa: BLE001 - every failure becomes a reported check result
            checks.append(
                {
                    "check": name,
                    "result": "warning" if warning else "fail",
                    "detail": _error_code(exc),
                }
            )

    dynamodb = make_client("dynamodb", region)
    for variable in ("SCAN_RUNS_TABLE", "FINDINGS_TABLE", "AUDIT_TABLE"):
        table = os.environ[variable]
        check(f"table:{variable.lower()}", lambda table=table: _require_active_table(dynamodb, table))
    check("bucket:reports", lambda: make_client("s3", region).get_bucket_location(Bucket=os.environ["REPORTS_BUCKET"]))
    check("kms:data-key", lambda: _require_enabled_key(make_client("kms", region), os.environ["DATA_KEY_ARN"]))
    check(
        "workflow:state-machine",
        lambda: make_client("stepfunctions", region).describe_state_machine(
            stateMachineArn=os.environ["SCAN_STATE_MACHINE_ARN"]
        ),
    )
    check(
        "identity:console-client",
        lambda: _require_code_grant(
            make_client("cognito-idp", region), os.environ["USER_POOL_ID"], os.environ["CONSOLE_CLIENT_ID"]
        ),
    )

    if os.environ.get("ORGANIZATION_MODE") == "AWS_ORGANIZATIONS":
        check(
            "organization:membership",
            lambda: _require_organization(make_client("organizations", region), os.environ.get("ORGANIZATION_ID", "")),
        )
        check(
            "organization:member-role-stackset",
            lambda: make_client("cloudformation", region).describe_stack_set(
                StackSetName=os.environ["STACK_SET_NAME"], CallAs=os.environ.get("STACK_SET_CALL_AS", "SELF")
            ),
        )

    for service, probe in _GLOBAL_PROBES.items():
        check(
            f"scanner:{service}:global", lambda service=service, probe=probe: probe(make_client(service, "us-east-1"))
        )
    for scan_region in [value for value in os.environ.get("DEFAULT_SCAN_REGIONS", region).split(",") if value]:
        for service, probe in _SCANNER_PROBES.items():
            # A region that is not enabled for the account is a warning, not a deployment fault.
            check(
                f"scanner:{service}:{scan_region}",
                lambda service=service, probe=probe, scan_region=scan_region: probe(make_client(service, scan_region)),
                warning=True,
            )

    failed = [entry for entry in checks if entry["result"] == "fail"]
    warnings = [entry for entry in checks if entry["result"] == "warning"]
    return {
        "ready": not failed,
        "releaseVersion": os.environ.get("RELEASE_VERSION", "development"),
        "summary": f"{len(checks) - len(failed) - len(warnings)} passed, {len(warnings)} warnings, "
        f"{len(failed)} failed",
        "checks": checks,
    }


def _require_organization(organizations: Any, organization_id: str) -> None:
    actual = organizations.describe_organization()["Organization"]["Id"]
    if actual != organization_id:
        raise RuntimeError("OrganizationIdMismatch")


def _require_active_table(dynamodb: Any, table: str) -> None:
    description = dynamodb.describe_table(TableName=table)["Table"]
    if description.get("TableStatus") != "ACTIVE":
        raise RuntimeError(f"TableStatus={description.get('TableStatus')}")
    if any(index.get("IndexStatus") != "ACTIVE" for index in description.get("GlobalSecondaryIndexes", [])):
        raise RuntimeError("IndexNotActive")


def _require_enabled_key(kms: Any, key_arn: str) -> None:
    metadata = kms.describe_key(KeyId=key_arn)["KeyMetadata"]
    if metadata.get("KeyState") != "Enabled":
        raise RuntimeError(f"KeyState={metadata.get('KeyState')}")


def _require_code_grant(cognito: Any, user_pool_id: str, client_id: str) -> None:
    client = cognito.describe_user_pool_client(UserPoolId=user_pool_id, ClientId=client_id)["UserPoolClient"]
    if client.get("AllowedOAuthFlows") != ["code"] or client.get("ClientSecret"):
        raise RuntimeError("ConsoleClientMisconfigured")


def _error_code(exc: Exception) -> str:
    response = getattr(exc, "response", {})
    if isinstance(response, dict) and response.get("Error", {}).get("Code"):
        return str(response["Error"]["Code"])
    return f"{type(exc).__name__}: {str(exc)[:120]}"


def _boto3_client(service: str, region: str) -> Any:
    import boto3

    return boto3.client(service, region_name=region)
