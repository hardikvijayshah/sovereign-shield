"""Direct, deterministic orchestration of AWS discovery scanners."""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from sovereign_shield.models.contracts import (
    DeterministicScanResult,
    FlowEvidence,
    ResourceEvidence,
    ScanCoverageGap,
    ScanRequest,
    ScanService,
    ScanStatus,
)
from sovereign_shield.regulations import ALL_REGULATIONS
from sovereign_shield.tools.aws_scanner import (
    scan_cloudfront_distributions,
    scan_dynamodb_tables,
    scan_kms_keys,
    scan_lambda_at_edge,
    scan_rds_instances,
    scan_s3_buckets,
    scan_sns_sqs,
    scan_transit_gateways,
)
from sovereign_shield.tools.invocation import invoke_tool

if TYPE_CHECKING:
    from sovereign_shield.services.scan_store import ScanStore

Scanner = Callable[..., str | dict[str, Any]]

DEFAULT_SCANNERS: dict[ScanService, Scanner] = {
    ScanService.S3: scan_s3_buckets,
    ScanService.RDS: scan_rds_instances,
    ScanService.DYNAMODB: scan_dynamodb_tables,
    ScanService.CLOUDFRONT: scan_cloudfront_distributions,
    ScanService.KMS: scan_kms_keys,
    ScanService.SNS_SQS: scan_sns_sqs,
    ScanService.TRANSIT_GATEWAY: scan_transit_gateways,
    ScanService.LAMBDA_AT_EDGE: scan_lambda_at_edge,
}

# These scanners call global AWS APIs internally and must not run once per
# requested regional target. The first requested region provides traceability.
GLOBAL_SERVICES = {ScanService.CLOUDFRONT, ScanService.LAMBDA_AT_EDGE}


def execute_scan(
    request: ScanRequest,
    *,
    account_id: str = "",
    scan_run_id: str | None = None,
    scanners: Mapping[ScanService, Scanner] | None = None,
    store: ScanStore | None = None,
) -> DeterministicScanResult:
    """Run every requested scanner directly and return normalized evidence.

    This function deliberately does not create an agent, call Bedrock, or
    persist state. Phase 2 will invoke it from bounded asynchronous workers and
    persist the returned typed result.
    """

    started_at = datetime.now(timezone.utc)
    result = DeterministicScanResult(
        scan_run_id=scan_run_id or str(uuid.uuid4()),
        account_id=account_id,
        request=request,
        status=ScanStatus.RUNNING,
        started_at=started_at,
        completed_at=started_at,
    )
    scanner_registry = dict(DEFAULT_SCANNERS if scanners is None else scanners)
    _validate_regulations(request)

    for region_index, region in enumerate(request.scan_regions):
        for service in request.services:
            if service in GLOBAL_SERVICES and region_index > 0:
                continue

            scanner = scanner_registry.get(service)
            if scanner is None:
                result.coverage_gaps.append(
                    _coverage_gap(
                        account_id,
                        region,
                        service,
                        "scanner_not_configured",
                        "No deterministic scanner is registered for this service.",
                    )
                )
                continue

            payload = _run_scanner(scanner, service, region, account_id)
            if isinstance(payload, ScanCoverageGap):
                result.coverage_gaps.append(payload)
                continue

            if payload.get("error"):
                result.coverage_gaps.append(
                    _coverage_gap(
                        account_id,
                        region,
                        service,
                        "scanner_error",
                        redact_error_text(str(payload["error"])),
                    )
                )
                continue

            _append_normalized_evidence(
                result=result,
                account_id=account_id,
                region=region,
                service=service,
                payload=payload,
            )

    result.completed_at = datetime.now(timezone.utc)
    result.status = ScanStatus.PARTIAL if result.coverage_gaps else ScanStatus.COMPLETE
    if store is not None:
        store.save_scan_result(result)
    return result


def _validate_regulations(request: ScanRequest) -> None:
    if not request.regulations:
        return

    known_regulations = {regulation.id for regulation in ALL_REGULATIONS.regulations}
    unknown_regulations = sorted(set(request.regulations) - known_regulations)
    if unknown_regulations:
        raise ValueError(f"Unknown regulations requested: {', '.join(unknown_regulations)}")


def _run_scanner(
    scanner: Scanner,
    service: ScanService,
    region: str,
    account_id: str,
) -> dict[str, Any] | ScanCoverageGap:
    """Invoke a plain callable or a Strands tool's underlying callable."""

    try:
        response = invoke_tool(scanner, region=region, account_id=account_id)
    except Exception as exc:  # noqa: BLE001 - converted to explicit scan coverage
        return _coverage_gap(
            account_id,
            region,
            service,
            "scanner_exception",
            redact_exception(exc),
        )

    if isinstance(response, dict):
        return response

    try:
        decoded = json.loads(response)
    except (TypeError, json.JSONDecodeError):
        return _coverage_gap(
            account_id,
            region,
            service,
            "invalid_scanner_response",
            "Scanner did not return a JSON object.",
        )

    if not isinstance(decoded, dict):
        return _coverage_gap(
            account_id,
            region,
            service,
            "invalid_scanner_response",
            "Scanner returned JSON that was not an object.",
        )
    return decoded


_AWS_ERROR_PATTERN = re.compile(r"\((?P<code>[A-Za-z][\w.]{0,63})\) when calling the (?P<operation>\w{1,64}) operation")


def redact_error_text(text: str) -> str:
    """Keep only the AWS error code and operation from scanner error text.

    AWS error messages can include principal ARNs, resource names, and account
    IDs. Coverage gaps are stored and shown in reports, so only the parts needed
    to act on the gap are kept (plan.md section 5.3).
    """

    match = _AWS_ERROR_PATTERN.search(text)
    if match:
        return f"{match.group('code')} calling {match.group('operation')}"
    return "Scanner error (details withheld; see the error code in the workflow logs)."


def redact_exception(exc: BaseException) -> str:
    """Describe an exception without echoing input values or AWS message text."""

    if isinstance(exc, ValidationError):
        problems = sorted({
            f"{'.'.join(str(part) for part in error.get('loc', ())) or 'record'}: {error.get('type', 'invalid')}"
            for error in exc.errors()
        })
        return "Invalid fields: " + "; ".join(problems[:10])
    redacted = redact_error_text(str(exc))
    if redacted.startswith("Scanner error"):
        return f"{type(exc).__name__} (details withheld)."
    return redacted


def _coverage_gap(
    account_id: str,
    region: str,
    service: ScanService,
    code: str,
    message: str,
) -> ScanCoverageGap:
    return ScanCoverageGap(
        account_id=account_id,
        region=region,
        service=service,
        code=code,
        message=message,
    )


def _append_normalized_evidence(
    *,
    result: DeterministicScanResult,
    account_id: str,
    region: str,
    service: ScanService,
    payload: dict[str, Any],
) -> None:
    """Normalize every scanner record without losing an otherwise useful scan.

    AWS APIs and product scanner versions can evolve independently. A malformed
    record is therefore a coverage gap, rather than a reason to lose valid
    evidence emitted by the same scanner invocation.
    """

    raw_resources = payload.get("resources", [])
    if not isinstance(raw_resources, list):
        result.coverage_gaps.append(
            _coverage_gap(
                account_id,
                region,
                service,
                "invalid_resource_collection",
                "Scanner response field 'resources' must be a JSON array.",
            )
        )
    else:
        resource_ids = {resource.evidence_id for resource in result.resources}
        for index, raw_resource in enumerate(raw_resources):
            if not isinstance(raw_resource, dict):
                result.coverage_gaps.append(
                    _invalid_evidence_gap(
                        account_id, region, service, "resource", index, "record must be a JSON object"
                    )
                )
                continue
            try:
                resource = _resource_evidence(
                    scan_run_id=result.scan_run_id,
                    account_id=account_id,
                    region=region,
                    service=service,
                    payload=raw_resource,
                )
            except (TypeError, ValidationError, ValueError) as exc:
                result.coverage_gaps.append(
                    _invalid_evidence_gap(account_id, region, service, "resource", index, redact_exception(exc))
                )
                continue
            if resource.evidence_id not in resource_ids:
                result.resources.append(resource)
                resource_ids.add(resource.evidence_id)

    raw_flows = payload.get("flows", [])
    if not isinstance(raw_flows, list):
        result.coverage_gaps.append(
            _coverage_gap(
                account_id,
                region,
                service,
                "invalid_flow_collection",
                "Scanner response field 'flows' must be a JSON array.",
            )
        )
        return

    flow_ids = {flow.evidence_id for flow in result.flows}
    for index, raw_flow in enumerate(raw_flows):
        if not isinstance(raw_flow, dict):
            result.coverage_gaps.append(
                _invalid_evidence_gap(account_id, region, service, "flow", index, "record must be a JSON object")
            )
            continue
        try:
            flow = _flow_evidence(
                scan_run_id=result.scan_run_id,
                account_id=account_id,
                service=service,
                payload=raw_flow,
            )
        except (TypeError, ValidationError, ValueError) as exc:
            result.coverage_gaps.append(
                _invalid_evidence_gap(account_id, region, service, "flow", index, redact_exception(exc))
            )
            continue
        if flow.evidence_id not in flow_ids:
            result.flows.append(flow)
            flow_ids.add(flow.evidence_id)


def _invalid_evidence_gap(
    account_id: str,
    region: str,
    service: ScanService,
    evidence_type: str,
    index: int,
    detail: str,
) -> ScanCoverageGap:
    return _coverage_gap(
        account_id,
        region,
        service,
        f"invalid_{evidence_type}_evidence",
        f"Scanner returned invalid {evidence_type} record at index {index}: {detail}",
    )


def _resource_evidence(
    *,
    scan_run_id: str,
    account_id: str,
    region: str,
    service: ScanService,
    payload: dict[str, Any],
) -> ResourceEvidence:
    resource_arn = str(payload.get("resource_arn", ""))
    resource_name = str(payload.get("resource_name", ""))
    evidence_id = _evidence_id(scan_run_id, service, resource_arn, region, "resource")
    return ResourceEvidence(
        evidence_id=evidence_id,
        account_id=account_id,
        region=str(payload.get("region", region)),
        service=service,
        resource_arn=resource_arn,
        resource_name=resource_name,
        resource_type=str(payload.get("resource_type", service.value)),
        encryption_at_rest=bool(payload.get("encryption_at_rest", False)),
        encryption_in_transit=bool(payload.get("encryption_in_transit", False)),
        details=_details(payload),
    )


def _flow_evidence(
    *,
    scan_run_id: str,
    account_id: str,
    service: ScanService,
    payload: dict[str, Any],
) -> FlowEvidence:
    resource_arn = str(payload.get("resource_arn", ""))
    source_region = str(payload.get("source_region", ""))
    raw_destinations = payload.get("destination_regions", [])
    if not isinstance(raw_destinations, list) or any(
        not isinstance(destination, str) or not destination.strip() for destination in raw_destinations
    ):
        raise ValueError("destination_regions must be a non-empty JSON array of strings")
    destinations = [destination.strip() for destination in raw_destinations]
    if not destinations:
        raise ValueError("destination_regions must contain at least one destination")
    evidence_id = _evidence_id(
        scan_run_id,
        service,
        resource_arn,
        f"{source_region}:{','.join(destinations)}",
        "flow",
    )
    return FlowEvidence(
        evidence_id=evidence_id,
        account_id=account_id,
        service=service,
        resource_arn=resource_arn,
        resource_name=str(payload.get("resource_name", "")),
        source_region=source_region,
        destination_regions=destinations,
        flow_type=str(payload.get("flow_type", "unknown")),
        encryption_enabled=bool(payload.get("encryption_enabled", False)),
        details=_details(payload),
    )


def _details(payload: dict[str, Any]) -> dict[str, Any]:
    details = payload.get("details", {})
    return details if isinstance(details, dict) else {"raw_details": str(details)}


def _evidence_id(
    scan_run_id: str,
    service: ScanService,
    resource_arn: str,
    scope: str,
    evidence_type: str,
) -> str:
    """Stable identifiers make worker retries safe for a given scan run."""

    name = "|".join((scan_run_id, service.value, resource_arn, scope, evidence_type))
    return str(uuid.uuid5(uuid.NAMESPACE_URL, name))
