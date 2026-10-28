"""Typed, deterministic evaluation of normalized sovereignty scan evidence."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from sovereign_shield.models.contracts import (
    DeterministicScanResult,
    EvaluationResult,
    FindingRecord,
    ScanService,
)
from sovereign_shield.models.regulations import DataResidencyConstraint, Regulation
from sovereign_shield.regulations import ALL_REGULATIONS

RULE_PACK_VERSION = "2026.10.25.1"

if TYPE_CHECKING:
    from sovereign_shield.services.scan_store import ScanStore


def evaluate_scan(
    scan: DeterministicScanResult,
    *,
    rule_pack_version: str = RULE_PACK_VERSION,
    store: ScanStore | None = None,
) -> EvaluationResult:
    """Evaluate normalized scan evidence and return stable, evidence-linked findings.

    This is a pure domain service: it does not create an agent, call a Strands
    tool, use Bedrock, or perform AWS I/O. It evaluates only the requested
    regulations and, when supplied, only constraints whose data categories
    overlap the customer-declared categories.
    """

    violations = _deduplicate_unclassified_violations(
        _evaluate_violations(scan),
        has_data_classification=bool(scan.request.data_categories),
    )
    findings = [
        _to_finding(
            violation=violation,
            scan=scan,
            rule_pack_version=rule_pack_version,
        )
        for violation in violations
    ]
    result = EvaluationResult(
        scan_run_id=scan.scan_run_id,
        rule_pack_version=rule_pack_version,
        findings=findings,
    )
    if store is not None:
        store.save_evaluation(result)
    return result


def _evaluate_violations(scan: DeterministicScanResult) -> list[dict[str, Any]]:
    """Produce rule violations directly from typed evidence and the rule pack."""

    violations: list[dict[str, Any]] = []
    for regulation, constraint, constraint_index in _applicable_constraints(scan):
        for resource in scan.resources:
            if (
                _region_in_scope(resource.region, constraint)
                and constraint.requires_encryption_at_rest
                and not resource.encryption_at_rest
            ):
                violations.append(
                    _violation(
                        regulation=regulation,
                        constraint=constraint,
                        constraint_index=constraint_index,
                        category="encryption_at_rest_missing",
                        severity="high",
                        account_id=resource.account_id or scan.account_id,
                        service=resource.service.value,
                        resource_arn=resource.resource_arn,
                        resource_name=resource.resource_name,
                        source_region=resource.region,
                        destination_region=resource.region,
                        description=(
                            f"{resource.service.value} resource '{resource.resource_name}' in {resource.region} "
                            f"lacks required encryption at rest. {regulation.name} requires encryption for "
                            f"{', '.join(constraint.data_categories)} data."
                        ),
                    )
                )

        for flow in scan.flows:
            if not _region_in_scope(flow.source_region, constraint):
                continue
            for destination_region in flow.destination_regions:
                violation = _evaluate_flow(
                    regulation=regulation,
                    constraint=constraint,
                    constraint_index=constraint_index,
                    account_id=flow.account_id or scan.account_id,
                    service=flow.service.value,
                    resource_arn=flow.resource_arn,
                    resource_name=flow.resource_name,
                    source_region=flow.source_region,
                    destination_region=destination_region,
                    encryption_enabled=flow.encryption_enabled,
                )
                if violation is not None:
                    violations.append(violation)
    return violations


def _applicable_constraints(
    scan: DeterministicScanResult,
) -> list[tuple[Regulation, DataResidencyConstraint, int]]:
    requested_regulations = set(scan.request.regulations)
    requested_categories = set(scan.request.data_categories)
    applicable: list[tuple[Regulation, DataResidencyConstraint, int]] = []
    for regulation in ALL_REGULATIONS.regulations:
        if requested_regulations and regulation.id not in requested_regulations:
            continue
        for index, constraint in enumerate(regulation.constraints):
            if requested_categories and not requested_categories.intersection(constraint.data_categories):
                continue
            applicable.append((regulation, constraint, index))
    return applicable


def _evaluate_flow(
    *,
    regulation: Regulation,
    constraint: DataResidencyConstraint,
    constraint_index: int,
    account_id: str,
    service: str,
    resource_arn: str,
    resource_name: str,
    source_region: str,
    destination_region: str,
    encryption_enabled: bool,
) -> dict[str, Any] | None:
    common = {
        "regulation": regulation,
        "constraint": constraint,
        "constraint_index": constraint_index,
        "account_id": account_id,
        "service": service,
        "resource_arn": resource_arn,
        "resource_name": resource_name,
        "source_region": source_region,
        "destination_region": destination_region,
    }
    if destination_region == "global-edge-locations":
        return _violation(
            category="global_edge_distribution",
            severity="high",
            description=(
                f"{service} '{resource_name}' executes at global edge locations, potentially distributing data "
                f"outside allowed regions. {regulation.name} restricts {', '.join(constraint.data_categories)} data."
            ),
            **common,
        )
    if destination_region in constraint.prohibited_regions:
        return _violation(
            category="prohibited_transfer",
            severity="critical",
            description=(
                f"{service} '{resource_name}' transfers data from {source_region} to {destination_region}, "
                f"which is explicitly prohibited under {regulation.name}."
            ),
            **common,
        )
    if destination_region not in constraint.allowed_regions:
        if constraint.allows_cross_border_with_adequacy and destination_region in constraint.adequacy_regions:
            return None
        severity = "critical" if not constraint.allows_cross_border_with_adequacy else "high"
        return _violation(
            category="non_allowed_destination",
            severity=severity,
            description=(
                f"{service} '{resource_name}' transfers data from {source_region} to {destination_region}. "
                f"Under {regulation.name}, {', '.join(constraint.data_categories)} data must reside in "
                f"{', '.join(constraint.allowed_regions)}. Destination {destination_region} is not an allowed region"
                + (
                    " and has no adequacy decision."
                    if not constraint.allows_cross_border_with_adequacy
                    else ". Adequacy decision or appropriate safeguards required."
                )
            ),
            **common,
        )
    if constraint.requires_encryption_in_transit and not encryption_enabled:
        return _violation(
            category="encryption_in_transit_missing",
            severity="medium",
            description=(
                f"{service} '{resource_name}' cross-region flow from {source_region} to {destination_region} "
                f"lacks encryption in transit. {regulation.name} requires encryption for "
                f"{', '.join(constraint.data_categories)} data transfers."
            ),
            **common,
        )
    return None


def _violation(
    *,
    regulation: Regulation,
    constraint: DataResidencyConstraint,
    constraint_index: int,
    category: str,
    severity: str,
    account_id: str,
    service: str,
    resource_arn: str,
    resource_name: str,
    source_region: str,
    destination_region: str,
    description: str,
) -> dict[str, Any]:
    return {
        "category": category,
        "account_id": account_id,
        "regulation_id": regulation.id,
        "article_reference": regulation.key_articles[0] if regulation.key_articles else "residency",
        "constraint_index": constraint_index,
        "severity": severity,
        "service": service,
        "resource_arn": resource_arn,
        "resource_name": resource_name,
        "source_region": source_region,
        "destination_region": destination_region,
        "description": description,
    }


def _region_in_scope(region: str, constraint: DataResidencyConstraint) -> bool:
    return region in constraint.allowed_regions or region in constraint.adequacy_regions


def _deduplicate_unclassified_violations(
    violations: list[dict[str, Any]],
    *,
    has_data_classification: bool,
) -> list[dict[str, Any]]:
    """Keep uncertain category overlaps as one conservative potential finding."""

    if has_data_classification:
        return violations

    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    deduplicated: dict[tuple[str, ...], dict[str, Any]] = {}
    for violation in violations:
        key = (
            str(violation.get("regulation_id", "")),
            str(violation.get("account_id", "")),
            str(violation.get("service", "")),
            str(violation.get("resource_arn", "")),
            str(violation.get("source_region", "")),
            str(violation.get("destination_region", "")),
        )
        existing = deduplicated.get(key)
        if existing is None or severity_order.get(str(violation.get("severity", "")).lower(), 0) > severity_order.get(
            str(existing.get("severity", "")).lower(),
            0,
        ):
            deduplicated[key] = violation
    return list(deduplicated.values())


def _to_finding(
    *,
    violation: dict[str, Any],
    scan: DeterministicScanResult,
    rule_pack_version: str,
) -> FindingRecord:
    service = _scan_service(violation.get("service", ""))
    source_region = str(violation.get("source_region", ""))
    destination_region = str(violation.get("destination_region", ""))
    resource_arn = str(violation.get("resource_arn", ""))
    evidence_ids = _matching_evidence_ids(
        scan=scan,
        resource_arn=resource_arn,
        source_region=source_region,
        destination_region=destination_region,
    )
    rule_id = _rule_id(violation)
    finding_account = str(violation.get("account_id") or scan.account_id)
    finding_id = _stable_id(
        scan.scan_run_id,
        finding_account,
        rule_id,
        resource_arn,
        source_region,
        destination_region,
        str(violation.get("description", "")),
    )
    return FindingRecord(
        finding_id=finding_id,
        scan_run_id=scan.scan_run_id,
        account_id=finding_account,
        region=source_region,
        service=service,
        resource_arn=resource_arn,
        resource_name=str(violation.get("resource_name", "")),
        rule_id=rule_id,
        rule_pack_version=rule_pack_version,
        severity=str(violation.get("severity", "info")).lower(),
        category=str(violation.get("category", "residency")),
        description=str(violation.get("description", "")),
        evidence_ids=evidence_ids,
        data_categories=scan.request.data_categories,
    )


def _scan_service(value: str) -> ScanService:
    mapping = {
        "s3": ScanService.S3,
        "rds": ScanService.RDS,
        "dynamodb": ScanService.DYNAMODB,
        "cloudfront": ScanService.CLOUDFRONT,
        "kms": ScanService.KMS,
        "sns": ScanService.SNS_SQS,
        "sqs": ScanService.SNS_SQS,
        "transitgateway": ScanService.TRANSIT_GATEWAY,
        "lambda@edge": ScanService.LAMBDA_AT_EDGE,
    }
    return mapping.get(value.lower(), ScanService.S3)


def _matching_evidence_ids(
    *,
    scan: DeterministicScanResult,
    resource_arn: str,
    source_region: str,
    destination_region: str,
) -> list[str]:
    evidence_ids = [
        flow.evidence_id
        for flow in scan.flows
        if flow.resource_arn == resource_arn
        and flow.source_region == source_region
        and destination_region in flow.destination_regions
    ]
    evidence_ids.extend(
        resource.evidence_id
        for resource in scan.resources
        if resource.resource_arn == resource_arn and resource.region == source_region
    )
    if evidence_ids:
        return sorted(set(evidence_ids))

    # A legacy scanner payload can omit enough detail to match a normalized
    # record. Preserve traceability rather than fabricating a link to unrelated
    # evidence.
    return [_stable_id(scan.scan_run_id, resource_arn, source_region, destination_region, "unmatched")]


def _rule_id(violation: dict[str, Any]) -> str:
    regulation_id = str(violation.get("regulation_id", "unknown")).lower()
    article = str(violation.get("article_reference", "residency")).lower()
    normalized_article = "-".join(part for part in article.replace("/", " ").split() if part)
    constraint_index = int(violation.get("constraint_index", 0))
    return f"{regulation_id}:{normalized_article or 'residency'}:{constraint_index}"


def _stable_id(*parts: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "|".join(parts)))
