"""Strands agent tool for detecting sovereignty violations by cross-referencing scan results with regulations."""

from __future__ import annotations

import json
import uuid

from sovereign_shield.regulations import ALL_REGULATIONS
from sovereign_shield.tools.invocation import tool


@tool
def check_violations(scan_results_json: str, applicable_regulations: str = "") -> str:
    """Analyze scan results against data sovereignty regulations to detect violations.

    Cross-references every detected cross-border data flow against the residency constraints
    of applicable regulations. Returns a list of violations with severity, regulation reference,
    and description.

    Args:
        scan_results_json: JSON string containing scan results with 'flows' and 'resources' arrays
        applicable_regulations: Comma-separated regulation IDs to check (e.g., 'gdpr,dpdp'). Empty means check all.
    """
    try:
        scan_data = json.loads(scan_results_json)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON in scan results", "violations": []})

    flows = scan_data.get("flows", [])
    resources = scan_data.get("resources", [])

    reg_ids = [r.strip() for r in applicable_regulations.split(",") if r.strip()] if applicable_regulations else None

    registry = ALL_REGULATIONS
    constraints = []
    for reg in registry.regulations:
        if reg_ids and reg.id not in reg_ids:
            continue
        for constraint in reg.constraints:
            constraints.append((reg, constraint))

    violations = []

    for flow in flows:
        source_region = flow.get("source_region", "")
        dest_regions = flow.get("destination_regions", [])
        service = flow.get("service", "")
        resource_name = flow.get("resource_name", "")
        resource_arn = flow.get("resource_arn", "")
        encryption = flow.get("encryption_enabled", False)

        for dest_region in dest_regions:
            for reg, constraint in constraints:
                if not _region_in_scope(source_region, constraint):
                    continue

                violation = _check_flow_against_constraint(
                    reg, constraint, source_region, dest_region, service, resource_name, resource_arn, encryption
                )
                if violation:
                    violations.append(violation)

    for resource in resources:
        res_region = resource.get("region", "")
        encryption_at_rest = resource.get("encryption_at_rest", False)
        service = resource.get("service", "")
        resource_name = resource.get("resource_name", "")
        resource_arn = resource.get("resource_arn", "")

        for reg, constraint in constraints:
            if not _region_in_scope(res_region, constraint):
                continue

            if constraint.requires_encryption_at_rest and not encryption_at_rest:
                violations.append({
                    "violation_id": str(uuid.uuid4())[:8],
                    "regulation_id": reg.id,
                    "regulation_name": reg.name,
                    "article_reference": reg.key_articles[0] if reg.key_articles else "",
                    "severity": "high",
                    "service": service,
                    "resource_arn": resource_arn,
                    "resource_name": resource_name,
                    "source_region": res_region,
                    "destination_region": res_region,
                    "description": (
                        f"{service} resource '{resource_name}' in {res_region} lacks required encryption at rest. "
                        f"{reg.name} requires encryption for {', '.join(constraint.data_categories)} data."
                    ),
                })

    return json.dumps({"violations": violations, "total": len(violations)})


def _region_in_scope(region: str, constraint) -> bool:
    """Check if a region falls under this constraint's jurisdiction."""
    if region in constraint.allowed_regions:
        return True
    if region in constraint.adequacy_regions:
        return True
    return False


def _check_flow_against_constraint(
    reg, constraint, source_region: str, dest_region: str,
    service: str, resource_name: str, resource_arn: str, encryption: bool,
) -> dict | None:
    """Check a single flow against a single constraint. Returns violation dict or None."""
    if dest_region == "global-edge-locations":
        return {
            "violation_id": str(uuid.uuid4())[:8],
            "regulation_id": reg.id,
            "regulation_name": reg.name,
            "article_reference": reg.key_articles[0] if reg.key_articles else "",
            "severity": "high",
            "service": service,
            "resource_arn": resource_arn,
            "resource_name": resource_name,
            "source_region": source_region,
            "destination_region": "global-edge-locations",
            "description": (
                f"{service} '{resource_name}' executes at global edge locations, potentially distributing "
                f"data outside allowed regions. {reg.name} restricts {', '.join(constraint.data_categories)} "
                f"data to {', '.join(constraint.allowed_regions)}."
            ),
        }

    if dest_region in constraint.prohibited_regions:
        return {
            "violation_id": str(uuid.uuid4())[:8],
            "regulation_id": reg.id,
            "regulation_name": reg.name,
            "article_reference": reg.key_articles[0] if reg.key_articles else "",
            "severity": "critical",
            "service": service,
            "resource_arn": resource_arn,
            "resource_name": resource_name,
            "source_region": source_region,
            "destination_region": dest_region,
            "description": (
                f"{service} '{resource_name}' replicates data from {source_region} to {dest_region}, "
                f"which is explicitly prohibited under {reg.name}. "
                f"Data categories affected: {', '.join(constraint.data_categories)}."
            ),
        }

    if dest_region not in constraint.allowed_regions:
        if constraint.allows_cross_border_with_adequacy and dest_region in constraint.adequacy_regions:
            return None

        severity = "critical" if not constraint.allows_cross_border_with_adequacy else "high"
        return {
            "violation_id": str(uuid.uuid4())[:8],
            "regulation_id": reg.id,
            "regulation_name": reg.name,
            "article_reference": reg.key_articles[0] if reg.key_articles else "",
            "severity": severity,
            "service": service,
            "resource_arn": resource_arn,
            "resource_name": resource_name,
            "source_region": source_region,
            "destination_region": dest_region,
            "description": (
                f"{service} '{resource_name}' transfers data from {source_region} to {dest_region}. "
                f"Under {reg.name}, {', '.join(constraint.data_categories)} data must reside in "
                f"{', '.join(constraint.allowed_regions)}. Destination {dest_region} is not an allowed region"
                + (" and has no adequacy decision." if not constraint.allows_cross_border_with_adequacy
                   else ". Adequacy decision or appropriate safeguards required.")
            ),
        }

    if constraint.requires_encryption_in_transit and not encryption:
        return {
            "violation_id": str(uuid.uuid4())[:8],
            "regulation_id": reg.id,
            "regulation_name": reg.name,
            "article_reference": reg.key_articles[0] if reg.key_articles else "",
            "severity": "medium",
            "service": service,
            "resource_arn": resource_arn,
            "resource_name": resource_name,
            "source_region": source_region,
            "destination_region": dest_region,
            "description": (
                f"{service} '{resource_name}' cross-region flow from {source_region} to {dest_region} "
                f"lacks encryption in transit. {reg.name} requires encryption for "
                f"{', '.join(constraint.data_categories)} data transfers."
            ),
        }

    return None
