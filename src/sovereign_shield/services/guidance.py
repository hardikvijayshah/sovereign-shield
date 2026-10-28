"""Deterministic, read-only remediation guidance for finding categories.

Guidance is advice for a human to review. Sovereign Shield never applies it:
the product has no permission to change scanned resources, attach SCPs, or
delete data.
"""

from __future__ import annotations

from typing import Any

GUIDANCE_NOTICE = (
    "Guidance only. Validate the data classification and legal basis with your compliance team "
    "before changing any resource. Sovereign Shield does not make changes."
)

_CATEGORY_GUIDANCE: dict[str, list[str]] = {
    "prohibited_transfer": [
        "Confirm which data actually flows to the destination region and whether it is in scope.",
        (
            "If it is, stop the transfer: remove or retarget the replication, subscription, or peering that crosses"
            " into the prohibited region."
        ),
        (
            "Consider a preventive guardrail, such as a service control policy that denies the destination region "
            "for this workload's accounts."
        ),
    ],
    "non_allowed_destination": [
        (
            "Confirm whether the destination region is covered by an adequacy decision or another transfer "
            "mechanism (for example, standard contractual clauses) for this data."
        ),
        "If not, move the destination into an allowed region or stop the transfer.",
        "Record the transfer basis you rely on so the next assessment can be validated against it.",
    ],
    "global_edge_distribution": [
        "Review whether the content served from edge locations includes in-scope data.",
        (
            "Restrict distribution geography or caching for in-scope content, or serve it from a regional endpoint "
            "in an allowed region."
        ),
    ],
    "encryption_at_rest_missing": [
        "Enable encryption at rest on the resource, preferably with a customer-managed KMS key in an allowed region.",
        "Check that key policies limit decryption to the principals that need it.",
    ],
    "encryption_in_transit_missing": [
        "Require TLS for the cross-region transfer path.",
        (
            "Where the service supports it, enforce encryption with a resource policy condition (for example, "
            "aws:SecureTransport)."
        ),
    ],
}

_SERVICE_HINTS: dict[str, str] = {
    "s3": "For S3, review the bucket's replication rules and destination buckets.",
    "rds": "For RDS, review cross-region read replicas and automated backup replication.",
    "dynamodb": "For DynamoDB, review the global table replica regions.",
    "kms": "For KMS, review multi-Region key replicas.",
    "sns_sqs": "For SNS, review cross-region subscriptions on the topic.",
    "transit_gateway": "For Transit Gateway, review inter-region peering attachments and route tables.",
    "cloudfront": "For CloudFront, review geographic restrictions and origin locations.",
    "lambda_at_edge": "For Lambda@Edge, review which associations process in-scope data at the edge.",
}


def guidance_for(finding: dict[str, Any]) -> dict[str, Any]:
    """Return guidance steps for one stored finding record."""

    steps = list(_CATEGORY_GUIDANCE.get(str(finding.get("category", "")), []))
    if not steps:
        steps = ["Review the finding's evidence and confirm whether in-scope data is affected."]
    hint = _SERVICE_HINTS.get(str(finding.get("service", "")))
    if hint:
        steps.append(hint)
    return {"notice": GUIDANCE_NOTICE, "steps": steps}
