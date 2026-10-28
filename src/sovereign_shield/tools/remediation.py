"""Strands agent tools for generating remediation plans and SCP policies."""

from __future__ import annotations

import json

from sovereign_shield.tools.invocation import tool


@tool
def generate_scp_policy(
    prohibited_regions: str,
    allowed_services: str = "s3,rds,dynamodb,kms,sns,sqs,lambda,ec2",
    policy_name: str = "SovereignShieldRegionRestriction",
) -> str:
    """Generate an AWS Service Control Policy (SCP) that prevents resource creation in prohibited regions.

    Args:
        prohibited_regions: Comma-separated list of AWS regions to block (e.g., 'us-east-1,us-west-2')
        allowed_services: Comma-separated AWS services to restrict (default: core data services)
        policy_name: Name for the SCP policy
    """
    regions = [r.strip() for r in prohibited_regions.split(",") if r.strip()]
    services = [s.strip() for s in allowed_services.split(",") if s.strip()]

    service_prefixes = []
    for svc in services:
        mapping = {
            "s3": "s3:*",
            "rds": "rds:*",
            "dynamodb": "dynamodb:*",
            "kms": "kms:*",
            "sns": "sns:*",
            "sqs": "sqs:*",
            "lambda": "lambda:*",
            "ec2": "ec2:*",
            "cloudfront": "cloudfront:*",
        }
        service_prefixes.append(mapping.get(svc, f"{svc}:*"))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": policy_name,
                "Effect": "Deny",
                "Action": service_prefixes,
                "Resource": "*",
                "Condition": {"StringNotEquals": {"aws:RequestedRegion": regions}},
            }
        ],
    }

    deny_replication_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": f"{policy_name}DenyReplication",
                "Effect": "Deny",
                "Action": [
                    "s3:PutReplicationConfiguration",
                    "rds:CreateDBInstanceReadReplica",
                    "dynamodb:UpdateTable",
                    "kms:ReplicateKey",
                ],
                "Resource": "*",
                "Condition": {"ForAnyValue:StringEquals": {"aws:RequestedRegion": regions}},
            }
        ],
    }

    return json.dumps(
        {
            "region_restriction_policy": policy,
            "replication_deny_policy": deny_replication_policy,
            "policy_name": policy_name,
            "blocked_regions": regions,
            "instructions": [
                "1. Go to AWS Organizations > Policies > Service Control Policies",
                f"2. Create a new SCP named '{policy_name}'",
                "3. Paste the region_restriction_policy JSON",
                "4. Attach to the target OU or accounts",
                "5. Optionally deploy the replication_deny_policy to prevent cross-region replication setup",
            ],
        },
        indent=2,
    )


@tool
def generate_remediation_plan(violations_json: str) -> str:
    """Generate a structured remediation plan for detected sovereignty violations.

    Analyzes each violation and produces actionable remediation steps including
    resource configuration changes, SCP policies, and architecture recommendations.

    Args:
        violations_json: JSON string containing violations array from the violation detector
    """
    try:
        data = json.loads(violations_json)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON", "remediations": []})

    violations = data.get("violations", [])
    remediations = []

    for v in violations:
        service = v.get("service", "")
        source = v.get("source_region", "")
        dest = v.get("destination_region", "")
        resource_name = v.get("resource_name", "")
        severity = v.get("severity", "medium")
        reg_name = v.get("regulation_name", "")

        remediation = {
            "violation_id": v.get("violation_id", ""),
            "title": "",
            "remediation_type": "",
            "description": "",
            "steps": [],
            "estimated_effort": "",
            "risk_if_not_remediated": "",
        }

        if service == "S3" and "replicat" in v.get("description", "").lower():
            remediation.update(
                {
                    "title": f"Remove S3 cross-region replication from '{resource_name}'",
                    "remediation_type": "resource_config",
                    "description": f"S3 bucket '{resource_name}' replicates from {source} to {dest}, violating {reg_name}.",
                    "steps": [
                        f"aws s3api delete-bucket-replication --bucket {resource_name}",
                        f"Verify: aws s3api get-bucket-replication --bucket {resource_name}",
                        f"If data already exists in {dest}, delete the replica bucket or migrate data back to {source}",
                        f"Deploy SCP to prevent future replication to {dest}",
                    ],
                    "estimated_effort": "1-2 hours",
                    "risk_if_not_remediated": f"Ongoing {reg_name} violation — potential regulatory fine and audit failure",
                }
            )

        elif service == "RDS":
            remediation.update(
                {
                    "title": f"Remove RDS cross-region read replica for '{resource_name}'",
                    "remediation_type": "resource_config",
                    "description": f"RDS instance '{resource_name}' has a read replica in {dest}, violating {reg_name}.",
                    "steps": [
                        f"Identify the read replica in {dest}: aws rds describe-db-instances --region {dest}",
                        f"Promote or delete the replica: aws rds delete-db-instance --db-instance-identifier <replica-id> --region {dest}",
                        f"If read scaling needed in {source}, create a replica within {source} instead",
                        f"Update application connection strings to remove {dest} endpoints",
                    ],
                    "estimated_effort": "2-4 hours (includes app config changes)",
                    "risk_if_not_remediated": f"Continuous data replication to non-compliant region — {reg_name} violation",
                }
            )

        elif service == "DynamoDB":
            remediation.update(
                {
                    "title": f"Remove DynamoDB global table replica in {dest} for '{resource_name}'",
                    "remediation_type": "resource_config",
                    "description": f"DynamoDB table '{resource_name}' has a global table replica in {dest}, violating {reg_name}.",
                    "steps": [
                        f"aws dynamodb update-table --table-name {resource_name} --replica-updates "
                        f'\'[{{"Delete": {{"RegionName": "{dest}"}}}}]\'',
                        f"Verify removal: aws dynamodb describe-table --table-name {resource_name}",
                        f"Update application to remove references to {dest} table endpoint",
                        "If multi-region access needed, add replicas only in compliant regions",
                    ],
                    "estimated_effort": "1-2 hours",
                    "risk_if_not_remediated": f"Active data replication to {dest} — {reg_name} violation",
                }
            )

        elif service == "CloudFront":
            remediation.update(
                {
                    "title": f"Restrict CloudFront distribution '{resource_name}' to compliant regions",
                    "remediation_type": "architecture_change",
                    "description": "CloudFront distribution caches data at edge locations outside compliant regions.",
                    "steps": [
                        "Update distribution price class to restrict edge locations (PriceClass_100 for US/EU only)",
                        f"Add geographic restrictions: aws cloudfront update-distribution --id {resource_name} "
                        f"--distribution-config with Restrictions.GeoRestriction",
                        "Consider using regional endpoints instead of CloudFront for region-restricted content",
                        "Evaluate if content served via CloudFront contains regulated data categories",
                    ],
                    "estimated_effort": "2-4 hours",
                    "risk_if_not_remediated": f"Regulated data cached at global edge locations — {reg_name} violation",
                }
            )

        elif service == "KMS":
            remediation.update(
                {
                    "title": f"Remove KMS multi-region key replica in {dest}",
                    "remediation_type": "resource_config",
                    "description": f"KMS key '{resource_name}' has replicas in non-compliant regions.",
                    "steps": [
                        f"Schedule deletion of replica key in {dest}: "
                        f"aws kms schedule-key-deletion --key-id <replica-key-id> --region {dest} --pending-window-in-days 7",
                        "Update resources using the replica key to use a region-local key instead",
                        "Create new KMS keys in compliant regions if needed",
                    ],
                    "estimated_effort": "2-4 hours (7-day minimum deletion wait)",
                    "risk_if_not_remediated": "Encryption key material present in non-compliant region",
                }
            )

        elif service == "TransitGateway":
            remediation.update(
                {
                    "title": f"Remove Transit Gateway peering to {dest}",
                    "remediation_type": "architecture_change",
                    "description": f"Transit Gateway '{resource_name}' peers with {dest}, enabling cross-border data flow.",
                    "steps": [
                        "Identify traffic flowing through the peering: check VPC flow logs",
                        "Migrate workloads to operate within compliant regions",
                        "Delete the peering attachment: aws ec2 delete-transit-gateway-peering-attachment "
                        "--transit-gateway-attachment-id <attachment-id>",
                        f"Update route tables to remove routes to {dest}",
                    ],
                    "estimated_effort": "1-2 weeks (requires traffic migration)",
                    "risk_if_not_remediated": "Network-level data path to non-compliant region",
                }
            )

        elif "encryption" in v.get("description", "").lower():
            remediation.update(
                {
                    "title": f"Enable encryption for {service} resource '{resource_name}'",
                    "remediation_type": "encryption_enablement",
                    "description": f"{service} resource '{resource_name}' lacks required encryption under {reg_name}.",
                    "steps": [
                        f"Create a KMS key in {source} if one doesn't exist",
                        f"Enable encryption at rest for the {service} resource",
                        "Enable encryption in transit where applicable",
                        "Verify encryption status after enablement",
                    ],
                    "estimated_effort": "1-4 hours depending on service",
                    "risk_if_not_remediated": f"Unencrypted regulated data — {reg_name} compliance failure",
                }
            )

        else:
            remediation.update(
                {
                    "title": f"Remediate {service} sovereignty violation for '{resource_name}'",
                    "remediation_type": "resource_config",
                    "description": v.get("description", ""),
                    "steps": [
                        f"Review the data flow from {source} to {dest}",
                        "Determine if the flow is necessary for business operations",
                        "If not needed, remove the cross-region configuration",
                        f"If needed, implement appropriate safeguards per {reg_name}",
                        "Deploy SCP to prevent future non-compliant configurations",
                    ],
                    "estimated_effort": "Variable",
                    "risk_if_not_remediated": f"{severity.upper()} severity {reg_name} violation",
                }
            )

        remediations.append(remediation)

    return json.dumps({"remediations": remediations, "total": len(remediations)}, indent=2)
