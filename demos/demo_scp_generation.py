"""Generate SCP policies for region restriction and replication prevention."""

import json

from sovereign_shield.tools.remediation import generate_remediation_plan, generate_scp_policy


def main():
    print("=" * 70)
    print("  SOVEREIGN SHIELD — SCP Policy Generation Demo")
    print("=" * 70)

    print("\n1. Region Restriction SCP (EU data services blocked outside EU)\n")
    scp_result = json.loads(generate_scp_policy.tool_func(
        prohibited_regions="us-east-1,us-west-2,ap-south-1,ap-southeast-1,sa-east-1",
        allowed_services="s3,rds,dynamodb,kms",
        policy_name="EUDataResidencyEnforcement",
    ))

    print("Region Restriction Policy:")
    print(json.dumps(scp_result["region_restriction_policy"], indent=2))
    print("\nReplication Deny Policy:")
    print(json.dumps(scp_result["replication_deny_policy"], indent=2))
    print("\nDeployment Instructions:")
    for step in scp_result["instructions"]:
        print(f"  {step}")

    print(f"\n{'─' * 70}")
    print("\n2. Remediation Plan for Sample Violations\n")

    violations = {
        "violations": [
            {
                "violation_id": "v001",
                "regulation_id": "gdpr",
                "regulation_name": "GDPR",
                "article_reference": "Art. 44",
                "severity": "critical",
                "service": "S3",
                "resource_arn": "arn:aws:s3:::customer-pii-prod",
                "resource_name": "customer-pii-prod",
                "source_region": "eu-central-1",
                "destination_region": "us-east-1",
                "description": "S3 bucket 'customer-pii-prod' replicating from eu-central-1 to us-east-1",
            },
            {
                "violation_id": "v002",
                "regulation_id": "gdpr",
                "regulation_name": "GDPR",
                "severity": "high",
                "service": "RDS",
                "resource_arn": "arn:aws:rds:eu-west-1:123:db:orders-primary",
                "resource_name": "orders-primary",
                "source_region": "eu-west-1",
                "destination_region": "ap-southeast-1",
                "description": "RDS instance 'orders-primary' has read replica in ap-southeast-1",
            },
            {
                "violation_id": "v003",
                "regulation_id": "gdpr",
                "regulation_name": "GDPR",
                "severity": "high",
                "service": "S3",
                "resource_arn": "arn:aws:s3:::sensitive-data",
                "resource_name": "sensitive-data",
                "source_region": "eu-central-1",
                "destination_region": "eu-central-1",
                "description": "S3 resource 'sensitive-data' lacks required encryption at rest under GDPR",
            },
        ],
    }

    plan_result = json.loads(generate_remediation_plan.tool_func(
        violations_json=json.dumps(violations),
    ))

    for rem in plan_result["remediations"]:
        print(f"  Violation: {rem['violation_id']}")
        print(f"  Title:     {rem['title']}")
        print(f"  Type:      {rem['remediation_type']}")
        print(f"  Effort:    {rem['estimated_effort']}")
        print("  Steps:")
        for i, step in enumerate(rem["steps"], 1):
            print(f"    {i}. {step}")
        print(f"  Risk:      {rem['risk_if_not_remediated']}")
        print()


if __name__ == "__main__":
    main()
