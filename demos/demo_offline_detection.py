"""Offline violation detection against sample scan data — no AWS credentials needed."""

import json

from sovereign_shield.tools.violation_detector import check_violations


def main():
    sample_scan = {
        "flows": [
            {
                "service": "S3",
                "resource_name": "customer-pii-prod",
                "resource_arn": "arn:aws:s3:::customer-pii-prod",
                "source_region": "eu-central-1",
                "destination_regions": ["us-east-1"],
                "flow_type": "replication",
                "encryption_enabled": True,
            },
            {
                "service": "RDS",
                "resource_name": "orders-primary",
                "resource_arn": "arn:aws:rds:eu-west-1:123456789012:db:orders-primary",
                "source_region": "eu-west-1",
                "destination_regions": ["ap-southeast-1"],
                "flow_type": "replication",
                "encryption_enabled": False,
            },
            {
                "service": "DynamoDB",
                "resource_name": "user-sessions",
                "resource_arn": "arn:aws:dynamodb:ap-south-1:123456789012:table/user-sessions",
                "source_region": "ap-south-1",
                "destination_regions": ["cn-north-1"],
                "flow_type": "replication",
                "encryption_enabled": True,
            },
            {
                "service": "S3",
                "resource_name": "eu-analytics",
                "resource_arn": "arn:aws:s3:::eu-analytics",
                "source_region": "eu-central-1",
                "destination_regions": ["eu-west-1"],
                "flow_type": "replication",
                "encryption_enabled": True,
            },
            {
                "service": "CloudFront",
                "resource_name": "E1A2B3C4D5E6F7",
                "resource_arn": "arn:aws:cloudfront::123456789012:distribution/E1A2B3C4D5E6F7",
                "source_region": "eu-central-1",
                "destination_regions": ["global-edge-locations"],
                "flow_type": "edge_cache",
                "encryption_enabled": True,
            },
        ],
        "resources": [
            {
                "service": "S3",
                "resource_name": "sensitive-data-bucket",
                "resource_arn": "arn:aws:s3:::sensitive-data-bucket",
                "region": "eu-central-1",
                "encryption_at_rest": False,
            },
            {
                "service": "RDS",
                "resource_name": "finance-db",
                "resource_arn": "arn:aws:rds:eu-west-1:123456789012:db:finance-db",
                "region": "eu-west-1",
                "encryption_at_rest": True,
            },
        ],
    }

    print("=" * 70)
    print("  SOVEREIGN SHIELD — Offline Violation Detection Demo")
    print("=" * 70)
    print()

    print("Checking against ALL regulations...")
    result = json.loads(check_violations.tool_func(
        scan_results_json=json.dumps(sample_scan),
        applicable_regulations="",
    ))

    print(f"\nTotal violations found: {result['total']}\n")

    for v in result["violations"]:
        severity_icon = {
            "critical": "[CRITICAL]",
            "high": "[HIGH]    ",
            "medium": "[MEDIUM]  ",
            "low": "[LOW]     ",
        }.get(v["severity"], "[INFO]    ")

        print(f"  {severity_icon} {v['regulation_name']}")
        print(f"             {v['service']} '{v['resource_name']}': {v['source_region']} -> {v['destination_region']}")
        print(f"             {v['description'][:120]}...")
        print()

    print("-" * 70)
    print("\nChecking against GDPR only...")
    gdpr_result = json.loads(check_violations.tool_func(
        scan_results_json=json.dumps(sample_scan),
        applicable_regulations="gdpr",
    ))
    print(f"GDPR violations: {gdpr_result['total']}\n")

    print("Checking against India DPDP only...")
    dpdp_result = json.loads(check_violations.tool_func(
        scan_results_json=json.dumps(sample_scan),
        applicable_regulations="dpdp",
    ))
    print(f"DPDP violations: {dpdp_result['total']}\n")

    for v in dpdp_result["violations"]:
        print(f"  [{v['severity'].upper()}] {v['description']}")


if __name__ == "__main__":
    main()
