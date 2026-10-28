"""Tests for the remediation tools."""

import json

from sovereign_shield.tools.invocation import invoke_tool
from sovereign_shield.tools.remediation import generate_remediation_plan, generate_scp_policy


def test_generate_scp_blocks_regions():
    result_str = invoke_tool(
        generate_scp_policy,
        prohibited_regions="us-east-1,us-west-2",
        allowed_services="s3,rds",
        policy_name="TestPolicy",
    )
    result = json.loads(result_str)
    policy = result["region_restriction_policy"]
    assert policy["Statement"][0]["Effect"] == "Deny"
    assert "us-east-1" in policy["Statement"][0]["Condition"]["StringNotEquals"]["aws:RequestedRegion"]


def test_generate_remediation_for_s3_violation():
    violations = {
        "violations": [{
            "violation_id": "abc123",
            "regulation_id": "gdpr",
            "regulation_name": "GDPR",
            "article_reference": "Art. 44",
            "severity": "critical",
            "service": "S3",
            "resource_arn": "arn:aws:s3:::my-bucket",
            "resource_name": "my-bucket",
            "source_region": "eu-central-1",
            "destination_region": "us-east-1",
            "description": "S3 bucket 'my-bucket' replicating from eu-central-1 to us-east-1 violates GDPR",
        }],
    }
    result_str = invoke_tool(generate_remediation_plan, violations_json=json.dumps(violations))
    result = json.loads(result_str)
    assert result["total"] == 1
    rem = result["remediations"][0]
    assert "delete-bucket-replication" in rem["steps"][0]
    assert rem["violation_id"] == "abc123"


def test_generate_remediation_for_encryption_violation():
    violations = {
        "violations": [{
            "violation_id": "enc001",
            "regulation_id": "gdpr",
            "regulation_name": "GDPR",
            "severity": "high",
            "service": "S3",
            "resource_arn": "arn:aws:s3:::noenc",
            "resource_name": "noenc",
            "source_region": "eu-central-1",
            "destination_region": "eu-central-1",
            "description": "S3 resource 'noenc' lacks required encryption at rest under GDPR",
        }],
    }
    result_str = invoke_tool(generate_remediation_plan, violations_json=json.dumps(violations))
    result = json.loads(result_str)
    assert result["total"] == 1
    assert result["remediations"][0]["remediation_type"] == "encryption_enablement"
